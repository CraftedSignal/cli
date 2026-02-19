package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/config"
	yamlutil "github.com/craftedsignal/cli/internal/yaml"
	"github.com/craftedsignal/cli/pkg/schema"
	"gopkg.in/yaml.v3"
)

func cmdGenerate(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, path string) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fromTI := fs.String("from-ti", "", "Threat intelligence description or path to Sigma YAML file")
	platform := fs.String("platform", "", "Target SIEM platform (splunk, sentinel, rapid7)")
	group := fs.String("group", "", "Group folder to save rules under")
	push := fs.Bool("push", false, "Auto-push generated rules to the platform")
	dryRun := fs.Bool("dry-run", false, "Print YAML to stdout without saving")

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	if *fromTI == "" {
		fmt.Fprintf(errOut, "Error: --from-ti is required\n")
		fs.Usage()
		return ExitError
	}

	// Resolve platform
	targetPlatform := *platform
	if targetPlatform == "" && cfg != nil {
		targetPlatform = cfg.Defaults.Platform
	}
	if targetPlatform == "" {
		fmt.Fprintf(errOut, "Error: --platform is required (or set CSCTL_PLATFORM in config)\n")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)

	// Detect input type: Sigma YAML file or free text
	var req api.GenerateRequest
	req.Platform = targetPlatform

	if isSigmaFile(*fromTI) {
		data, err := os.ReadFile(*fromTI)
		if err != nil {
			fmt.Fprintf(errOut, "Error reading Sigma file: %v\n", err)
			return ExitError
		}
		req.SigmaYAML = string(data)
		fmt.Printf("Rewriting Sigma rule for %s...\n", targetPlatform)
	} else {
		req.Description = *fromTI
		fmt.Printf("Generating rules from: %q\n", *fromTI)
	}

	// Start generation
	startResp, err := client.StartGenerate(req)
	if err != nil {
		fmt.Fprintf(errOut, "Error: %v\n", err)
		return ExitError
	}

	var rules []schema.Detection

	if startResp.Status == "completed" {
		rules = startResp.Rules
	} else {
		rules, err = pollForCompletion(client, startResp.WorkflowID)
		if err != nil {
			fmt.Fprintf(errOut, "Error: %v\n", err)
			return ExitError
		}
	}

	if len(rules) == 0 {
		fmt.Println("No rules generated.")
		return ExitSuccess
	}

	fmt.Printf("\nGenerated %d rule(s):\n", len(rules))

	// Apply group and platform
	for i := range rules {
		if rules[i].Platform == "" {
			rules[i].Platform = targetPlatform
		}
		if *group != "" {
			rules[i].Groups = []string{*group}
		}
		rules[i].Enabled = true
	}

	for _, d := range rules {
		fmt.Printf("  - %s (%s)\n", d.Title, d.Severity)
	}

	if *dryRun {
		fmt.Println("\n--- Dry run (not saving) ---")
		for _, d := range rules {
			yamlBytes, _ := yaml.Marshal(d)
			fmt.Println(string(yamlBytes))
			fmt.Println("---")
		}
		return ExitSuccess
	}

	// Save to disk
	groupDir := *group
	if groupDir == "" {
		groupDir = "generated"
	}
	outputDir := filepath.Join(path, groupDir)
	os.MkdirAll(outputDir, 0755)

	for _, d := range rules {
		filename := sanitizeFilename(d.Title)
		filePath := filepath.Join(outputDir, filename)
		if err := yamlutil.SaveFile(d, filePath); err != nil {
			fmt.Fprintf(errOut, "Error saving %s: %v\n", filePath, err)
			continue
		}
		fmt.Printf("  Saved: %s\n", filePath)
	}

	// Auto-push if requested
	if *push {
		fmt.Println("\nPushing rules to platform...")
		atomic := true
		if _, err := client.Import(rules, "AI-generated rules", "push", atomic, false); err != nil {
			fmt.Fprintf(errOut, "Push failed: %v\n", err)
			return ExitError
		}
		fmt.Println("Rules pushed successfully.")
	}

	return ExitSuccess
}

func pollForCompletion(client *api.Client, workflowID string) ([]schema.Detection, error) {
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0

	for {
		resp, err := client.PollGenerate(workflowID)
		if err != nil {
			return nil, err
		}

		switch resp.Status {
		case "completed":
			fmt.Print("\r\033[K") // clear spinner line
			return resp.Rules, nil
		case "failed":
			fmt.Print("\r\033[K")
			return nil, fmt.Errorf("generation failed: %s", resp.Error)
		default:
			progress := resp.Progress
			if progress == "" {
				progress = "Generating..."
			}
			fmt.Printf("\r%s %s", spinner[i%len(spinner)], progress)
			i++
			time.Sleep(3 * time.Second)
		}
	}
}

func isSigmaFile(input string) bool {
	lower := strings.ToLower(input)
	if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
		return false
	}
	_, err := os.Stat(input)
	return err == nil
}

