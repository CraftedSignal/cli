package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
	internalyaml "github.com/craftedsignal/cli/internal/yaml"
	"github.com/craftedsignal/cli/pkg/schema"
)

func cmdInit(url, token string, args []string, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	fromPlatform := fs.Bool("from-platform", false, "Bootstrap from existing platform rules")
	fs.Parse(args)

	if *tokenFlag != "" {
		token = *tokenFlag
	}

	path := strings.TrimRight(rulePath, "/")

	if *fromPlatform {
		if url == "" || token == "" {
			fmt.Fprintln(errOut, "Error: URL and token required for --from-platform")
			return ExitError
		}
		return cmdPull(url, token, []string{}, nil, clientOpts, path)
	}

	dirs := []string{path + "/endpoint", path + "/network", path + "/cloud"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(errOut, "Error: failed to create %s: %v\n", dir, err)
			return ExitError
		}
		fmt.Printf("  Created %s/\n", dir)
	}

	example := schema.Detection{
		Title:       "Example Detection",
		Description: "An example detection rule",
		Platform:    "splunk",
		Query:       "index=main | stats count",
		Severity:    "medium",
		Kind:        "query",
		Enabled:     true,
		Frequency:   "1h",
		Period:      "1h",
	}
	examplePath := path + "/endpoint/example-detection.yaml"
	if err := internalyaml.SaveFile(example, examplePath); err != nil {
		fmt.Fprintf(errOut, "Error: failed to create example: %v\n", err)
		return ExitError
	}
	fmt.Printf("  Created %s\n", examplePath)

	if _, err := os.Stat(".csctl.yaml"); os.IsNotExist(err) {
		configContent := `# CraftedSignal CLI Configuration
# url: https://app.craftedsignal.io  # (default, uncomment to override)

defaults:
  path: detections/
  platform: splunk
`
		if err := os.WriteFile(".csctl.yaml", []byte(configContent), 0600); err != nil {
			fmt.Fprintf(errOut, "Error: failed to create .csctl.yaml: %v\n", err)
			return ExitError
		}
		fmt.Println("  Created .csctl.yaml")
	}

	fmt.Println("\nInitialized! Set CSCTL_TOKEN and update .csctl.yaml with your instance URL.")
	return ExitSuccess
}
