package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/config"
	"github.com/craftedsignal/cli/internal/lockfile"
	internalyaml "github.com/craftedsignal/cli/internal/yaml"
	"github.com/craftedsignal/cli/pkg/schema"
)

func cmdPush(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	message := fs.String("m", "", "Version comment")
	dryRun := fs.Bool("dry-run", false, "Preview changes without applying")
	filter := fs.String("filter", "", "Filter rules by name or ID (supports * wildcard)")
	group := fs.String("group", "", "Filter rules by group")
	atomic := fs.Bool("atomic", true, "Rollback all changes if any rule fails")
	test := fs.Bool("test", true, "Run tests for changed rules before pushing")
	deploy := fs.Bool("deploy", false, "Deploy rules to SIEM after pushing")
	forceSync := fs.Bool("force-sync", false, "Continue push even if validation or tests fail")
	forceDeploy := fs.Bool("force-deploy", false, "Deploy even if validation or tests fail (implies -deploy)")

	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
		return ExitError
	}

	if *tokenFlag != "" {
		token = *tokenFlag
	}

	// -force-deploy implies -deploy
	if *forceDeploy {
		*deploy = true
	}

	path := strings.TrimRight(rulePath, "/")
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if url == "" || token == "" {
		_, _ = fmt.Fprintln(errOut, "Error: URL and token required (set via .csctl.yaml and CSCTL_TOKEN)")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)
	lf, _ := lockfile.Load()

	allRules, loadErrors := internalyaml.LoadAllLenient(path)
	if len(loadErrors) > 0 {
		if !*forceSync {
			_, _ = fmt.Fprintf(errOut, "Error: failed to load rules: %v\n", loadErrors[0])
			return ExitError
		}
		_, _ = fmt.Fprintln(errOut, "Warning: skipping files with errors (-force-sync):")
		for _, e := range loadErrors {
			_, _ = fmt.Fprintf(errOut, "  ! %s\n", e)
		}
	}

	// Apply filters
	var rules []internalyaml.LoadedRule
	for _, r := range allRules {
		if matchesFilter(r.Rule.Title, r.Rule.ID, *filter) && matchesGroup(r.Rule.Groups, *group) {
			rules = append(rules, r)
		}
	}

	if len(rules) == 0 {
		fmt.Println("No rules found matching filters")
		return ExitSuccess
	}

	fmt.Printf("Found %d rules\n", len(rules))

	// Determine which rules changed since last sync
	changedRules := filterChangedRules(rules, lf)
	fmt.Printf("Changed: %d rules\n", len(changedRules))

	// Validate only changed rules
	if len(changedRules) > 0 {
		vResult := validateRules(changedRules)
		if !vResult.Valid() {
			_, _ = fmt.Fprintln(errOut, "Validation errors:")
			for _, e := range vResult.Errors {
				_, _ = fmt.Fprintf(errOut, "  ! %s\n", e)
			}
			if !*forceSync {
				return ExitError
			}
			_, _ = fmt.Fprintln(errOut, "Warning: continuing despite validation errors (-force-sync)")
		}
	}

	// Run tests for changed rules
	if *test && len(changedRules) > 0 {
		if !runTests(client, changedRules) {
			if !*forceSync {
				return ExitError
			}
			_, _ = fmt.Fprintln(errOut, "Warning: continuing despite test failures (-force-sync)")
		}
	}

	if *dryRun {
		for _, r := range rules {
			fmt.Printf("  %s (%s)\n", r.Rule.Title, r.FilePath)
		}
		return ExitSuccess
	}

	var apiRules []schema.Detection
	for _, r := range rules {
		apiRules = append(apiRules, r.Rule)
	}

	resp, err := client.Import(apiRules, *message, "push", *atomic, false)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: import failed: %v\n", err)
		return ExitError
	}

	logImportStatus(resp.StatusCode)

	if resp.RolledBack {
		_, _ = fmt.Fprintln(errOut, "ROLLED BACK: One or more rules failed, all changes reverted")
		for _, result := range resp.Results {
			if result.Error != "" {
				_, _ = fmt.Fprintf(errOut, "  ! %s: %s\n", result.Title, result.Error)
			}
		}
		return ExitError
	}

	if len(resp.Results) != len(rules) {
		_, _ = fmt.Fprintf(errOut, "Warning: result count (%d) does not match rule count (%d), skipping lockfile update\n",
			len(resp.Results), len(rules))
		for _, result := range resp.Results {
			fmt.Printf("  %s %s", actionSymbol(result.Action), result.Title)
			if result.Error != "" {
				fmt.Printf(" (%s)", result.Error)
			}
			fmt.Println()
		}
	} else {
		for i, result := range resp.Results {
			if result.Action == "created" || result.Action == "updated" {
				if rules[i].Rule.ID == "" && result.ID != "" {
					rules[i].Rule.ID = result.ID
					if saveErr := internalyaml.SaveFile(rules[i].Rule, rules[i].FilePath); saveErr != nil {
						_, _ = fmt.Fprintf(errOut, "  Warning: failed to write ID back to %s: %v\n", rules[i].FilePath, saveErr)
					}
				}
				lf.Update(result.ID, rules[i].FilePath, rules[i].Hash, result.Version)
			}

			fmt.Printf("  %s %s", actionSymbol(result.Action), result.Title)
			if result.Error != "" {
				fmt.Printf(" (%s)", result.Error)
			}
			fmt.Println()
		}
	}

	_ = lf.Save()

	fmt.Printf("\nCreated: %d, Updated: %d, Unchanged: %d, Errors: %d\n",
		resp.Created, resp.Updated, resp.Unchanged, resp.Errors)

	// Deploy if requested
	if *deploy {
		// Collect IDs of successfully pushed rules
		var deployIDs []string
		for _, r := range rules {
			if r.Rule.ID != "" {
				deployIDs = append(deployIDs, r.Rule.ID)
			}
		}

		if len(deployIDs) == 0 {
			fmt.Println("No rules with IDs to deploy")
		} else {
			fmt.Println("\nDeploying rules...")
			deployResp, err := client.Deploy(deployIDs, *forceDeploy)
			if err != nil {
				_, _ = fmt.Fprintf(errOut, "Error: deploy failed: %v\n", err)
				if !*forceDeploy {
					return ExitError
				}
				_, _ = fmt.Fprintln(errOut, "Warning: deploy failed but continuing (-force-deploy)")
			} else {
				for _, result := range deployResp.Results {
					if result.Action == "deployed" {
						fmt.Printf("  + %s\n", result.Title)
					} else {
						_, _ = fmt.Fprintf(errOut, "  ! %s: %s\n", result.Title, result.Error)
					}
				}
				if deployResp.Failed > 0 && !*forceDeploy {
					_, _ = fmt.Fprintf(errOut, "Deploy failed for %d rules\n", deployResp.Failed)
					return ExitError
				}
				fmt.Printf("Deployed: %d, Failed: %d\n", deployResp.Deployed, deployResp.Failed)
			}
		}
	}

	return ExitSuccess
}
