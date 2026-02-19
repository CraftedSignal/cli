package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/config"
	"github.com/craftedsignal/cli/internal/lockfile"
	internalyaml "github.com/craftedsignal/cli/internal/yaml"
	"github.com/craftedsignal/cli/pkg/schema"
)

func cmdSync(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	resolve := fs.String("resolve", "", "Resolve conflicts: local or remote")
	message := fs.String("m", "", "Version comment for pushed changes")
	filter := fs.String("filter", "", "Filter rules by name or ID (supports * wildcard)")
	group := fs.String("group", "", "Filter rules by group")
	atomic := fs.Bool("atomic", true, "Rollback all changes if any rule fails")
	test := fs.Bool("test", true, "Run tests for changed rules before syncing")
	deploy := fs.Bool("deploy", false, "Deploy rules to SIEM after syncing")
	forceSync := fs.Bool("force-sync", false, "Continue sync even if validation or tests fail")
	forceDeploy := fs.Bool("force-deploy", false, "Deploy even if validation or tests fail (implies -deploy)")
	_ = fs.Parse(args)

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
		_, _ = fmt.Fprintln(errOut, "Error: URL and token required")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)
	lf, _ := lockfile.Load()

	// Load local rules
	allLocalRules, loadErrors := internalyaml.LoadAllLenient(path)
	if len(loadErrors) > 0 {
		if !*forceSync {
			_, _ = fmt.Fprintf(errOut, "Error: failed to load local rules: %v\n", loadErrors[0])
			return ExitError
		}
		_, _ = fmt.Fprintln(errOut, "Warning: skipping files with errors (-force-sync):")
		for _, e := range loadErrors {
			_, _ = fmt.Fprintf(errOut, "  ! %s\n", e)
		}
	}

	// Apply filters to local rules
	var localRules []internalyaml.LoadedRule
	for _, r := range allLocalRules {
		if matchesFilter(r.Rule.Title, r.Rule.ID, *filter) && matchesGroup(r.Rule.Groups, *group) {
			localRules = append(localRules, r)
		}
	}

	// Get platform status
	status, err := client.GetSyncStatus()
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to get sync status: %v\n", err)
		return ExitError
	}

	// Build maps for comparison
	localByID := make(map[string]internalyaml.LoadedRule)
	for _, r := range localRules {
		if r.Rule.ID != "" {
			localByID[r.Rule.ID] = r
		}
	}

	platformByID := make(map[string]api.SyncStatusRule)
	for _, r := range status.Rules {
		if matchesFilter(r.Title, r.ID, *filter) && matchesGroup(r.Groups, *group) {
			platformByID[r.ID] = r
		}
	}

	var conflicts []conflictInfo
	var toPush []syncPushItem
	var toPull []syncPullItem

	// Check each local rule
	for id, local := range localByID {
		platform, existsOnPlatform := platformByID[id]
		lastSync, wasSynced := lf.Get(id)

		if !existsOnPlatform {
			toPush = append(toPush, syncPushItem{Rule: local, Reason: "new rule"})
			continue
		}

		// If hashes match, already in sync - nothing to do
		if local.Hash == platform.Hash {
			continue
		}

		localChanged := !wasSynced || local.Hash != lastSync.LastSyncedHash
		platformChanged := !wasSynced || platform.Hash != lastSync.LastSyncedHash

		if localChanged && platformChanged {
			// Both changed - use timestamps to resolve
			localMtime := getFileMtime(local.FilePath)
			if platform.UpdatedAt.After(localMtime) {
				toPull = append(toPull, syncPullItem{ID: id, Reason: "conflict: platform is newer"})
			} else {
				toPush = append(toPush, syncPushItem{Rule: local, Reason: "conflict: local is newer"})
			}
		} else if localChanged {
			toPush = append(toPush, syncPushItem{Rule: local, Reason: "local changed"})
		} else if platformChanged {
			toPull = append(toPull, syncPullItem{ID: id, Reason: "platform changed"})
		}
	}

	// Check for rules on platform that don't exist locally
	for id := range platformByID {
		if _, exists := localByID[id]; !exists {
			toPull = append(toPull, syncPullItem{ID: id, Reason: "new on platform"})
		}
	}

	// Handle conflicts
	if len(conflicts) > 0 && *resolve == "" {
		fmt.Println("CONFLICTS detected:")
		for _, c := range conflicts {
			fmt.Printf("  ! %s (ID: %s)\n", c.Title, c.ID)
		}
		fmt.Println("\nResolve with:")
		fmt.Println("  csctl sync --resolve=local   # Keep local changes")
		fmt.Println("  csctl sync --resolve=remote  # Keep platform changes")
		return ExitConflict
	}

	switch *resolve {
	case "local":
		for _, c := range conflicts {
			if local, exists := localByID[c.ID]; exists {
				toPush = append(toPush, syncPushItem{Rule: local, Reason: "conflict resolved: keep local"})
			}
		}
	case "remote":
		for _, c := range conflicts {
			toPull = append(toPull, syncPullItem{ID: c.ID, Reason: "conflict resolved: keep remote"})
		}
	}

	// Extract rules for validation and testing
	var pushRules []internalyaml.LoadedRule
	for _, item := range toPush {
		pushRules = append(pushRules, item.Rule)
	}

	// Validate rules to push
	if len(pushRules) > 0 {
		vResult := validateRules(pushRules)
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

	// Execute push (skip saving tests until after test run)
	wantsTests := *test
	var pushedAPIRules []schema.Detection
	if len(toPush) > 0 {
		for _, item := range toPush {
			pushedAPIRules = append(pushedAPIRules, item.Rule.Rule)
		}

		resp, err := client.Import(pushedAPIRules, *message, "push", *atomic, wantsTests)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "Error: push failed: %v\n", err)
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

		if len(resp.Results) != len(toPush) {
			_, _ = fmt.Fprintf(errOut, "Warning: result count (%d) does not match rule count (%d), skipping lockfile update\n",
				len(resp.Results), len(toPush))
			for _, result := range resp.Results {
				fmt.Printf("  -> %s (%s)\n", result.Title, result.Action)
			}
		} else {
			for i, result := range resp.Results {
				item := &toPush[i]
				if result.Action == "created" || result.Action == "updated" {
					if item.Rule.Rule.ID == "" && result.ID != "" {
						item.Rule.Rule.ID = result.ID
						if saveErr := internalyaml.SaveFile(item.Rule.Rule, item.Rule.FilePath); saveErr != nil {
							_, _ = fmt.Fprintf(errOut, "  Warning: failed to write ID back to %s: %v\n", item.Rule.FilePath, saveErr)
						}
					}
					lf.Update(result.ID, item.Rule.FilePath, item.Rule.Hash, result.Version)
				}
				fmt.Printf("  -> %s (%s) [%s]\n", result.Title, result.Action, item.Reason)
			}
		}
	}

	// Run tests against the pushed rules (now testing the current version on platform)
	testsPassed := true
	if wantsTests && len(pushRules) > 0 {
		if !runTests(client, pushRules) {
			testsPassed = false
			if !*forceSync {
				_, _ = fmt.Fprintln(errOut, "Tests failed. Test definitions were NOT saved to the platform.")
				_, _ = fmt.Fprintln(errOut, "Fix the tests and re-run, or use -force-sync to save anyway.")
				return ExitError
			}
			_, _ = fmt.Fprintln(errOut, "Warning: continuing despite test failures (-force-sync)")
		}
	}

	// Commit test definitions to the platform (second push with skip_tests=false)
	if wantsTests && len(pushedAPIRules) > 0 && (testsPassed || *forceSync) {
		hasTests := false
		for _, r := range pushedAPIRules {
			if r.Tests != nil && (len(r.Tests.Positive) > 0 || len(r.Tests.Negative) > 0) {
				hasTests = true
				break
			}
		}
		if hasTests {
			_, err := client.Import(pushedAPIRules, "", "push", *atomic, false)
			if err != nil {
				_, _ = fmt.Fprintf(errOut, "Warning: failed to save test definitions: %v\n", err)
			}
		}
	}

	// Execute pull
	var pulledRules []schema.Detection
	if len(toPull) > 0 {
		rules, err := client.Export("")
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "Error: pull failed: %v\n", err)
			return ExitError
		}

		pullIDs := make(map[string]string) // ID -> reason
		for _, item := range toPull {
			pullIDs[item.ID] = item.Reason
		}

		usedPaths := make(map[string]bool)
		for _, r := range rules {
			reason, shouldPull := pullIDs[r.ID]
			if !shouldPull {
				continue
			}

			dir := path
			if len(r.Groups) > 0 {
				dir = filepath.Join(path, r.Groups[0])
			}

			filename := sanitizeFilename(r.Title)
			filePath := filepath.Join(dir, filename)

			// Check if file exists with different rule ID
			if existingID := getFileRuleID(filePath); existingID != "" && existingID != r.ID {
				base := strings.TrimSuffix(filename, ".yaml")
				shortID := r.ID
				if len(shortID) > 8 {
					shortID = shortID[:8]
				}
				filename = base + "-" + shortID + ".yaml"
				filePath = filepath.Join(dir, filename)
			}
			// Also handle collisions within this batch
			if usedPaths[filePath] {
				base := strings.TrimSuffix(filename, ".yaml")
				shortID := r.ID
				if len(shortID) > 8 {
					shortID = shortID[:8]
				}
				filename = base + "-" + shortID + ".yaml"
				filePath = filepath.Join(dir, filename)
			}
			usedPaths[filePath] = true

			if err := internalyaml.SaveFile(r, filePath); err != nil {
				fmt.Printf("  ! %s: %v\n", r.Title, err)
				continue
			}

			hash, err := internalyaml.ComputeHash(r)
			if err != nil {
				fmt.Printf("  ! %s: %v\n", r.Title, err)
				os.Exit(ExitError)
			}

			lf.Update(r.ID, filePath, hash, 0)
			pulledRules = append(pulledRules, r)
			fmt.Printf("  <- %s [%s]\n", r.Title, reason)
		}
	}

	_ = lf.Save()

	if len(toPush) == 0 && len(toPull) == 0 {
		fmt.Println("Already in sync")
	} else {
		fmt.Printf("\nPushed: %d, Pulled: %d\n", len(toPush), len(toPull))
	}

	// Deploy if requested
	if *deploy {
		// Collect IDs of synced rules (pushed + pulled)
		var deployIDs []string
		for _, item := range toPush {
			if item.Rule.Rule.ID != "" {
				deployIDs = append(deployIDs, item.Rule.Rule.ID)
			}
		}
		for _, r := range pulledRules {
			deployIDs = append(deployIDs, r.ID)
		}

		if len(deployIDs) > 0 {
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
