package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/config"
	"github.com/craftedsignal/cli/internal/lockfile"
	internalyaml "github.com/craftedsignal/cli/internal/yaml"
)

func cmdDiff(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	filter := fs.String("filter", "", "Filter rules by name or ID (supports * wildcard)")
	group := fs.String("group", "", "Filter rules by group")
	fs.Parse(args)

	if *tokenFlag != "" {
		token = *tokenFlag
	}

	path := strings.TrimRight(rulePath, "/")
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if url == "" || token == "" {
		fmt.Fprintln(errOut, "Error: URL and token required")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)
	lf, _ := lockfile.Load()

	allLocalRules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(errOut, "Error: failed to load local rules: %v\n", err)
		return ExitError
	}

	// Apply filters
	var localRules []internalyaml.LoadedRule
	for _, r := range allLocalRules {
		if matchesFilter(r.Rule.Title, r.Rule.ID, *filter) && matchesGroup(r.Rule.Groups, *group) {
			localRules = append(localRules, r)
		}
	}

	status, err := client.GetSyncStatus()
	if err != nil {
		fmt.Fprintf(errOut, "Error: failed to get sync status: %v\n", err)
		return ExitError
	}

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

	hasChanges := false

	for id, local := range localByID {
		platform, existsOnPlatform := platformByID[id]
		lastSync, wasSynced := lf.Get(id)

		if !existsOnPlatform {
			fmt.Printf("+ %s (new local)\n", local.Rule.Title)
			hasChanges = true
			continue
		}

		localChanged := !wasSynced || local.Hash != lastSync.LastSyncedHash
		platformChanged := !wasSynced || platform.Hash != lastSync.LastSyncedHash

		if localChanged && platformChanged {
			fmt.Printf("! %s (conflict)\n", local.Rule.Title)
			hasChanges = true
		} else if localChanged {
			fmt.Printf("~ %s (local modified)\n", local.Rule.Title)
			hasChanges = true
		} else if platformChanged {
			fmt.Printf("~ %s (platform modified)\n", local.Rule.Title)
			hasChanges = true
		}
	}

	for id := range platformByID {
		if _, exists := localByID[id]; !exists {
			if _, wasSynced := lf.Get(id); !wasSynced {
				fmt.Printf("+ %s (new on platform)\n", id)
				hasChanges = true
			}
		}
	}

	if !hasChanges {
		fmt.Println("No differences")
	}

	return ExitSuccess
}
