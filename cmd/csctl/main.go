package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/config"
	"github.com/craftedsignal/cli/internal/lockfile"
	internalyaml "github.com/craftedsignal/cli/internal/yaml"
	"github.com/craftedsignal/cli/pkg/schema"
)

const (
	// ExitSuccess indicates successful execution
	ExitSuccess = 0
	// ExitError indicates an error occurred
	ExitError = 1
	// ExitConflict indicates conflicts were detected
	ExitConflict = 2
)

var (
	logger *slog.Logger
)

func main() {
	// Global flags
	var (
		urlFlag      = flag.String("url", "", "Platform URL")
		tokenFlag    = flag.String("token", "", "API token")
		insecureFlag = flag.Bool("insecure", false, "Skip TLS certificate verification")
		verboseFlag  = flag.Bool("v", false, "Verbose output")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `csctl - CraftedSignal CLI for detection-as-code

Usage:
  csctl [flags] <command> [command flags]

Commands:
  push      Push local YAML files to platform
  pull      Pull rules from platform to local YAML files
  sync      Bidirectional sync (fails on conflicts)
  validate  Validate YAML files locally
  diff      Show differences between local and platform
  init      Initialize detections directory structure
  auth      Check authentication status

Global Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Environment Variables:
  CSCTL_TOKEN    API token (alternative to --token flag)

Examples:
  csctl push                         # Push all rules
  csctl push -m "Deploy Q1 rules"    # With version comment
  csctl pull -group endpoint         # Pull specific group
  csctl sync --resolve=local         # Resolve conflicts with local version
`)
	}

	flag.Parse()

	// Setup logging
	logLevel := slog.LevelWarn
	if *verboseFlag {
		logLevel = slog.LevelDebug
	}
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Load config
	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load config", slog.Any("error", err))
	}

	// Resolve URL and token
	url := *urlFlag
	if url == "" && cfg != nil {
		url = cfg.URL
	}

	token := *tokenFlag
	if token == "" {
		token = config.GetToken()
	}

	// Get command
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(ExitError)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	// Create client options
	var clientOpts []api.ClientOption
	if *insecureFlag {
		clientOpts = append(clientOpts, api.WithInsecureSkipVerify())
	}
	clientOpts = append(clientOpts, api.WithLogger(logger))

	// Execute command
	var exitCode int
	switch cmd {
	case "push":
		exitCode = cmdPush(url, token, cmdArgs, cfg, clientOpts)
	case "pull":
		exitCode = cmdPull(url, token, cmdArgs, cfg, clientOpts)
	case "sync":
		exitCode = cmdSync(url, token, cmdArgs, cfg, clientOpts)
	case "validate":
		exitCode = cmdValidate(cmdArgs, cfg)
	case "diff":
		exitCode = cmdDiff(url, token, cmdArgs, cfg, clientOpts)
	case "init":
		exitCode = cmdInit(url, token, cmdArgs, clientOpts)
	case "auth":
		exitCode = cmdAuth(url, token, clientOpts)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		flag.Usage()
		exitCode = ExitError
	}

	os.Exit(exitCode)
}

func cmdPush(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	message := fs.String("m", "", "Version comment")
	dryRun := fs.Bool("dry-run", false, "Preview changes without applying")
	fs.Parse(args)

	path := "detections"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	} else if cfg != nil && cfg.Defaults.Path != "" {
		path = cfg.Defaults.Path
	}

	if url == "" || token == "" {
		fmt.Fprintln(os.Stderr, "Error: URL and token required (set via .csctl.yaml and CSCTL_TOKEN)")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)

	rules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load rules: %v\n", err)
		return ExitError
	}

	if len(rules) == 0 {
		fmt.Println("No rules found")
		return ExitSuccess
	}

	fmt.Printf("Found %d rules\n", len(rules))

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

	resp, err := client.Import(apiRules, *message, "push")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: import failed: %v\n", err)
		return ExitError
	}

	lf, _ := lockfile.Load()
	for i, result := range resp.Results {
		if result.Action == "created" || result.Action == "updated" {
			if rules[i].Rule.ID == "" && result.ID != "" {
				rules[i].Rule.ID = result.ID
				internalyaml.SaveFile(rules[i].Rule, rules[i].FilePath)
			}
			lf.Update(result.ID, rules[i].FilePath, rules[i].Hash, result.Version)
		}

		symbol := "?"
		switch result.Action {
		case "created":
			symbol = "+"
		case "updated":
			symbol = "~"
		case "unchanged":
			symbol = "="
		case "error":
			symbol = "!"
		}
		fmt.Printf("  %s %s", symbol, result.Title)
		if result.Error != "" {
			fmt.Printf(" (%s)", result.Error)
		}
		fmt.Println()
	}

	lf.Save()

	fmt.Printf("\nCreated: %d, Updated: %d, Unchanged: %d, Errors: %d\n",
		resp.Created, resp.Updated, resp.Unchanged, resp.Errors)

	return ExitSuccess
}

func cmdPull(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	group := fs.String("group", "", "Pull specific group only")
	fs.Parse(args)

	path := "detections"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if url == "" || token == "" {
		fmt.Fprintln(os.Stderr, "Error: URL and token required")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)

	rules, err := client.Export(*group)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: export failed: %v\n", err)
		return ExitError
	}

	fmt.Printf("Fetched %d rules\n", len(rules))

	lf, _ := lockfile.Load()

	for _, r := range rules {
		dir := path
		if len(r.Groups) > 0 {
			dir = filepath.Join(path, r.Groups[0])
		}

		filename := strings.ReplaceAll(strings.ToLower(r.Title), " ", "-") + ".yaml"
		filePath := filepath.Join(dir, filename)

		if err := internalyaml.SaveFile(r, filePath); err != nil {
			fmt.Printf("  ! %s: %v\n", r.Title, err)
			continue
		}

		hash := internalyaml.ComputeHash(r)
		lf.Update(r.ID, filePath, hash, 0)

		fmt.Printf("  + %s -> %s\n", r.Title, filePath)
	}

	lf.Save()
	return ExitSuccess
}

func cmdSync(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	resolve := fs.String("resolve", "", "Resolve conflicts: local or remote")
	message := fs.String("m", "", "Version comment for pushed changes")
	fs.Parse(args)

	path := "detections"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if url == "" || token == "" {
		fmt.Fprintln(os.Stderr, "Error: URL and token required")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)
	lf, _ := lockfile.Load()

	// Load local rules
	localRules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load local rules: %v\n", err)
		return ExitError
	}

	// Get platform status
	status, err := client.GetSyncStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get sync status: %v\n", err)
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
		platformByID[r.ID] = r
	}

	var conflicts []string
	var toPush []internalyaml.LoadedRule
	var toPull []string

	// Check each local rule
	for id, local := range localByID {
		platform, existsOnPlatform := platformByID[id]
		lastSync, wasSynced := lf.Get(id)

		if !existsOnPlatform {
			toPush = append(toPush, local)
			continue
		}

		localChanged := !wasSynced || local.Hash != lastSync.LastSyncedHash
		platformChanged := !wasSynced || platform.Hash != lastSync.LastSyncedHash

		if localChanged && platformChanged {
			conflicts = append(conflicts, fmt.Sprintf("%s: modified both locally and on platform", local.Rule.Title))
		} else if localChanged {
			toPush = append(toPush, local)
		} else if platformChanged {
			toPull = append(toPull, id)
		}
	}

	// Check for new rules on platform
	for id := range platformByID {
		if _, exists := localByID[id]; !exists {
			if _, wasSynced := lf.Get(id); !wasSynced {
				toPull = append(toPull, id)
			}
		}
	}

	// Handle conflicts
	if len(conflicts) > 0 && *resolve == "" {
		fmt.Println("CONFLICTS detected:")
		for _, c := range conflicts {
			fmt.Printf("  ! %s\n", c)
		}
		fmt.Println("\nResolve with:")
		fmt.Println("  csctl sync --resolve=local   # Keep local changes")
		fmt.Println("  csctl sync --resolve=remote  # Keep platform changes")
		return ExitConflict
	}

	if *resolve == "local" {
		for _, c := range conflicts {
			for _, r := range localRules {
				if strings.Contains(c, r.Rule.Title) {
					toPush = append(toPush, r)
					break
				}
			}
		}
	} else if *resolve == "remote" {
		for id := range platformByID {
			if local, exists := localByID[id]; exists {
				for _, c := range conflicts {
					if strings.Contains(c, local.Rule.Title) {
						toPull = append(toPull, id)
						break
					}
				}
			}
		}
	}

	// Execute push
	if len(toPush) > 0 {
		var apiRules []schema.Detection
		for _, r := range toPush {
			apiRules = append(apiRules, r.Rule)
		}

		resp, err := client.Import(apiRules, *message, "push")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: push failed: %v\n", err)
			return ExitError
		}

		for i, result := range resp.Results {
			if result.Action == "created" || result.Action == "updated" {
				if toPush[i].Rule.ID == "" && result.ID != "" {
					toPush[i].Rule.ID = result.ID
					internalyaml.SaveFile(toPush[i].Rule, toPush[i].FilePath)
				}
				lf.Update(result.ID, toPush[i].FilePath, toPush[i].Hash, result.Version)
			}
			fmt.Printf("  -> %s (%s)\n", result.Title, result.Action)
		}
	}

	// Execute pull
	if len(toPull) > 0 {
		rules, err := client.Export("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: pull failed: %v\n", err)
			return ExitError
		}

		pullIDs := make(map[string]bool)
		for _, id := range toPull {
			pullIDs[id] = true
		}

		for _, r := range rules {
			if !pullIDs[r.ID] {
				continue
			}

			dir := path
			if len(r.Groups) > 0 {
				dir = filepath.Join(path, r.Groups[0])
			}

			filename := strings.ReplaceAll(strings.ToLower(r.Title), " ", "-") + ".yaml"
			filePath := filepath.Join(dir, filename)

			if err := internalyaml.SaveFile(r, filePath); err != nil {
				fmt.Printf("  ! %s: %v\n", r.Title, err)
				continue
			}

			hash := internalyaml.ComputeHash(r)
			lf.Update(r.ID, filePath, hash, 0)
			fmt.Printf("  <- %s\n", r.Title)
		}
	}

	lf.Save()

	if len(toPush) == 0 && len(toPull) == 0 {
		fmt.Println("Already in sync")
	} else {
		fmt.Printf("\nPushed: %d, Pulled: %d\n", len(toPush), len(toPull))
	}

	return ExitSuccess
}

func cmdValidate(args []string, cfg *config.Config) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	fs.Parse(args)

	path := "detections"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	rules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: validation failed: %v\n", err)
		return ExitError
	}

	errors := 0
	for _, r := range rules {
		var issues []string
		if r.Rule.Title == "" {
			issues = append(issues, "missing title")
		}
		if r.Rule.Platform == "" {
			issues = append(issues, "missing platform")
		}
		if r.Rule.Query == "" {
			issues = append(issues, "missing query")
		}

		if len(issues) > 0 {
			fmt.Printf("  ! %s: %s\n", r.FilePath, strings.Join(issues, ", "))
			errors++
		} else {
			fmt.Printf("  ok %s\n", r.FilePath)
		}
	}

	if errors > 0 {
		fmt.Fprintf(os.Stderr, "\n%d files have errors\n", errors)
		return ExitError
	}

	fmt.Printf("\n%d files valid\n", len(rules))
	return ExitSuccess
}

func cmdDiff(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	fs.Parse(args)

	path := "detections"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if url == "" || token == "" {
		fmt.Fprintln(os.Stderr, "Error: URL and token required")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)
	lf, _ := lockfile.Load()

	localRules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load local rules: %v\n", err)
		return ExitError
	}

	status, err := client.GetSyncStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get sync status: %v\n", err)
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
		platformByID[r.ID] = r
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

func cmdInit(url, token string, args []string, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fromPlatform := fs.Bool("from-platform", false, "Bootstrap from existing platform rules")
	fs.Parse(args)

	if *fromPlatform {
		if url == "" || token == "" {
			fmt.Fprintln(os.Stderr, "Error: URL and token required for --from-platform")
			return ExitError
		}
		return cmdPull(url, token, []string{}, nil, clientOpts)
	}

	dirs := []string{"detections/endpoint", "detections/network", "detections/cloud"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create %s: %v\n", dir, err)
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
	examplePath := "detections/endpoint/example-detection.yaml"
	if err := internalyaml.SaveFile(example, examplePath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create example: %v\n", err)
		return ExitError
	}
	fmt.Printf("  Created %s\n", examplePath)

	if _, err := os.Stat(".csctl.yaml"); os.IsNotExist(err) {
		configContent := `# CraftedSignal CLI Configuration
url: https://your-craftedsignal-instance.com

defaults:
  path: detections/
  platform: splunk
`
		if err := os.WriteFile(".csctl.yaml", []byte(configContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create .csctl.yaml: %v\n", err)
			return ExitError
		}
		fmt.Println("  Created .csctl.yaml")
	}

	fmt.Println("\nInitialized! Set CSCTL_TOKEN and update .csctl.yaml with your instance URL.")
	return ExitSuccess
}

func cmdAuth(url, token string, clientOpts []api.ClientOption) int {
	if url == "" || token == "" {
		fmt.Println("Not configured")
		fmt.Println("Set URL in .csctl.yaml and token in CSCTL_TOKEN env var")
		return ExitSuccess
	}

	client := api.NewClient(url, token, clientOpts...)
	if err := client.ValidateToken(); err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return ExitError
	}

	fmt.Printf("Authenticated to %s\n", url)
	return ExitSuccess
}
