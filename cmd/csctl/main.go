package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/config"
	"github.com/craftedsignal/cli/internal/lockfile"
	"github.com/craftedsignal/cli/internal/validate"
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
		configFlag   = flag.String("config", "", "Path to config file")
		urlFlag      = flag.String("url", "", "Platform URL")
		insecureFlag = flag.Bool("insecure", false, "Skip TLS certificate verification")
		logFlag      = flag.String("log", "info", "Log level: debug, info, warn, error")
		path         = flag.String("path", "detections/", "Path to detections folder")
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
  CSCTL_URL       Platform URL
  CSCTL_TOKEN     API token
  CSCTL_INSECURE  Skip TLS verification (true/false)
  CSCTL_PATH      Default detections path
  CSCTL_PLATFORM  Default platform (splunk, elastic, etc.)

Examples:
  csctl push                         # Push all rules
  csctl push -m "Deploy Q1 rules"    # With version comment
  csctl push -filter "brute*"        # Push rules matching pattern
  csctl pull -group endpoint         # Pull specific group
  csctl pull -filter lateral         # Pull rules containing "lateral"
  csctl sync --resolve=local         # Resolve conflicts with local version
`)
	}

	flag.Parse()

	// Setup logging
	var logLevel slog.Level
	switch strings.ToLower(*logFlag) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Load config
	cfg, err := config.LoadFromPath(*configFlag)
	if err != nil {
		if *configFlag != "" {
			fmt.Fprintf(os.Stderr, "Error: failed to load config file %s: %v\n", *configFlag, err)
			os.Exit(ExitError)
		}
		logger.Warn("could not load config", slog.Any("error", err))
	}

	// Resolve URL, token, and insecure from flags or config
	url := *urlFlag
	if url == "" && cfg != nil {
		url = cfg.URL
	}

	var token string
	if cfg != nil {
		token = cfg.Token
	}

	// Config insecure can be overridden by flag
	insecure := *insecureFlag
	if !insecure && cfg != nil {
		insecure = cfg.Insecure
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
	if insecure {
		clientOpts = append(clientOpts, api.WithInsecureSkipVerify())
	}
	clientOpts = append(clientOpts, api.WithLogger(logger))

	// Execute command
	var exitCode int
	switch cmd {
	case "push":
		exitCode = cmdPush(url, token, cmdArgs, cfg, clientOpts, *path)
	case "pull":
		exitCode = cmdPull(url, token, cmdArgs, cfg, clientOpts, *path)
	case "sync":
		exitCode = cmdSync(url, token, cmdArgs, cfg, clientOpts, *path)
	case "validate":
		exitCode = cmdValidate(cmdArgs, cfg, *path)
	case "diff":
		exitCode = cmdDiff(url, token, cmdArgs, cfg, clientOpts, *path)
	case "init":
		exitCode = cmdInit(url, token, cmdArgs, clientOpts, *path)
	case "auth":
		exitCode = cmdAuth(url, token, clientOpts)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		flag.Usage()
		exitCode = ExitError
	}

	os.Exit(exitCode)
}

// conflictInfo tracks a sync conflict by rule ID and title.
type conflictInfo struct {
	ID    string
	Title string
}

func cmdPush(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	message := fs.String("m", "", "Version comment")
	dryRun := fs.Bool("dry-run", false, "Preview changes without applying")
	filter := fs.String("filter", "", "Filter rules by name or ID (supports * wildcard)")
	group := fs.String("group", "", "Filter rules by group")
	atomic := fs.Bool("atomic", true, "Rollback all changes if any rule fails")
	fs.Parse(args)

	path := strings.TrimRight(rulePath, "/")
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if url == "" || token == "" {
		fmt.Fprintln(os.Stderr, "Error: URL and token required (set via .csctl.yaml and CSCTL_TOKEN)")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)

	allRules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load rules: %v\n", err)
		return ExitError
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

	// Validate before pushing
	vResult := validateRules(rules)
	if !vResult.Valid() {
		fmt.Fprintln(os.Stderr, "Validation errors:")
		for _, e := range vResult.Errors {
			fmt.Fprintf(os.Stderr, "  ! %s\n", e)
		}
		return ExitError
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

	resp, err := client.Import(apiRules, *message, "push", *atomic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: import failed: %v\n", err)
		return ExitError
	}

	logImportStatus(resp.StatusCode)

	if resp.RolledBack {
		fmt.Fprintln(os.Stderr, "ROLLED BACK: One or more rules failed, all changes reverted")
		for _, result := range resp.Results {
			if result.Error != "" {
				fmt.Fprintf(os.Stderr, "  ! %s: %s\n", result.Title, result.Error)
			}
		}
		return ExitError
	}

	lf, _ := lockfile.Load()

	if len(resp.Results) != len(rules) {
		fmt.Fprintf(os.Stderr, "Warning: result count (%d) does not match rule count (%d), skipping lockfile update\n",
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
						fmt.Fprintf(os.Stderr, "  Warning: failed to write ID back to %s: %v\n", rules[i].FilePath, saveErr)
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

	lf.Save()

	fmt.Printf("\nCreated: %d, Updated: %d, Unchanged: %d, Errors: %d\n",
		resp.Created, resp.Updated, resp.Unchanged, resp.Errors)

	return ExitSuccess
}

func cmdPull(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	group := fs.String("group", "", "Pull specific group only")
	filter := fs.String("filter", "", "Filter rules by name or ID (supports * wildcard)")
	fs.Parse(args)

	path := strings.TrimRight(rulePath, "/")
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if url == "" || token == "" {
		fmt.Fprintln(os.Stderr, "Error: URL and token required")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)

	allRules, err := client.Export(*group)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: export failed: %v\n", err)
		return ExitError
	}

	// Apply filter
	var rules []schema.Detection
	for _, r := range allRules {
		if matchesFilter(r.Title, r.ID, *filter) {
			rules = append(rules, r)
		}
	}

	fmt.Printf("Fetched %d rules\n", len(rules))

	lf, _ := lockfile.Load()

	for _, r := range rules {
		dir := path
		if len(r.Groups) > 0 {
			dir = filepath.Join(path, r.Groups[0])
		}

		filename := sanitizeFilename(r.Title)
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

func cmdSync(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	resolve := fs.String("resolve", "", "Resolve conflicts: local or remote")
	message := fs.String("m", "", "Version comment for pushed changes")
	filter := fs.String("filter", "", "Filter rules by name or ID (supports * wildcard)")
	group := fs.String("group", "", "Filter rules by group")
	atomic := fs.Bool("atomic", true, "Rollback all changes if any rule fails")
	fs.Parse(args)

	path := strings.TrimRight(rulePath, "/")
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
	allLocalRules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load local rules: %v\n", err)
		return ExitError
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
		if matchesFilter(r.Title, r.ID, *filter) && matchesGroup(r.Groups, *group) {
			platformByID[r.ID] = r
		}
	}

	var conflicts []conflictInfo
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
			conflicts = append(conflicts, conflictInfo{ID: id, Title: local.Rule.Title})
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
			fmt.Printf("  ! %s (ID: %s)\n", c.Title, c.ID)
		}
		fmt.Println("\nResolve with:")
		fmt.Println("  csctl sync --resolve=local   # Keep local changes")
		fmt.Println("  csctl sync --resolve=remote  # Keep platform changes")
		return ExitConflict
	}

	if *resolve == "local" {
		for _, c := range conflicts {
			if local, exists := localByID[c.ID]; exists {
				toPush = append(toPush, local)
			}
		}
	} else if *resolve == "remote" {
		for _, c := range conflicts {
			toPull = append(toPull, c.ID)
		}
	}

	// Validate before pushing
	if len(toPush) > 0 {
		vResult := validateRules(toPush)
		if !vResult.Valid() {
			fmt.Fprintln(os.Stderr, "Validation errors:")
			for _, e := range vResult.Errors {
				fmt.Fprintf(os.Stderr, "  ! %s\n", e)
			}
			return ExitError
		}
	}

	// Execute push
	if len(toPush) > 0 {
		var apiRules []schema.Detection
		for _, r := range toPush {
			apiRules = append(apiRules, r.Rule)
		}

		resp, err := client.Import(apiRules, *message, "push", *atomic)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: push failed: %v\n", err)
			return ExitError
		}

		logImportStatus(resp.StatusCode)

		if resp.RolledBack {
			fmt.Fprintln(os.Stderr, "ROLLED BACK: One or more rules failed, all changes reverted")
			for _, result := range resp.Results {
				if result.Error != "" {
					fmt.Fprintf(os.Stderr, "  ! %s: %s\n", result.Title, result.Error)
				}
			}
			return ExitError
		}

		if len(resp.Results) != len(toPush) {
			fmt.Fprintf(os.Stderr, "Warning: result count (%d) does not match rule count (%d), skipping lockfile update\n",
				len(resp.Results), len(toPush))
			for _, result := range resp.Results {
				fmt.Printf("  -> %s (%s)\n", result.Title, result.Action)
			}
		} else {
			for i, result := range resp.Results {
				if result.Action == "created" || result.Action == "updated" {
					if toPush[i].Rule.ID == "" && result.ID != "" {
						toPush[i].Rule.ID = result.ID
						if saveErr := internalyaml.SaveFile(toPush[i].Rule, toPush[i].FilePath); saveErr != nil {
							fmt.Fprintf(os.Stderr, "  Warning: failed to write ID back to %s: %v\n", toPush[i].FilePath, saveErr)
						}
					}
					lf.Update(result.ID, toPush[i].FilePath, toPush[i].Hash, result.Version)
				}
				fmt.Printf("  -> %s (%s)\n", result.Title, result.Action)
			}
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

			filename := sanitizeFilename(r.Title)
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

func cmdValidate(args []string, cfg *config.Config, rulePath string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	fs.Parse(args)

	path := strings.TrimRight(rulePath, "/")
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	rules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: validation failed: %v\n", err)
		return ExitError
	}

	errorCount := 0
	for _, r := range rules {
		result := validate.ValidateRule(r.Rule, r.FilePath)
		if !result.Valid() {
			for _, e := range result.Errors {
				fmt.Printf("  ! %s\n", e)
			}
			errorCount++
		} else {
			fmt.Printf("  ok %s\n", r.FilePath)
		}
	}

	if errorCount > 0 {
		fmt.Fprintf(os.Stderr, "\n%d files have errors\n", errorCount)
		return ExitError
	}

	fmt.Printf("\n%d files valid\n", len(rules))
	return ExitSuccess
}

func cmdDiff(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	filter := fs.String("filter", "", "Filter rules by name or ID (supports * wildcard)")
	group := fs.String("group", "", "Filter rules by group")
	fs.Parse(args)

	path := strings.TrimRight(rulePath, "/")
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if url == "" || token == "" {
		fmt.Fprintln(os.Stderr, "Error: URL and token required")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)
	lf, _ := lockfile.Load()

	allLocalRules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load local rules: %v\n", err)
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

func cmdInit(url, token string, args []string, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fromPlatform := fs.Bool("from-platform", false, "Bootstrap from existing platform rules")
	fs.Parse(args)

	path := strings.TrimRight(rulePath, "/")

	if *fromPlatform {
		if url == "" || token == "" {
			fmt.Fprintln(os.Stderr, "Error: URL and token required for --from-platform")
			return ExitError
		}
		return cmdPull(url, token, []string{}, nil, clientOpts, path)
	}

	dirs := []string{path + "/endpoint", path + "/network", path + "/cloud"}
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
	examplePath := path + "/endpoint/example-detection.yaml"
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
		if err := os.WriteFile(".csctl.yaml", []byte(configContent), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create .csctl.yaml: %v\n", err)
			return ExitError
		}
		fmt.Println("  Created .csctl.yaml")
	}

	fmt.Println("\nInitialized! Set CSCTL_TOKEN and update .csctl.yaml with your instance URL.")
	return ExitSuccess
}

// matchesFilter checks if a rule matches the filter pattern (glob-like with * wildcard)
func matchesFilter(title, id, filter string) bool {
	if filter == "" {
		return true
	}
	filter = strings.ToLower(filter)
	title = strings.ToLower(title)
	id = strings.ToLower(id)

	// Check exact ID match first
	if id == filter {
		return true
	}

	// If filter contains glob characters, use filepath.Match
	if strings.ContainsAny(filter, "*?[") {
		if matched, err := filepath.Match(filter, title); err == nil && matched {
			return true
		}
		if matched, err := filepath.Match(filter, id); err == nil && matched {
			return true
		}
		return false
	}

	// Default: substring match on title or ID
	return strings.Contains(title, filter) || strings.Contains(id, filter)
}

// matchesGroup checks if a rule belongs to the specified group
func matchesGroup(groups []string, group string) bool {
	if group == "" {
		return true
	}
	group = strings.ToLower(group)
	for _, g := range groups {
		if strings.ToLower(g) == group {
			return true
		}
	}
	return false
}

func cmdAuth(url, token string, clientOpts []api.ClientOption) int {
	if url == "" || token == "" {
		fmt.Println("Not configured")
		fmt.Println("Set URL in .csctl.yaml and token in CSCTL_TOKEN env var")
		return ExitSuccess
	}

	client := api.NewClient(url, token, clientOpts...)
	me, err := client.GetMe()
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return ExitError
	}

	fmt.Printf("Authenticated to %s\n", url)
	fmt.Printf("  Company:  %s\n", me.Company)
	fmt.Printf("  API Key:  %s\n", me.APIKeyName)
	fmt.Printf("  Scopes:   %s\n", strings.Join(me.Scopes, ", "))
	return ExitSuccess
}

// actionSymbol returns a display symbol for an import result action.
func actionSymbol(action string) string {
	switch action {
	case "created":
		return "+"
	case "updated":
		return "~"
	case "unchanged":
		return "="
	case "error":
		return "!"
	default:
		return "?"
	}
}

// sanitizeFilename converts a rule title to a safe filename.
func sanitizeFilename(title string) string {
	name := strings.ToLower(title)
	name = strings.ReplaceAll(name, " ", "-")
	for _, ch := range []string{"/", "\\", ":", "?", "<", ">", "|", "*", "\"", "'", "\n", "\r", "\t"} {
		name = strings.ReplaceAll(name, ch, "")
	}
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-")
	if name == "" {
		name = "unnamed"
	}
	return name + ".yaml"
}

// validateRules validates a slice of loaded rules using the validate package.
func validateRules(rules []internalyaml.LoadedRule) *validate.Result {
	loaded := make([]validate.LoadedDetection, len(rules))
	for i, r := range rules {
		loaded[i] = validate.LoadedDetection{Rule: r.Rule, File: r.FilePath}
	}
	return validate.ValidateAll(loaded)
}

// logImportStatus prints warnings for non-200 import status codes.
func logImportStatus(statusCode int) {
	switch statusCode {
	case http.StatusConflict:
		fmt.Fprintln(os.Stderr, "Warning: server reported conflicts (409)")
	case http.StatusUnprocessableEntity:
		fmt.Fprintln(os.Stderr, "Warning: server rejected some rules (422)")
	case http.StatusOK, 207:
		// Normal
	default:
		if statusCode != 0 {
			fmt.Fprintf(os.Stderr, "Warning: unexpected status %d from server\n", statusCode)
		}
	}
}
