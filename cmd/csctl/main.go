package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/config"
)

const (
	// ExitSuccess indicates successful execution
	ExitSuccess = 0
	// ExitError indicates an error occurred
	ExitError = 1
	// ExitConflict indicates conflicts were detected
	ExitConflict = 2
)

// Build-time variables set via ldflags.
// GoReleaser sets these automatically; for dev builds use:
//
//	go build -ldflags "-X main.version=dev -X main.commit=$(git rev-parse --short HEAD)" ./cmd/csctl/
var (
	version = "dev"
	commit  = "unknown"
)

var (
	logger *slog.Logger
	errOut io.Writer = os.Stderr
)

func main() {
	// Global flags
	var (
		configFlag   = flag.String("config", "", "Path to config file")
		urlFlag      = flag.String("url", "", "Platform URL (default: https://app.craftedsignal.io)")
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
  library   Library management (index generation, signing)
  generate  Generate detection rules from threat intelligence

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
	if url == "" {
		url = "https://app.craftedsignal.io"
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
	case "version":
		if version == "dev" {
			fmt.Printf("csctl %s (commit: %s)\n", version, commit)
		} else {
			fmt.Printf("csctl %s\n", version)
		}
		os.Exit(ExitSuccess)
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
		exitCode = cmdAuth(url, token, cmdArgs, clientOpts)
	case "library":
		exitCode = cmdLibrary(cmdArgs)
	case "generate":
		exitCode = cmdGenerate(url, token, cmdArgs, cfg, clientOpts, *path)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		flag.Usage()
		exitCode = ExitError
	}

	os.Exit(exitCode)
}
