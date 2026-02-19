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

func cmdPull(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	group := fs.String("group", "", "Pull specific group only")
	filter := fs.String("filter", "", "Filter rules by name or ID (supports * wildcard)")
	_ = fs.Parse(args)

	if *tokenFlag != "" {
		token = *tokenFlag
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

	allRules, err := client.Export(*group)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: export failed: %v\n", err)
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

	usedPaths := make(map[string]bool)
	for _, r := range rules {
		dir := path
		if len(r.Groups) > 0 {
			dir = filepath.Join(path, r.Groups[0])
		}

		filename := sanitizeFilename(r.Title)
		filePath := filepath.Join(dir, filename)

		// Handle filename collisions by appending rule ID suffix
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

		fmt.Printf("  + %s -> %s\n", r.Title, filePath)
	}

	_ = lf.Save()
	return ExitSuccess
}
