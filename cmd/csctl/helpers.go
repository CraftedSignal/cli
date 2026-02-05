package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/lockfile"
	"github.com/craftedsignal/cli/internal/validate"
	internalyaml "github.com/craftedsignal/cli/internal/yaml"
)

// conflictInfo tracks a sync conflict by rule ID and title.
type conflictInfo struct {
	ID    string
	Title string
}

// syncPushItem tracks a rule to push with the reason why.
type syncPushItem struct {
	Rule   internalyaml.LoadedRule
	Reason string
}

// syncPullItem tracks a rule ID to pull with the reason why.
type syncPullItem struct {
	ID     string
	Reason string
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

// filterChangedRules returns only rules that have changed since the last sync.
// A rule is considered changed if it has no ID, is not in the lockfile, or its
// hash differs from the last synced hash.
func filterChangedRules(rules []internalyaml.LoadedRule, lf *lockfile.Lockfile) []internalyaml.LoadedRule {
	var changed []internalyaml.LoadedRule
	for _, r := range rules {
		if r.Rule.ID == "" {
			changed = append(changed, r)
			continue
		}
		lastSync, wasSynced := lf.Get(r.Rule.ID)
		if !wasSynced || r.Hash != lastSync.LastSyncedHash {
			changed = append(changed, r)
		}
	}
	return changed
}

// runTests triggers test execution on the platform and polls for results.
// Only tests rules that have an ID (exist on the platform) and have test cases.
// Returns true if all tests passed or no rules are testable.
func runTests(client *api.Client, rules []internalyaml.LoadedRule) bool {
	var testIDs []string
	for _, r := range rules {
		if r.Rule.ID != "" && r.Rule.Tests != nil &&
			(len(r.Rule.Tests.Positive) > 0 || len(r.Rule.Tests.Negative) > 0) {
			testIDs = append(testIDs, r.Rule.ID)
		}
	}

	if len(testIDs) == 0 {
		return true
	}

	fmt.Printf("Triggering tests for %d rules...\n", len(testIDs))

	// Trigger test workflows
	resp, err := client.RunTests(testIDs)
	if err != nil {
		fmt.Fprintf(errOut, "Error: failed to trigger tests: %v\n", err)
		return false
	}

	// Collect IDs of tests that were actually started
	var startedIDs []string
	for _, result := range resp.Results {
		switch result.Action {
		case "started":
			fmt.Printf("  ~ %s (testing...)\n", result.Title)
			startedIDs = append(startedIDs, result.ID)
		case "skipped":
			fmt.Printf("  - %s (%s)\n", result.Title, result.Error)
		case "error":
			fmt.Fprintf(errOut, "  ! %s: %s\n", result.Title, result.Error)
		}
	}

	if len(startedIDs) == 0 {
		if resp.Errors > 0 {
			fmt.Fprintln(errOut, "All test triggers failed")
			return false
		}
		fmt.Println("No tests were triggered")
		return true
	}

	// Poll for test completion
	fmt.Printf("Waiting for %d test runs to complete...\n", len(startedIDs))
	const maxPolls = 60 // 5 minutes at 5s intervals
	const pollInterval = 5 * time.Second

	for i := 0; i < maxPolls; i++ {
		time.Sleep(pollInterval)

		status, err := client.GetTestStatus(startedIDs)
		if err != nil {
			fmt.Fprintf(errOut, "Error: failed to get test status: %v\n", err)
			return false
		}

		if status.Pending == 0 {
			// All tests completed
			allPassed := true
			for _, result := range status.Results {
				switch result.TestStatus {
				case "passing":
					fmt.Printf("  ok %s\n", result.Title)
				case "failing":
					allPassed = false
					fmt.Fprintf(errOut, "  FAIL %s\n", result.Title)
					for _, f := range result.FailedTests {
						if f.Error != "" {
							fmt.Fprintf(errOut, "       - %s (%s): %s\n", f.Name, f.Type, f.Error)
						} else if f.Type == "positive" && f.Matches == 0 {
							fmt.Fprintf(errOut, "       - %s (%s): expected match, got none\n", f.Name, f.Type)
						} else if f.Type == "negative" && f.Matches > 0 {
							fmt.Fprintf(errOut, "       - %s (%s): expected no match, got %d\n", f.Name, f.Type, f.Matches)
						} else {
							fmt.Fprintf(errOut, "       - %s (%s): failed\n", f.Name, f.Type)
						}
					}
				case "error":
					allPassed = false
					fmt.Fprintf(errOut, "  ERROR %s\n", result.Title)
					for _, f := range result.FailedTests {
						if f.Error != "" {
							fmt.Fprintf(errOut, "       - %s: %s\n", f.Name, f.Error)
						}
					}
				default:
					fmt.Printf("  ? %s (%s)\n", result.Title, result.TestStatus)
				}
			}

			fmt.Printf("\nTests: %d passed, %d failed\n", status.Passed, status.Failed)
			return allPassed
		}
	}

	fmt.Fprintln(errOut, "Error: test execution timed out after 5 minutes")
	return false
}

// validateRules validates a slice of loaded rules using the validate package.
func validateRules(rules []internalyaml.LoadedRule) *validate.Result {
	loaded := make([]validate.LoadedDetection, len(rules))
	for i, r := range rules {
		loaded[i] = validate.LoadedDetection{Rule: r.Rule, File: r.FilePath}
	}
	return validate.ValidateAll(loaded)
}

// getFileMtime returns the modification time of a file, or zero time on error.
func getFileMtime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// getFileRuleID reads a YAML file and returns its rule ID, or empty string on error.
func getFileRuleID(path string) string {
	rules, _ := internalyaml.LoadFile(path, "")
	if len(rules) > 0 {
		return rules[0].Rule.ID
	}
	return ""
}

// logImportStatus prints warnings for non-200 import status codes.
func logImportStatus(statusCode int) {
	switch statusCode {
	case http.StatusConflict:
		fmt.Fprintln(errOut, "Warning: server reported conflicts (409)")
	case http.StatusUnprocessableEntity:
		fmt.Fprintln(errOut, "Warning: server rejected some rules (422)")
	case http.StatusOK, 207:
		// Normal
	default:
		if statusCode != 0 {
			fmt.Fprintf(errOut, "Warning: unexpected status %d from server\n", statusCode)
		}
	}
}
