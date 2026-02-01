package validate

import (
	"fmt"
	"strings"

	kql "github.com/craftedsignal/kql-parser"
	leql "github.com/craftedsignal/leql-parser"
	spl "github.com/craftedsignal/spl-parser"

	"github.com/craftedsignal/cli/pkg/schema"
)

// PlatformConstraints defines limits for a SIEM platform.
type PlatformConstraints struct {
	MaxNameLength  int
	MaxQueryLength int
}

// ValidPlatforms maps platform names to their constraints.
var ValidPlatforms = map[string]PlatformConstraints{
	"splunk":      {MaxNameLength: 100, MaxQueryLength: 10000},
	"sentinel":    {MaxNameLength: 256, MaxQueryLength: 30000},
	"crowdstrike": {MaxNameLength: 256, MaxQueryLength: 5000},
	"elastic":     {MaxNameLength: 256, MaxQueryLength: 65536},
	"chronicle":   {MaxNameLength: 128, MaxQueryLength: 10000},
	"rapid7":      {MaxNameLength: 256, MaxQueryLength: 10000},
}

var validSeverities = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

var validKinds = map[string]bool{
	"query": true,
}

// invalidTitleChars are characters that cause issues across platforms and filesystems.
var invalidTitleChars = []string{"/", "\\", ":", "?", "<", ">", "|", "*", "\n", "\r", "\t"}

// ValidationError represents a single validation problem.
type ValidationError struct {
	File    string
	Title   string
	Field   string
	Message string
}

func (e ValidationError) String() string {
	loc := e.File
	if loc == "" {
		loc = e.Title
	}
	return fmt.Sprintf("%s: %s: %s", loc, e.Field, e.Message)
}

// Result holds all validation errors for a set of rules.
type Result struct {
	Errors []ValidationError
}

// Valid returns true if no validation errors were found.
func (r *Result) Valid() bool {
	return len(r.Errors) == 0
}

func (r *Result) add(file, title, field, msg string) {
	r.Errors = append(r.Errors, ValidationError{
		File: file, Title: title, Field: field, Message: msg,
	})
}

// ValidateRule validates a single detection rule.
func ValidateRule(r schema.Detection, file string) *Result {
	res := &Result{}
	title := r.Title
	if title == "" {
		title = "(untitled)"
	}

	// Title checks
	if r.Title == "" {
		res.add(file, title, "title", "must not be empty")
	} else {
		for _, ch := range invalidTitleChars {
			if strings.Contains(r.Title, ch) {
				res.add(file, title, "title", fmt.Sprintf("contains invalid character %q", ch))
				break
			}
		}
	}

	// Platform checks
	platform := strings.ToLower(r.Platform)
	if r.Platform == "" {
		res.add(file, title, "platform", "must not be empty")
	} else {
		constraints, ok := ValidPlatforms[platform]
		if !ok {
			res.add(file, title, "platform",
				fmt.Sprintf("invalid platform %q (valid: splunk, sentinel, crowdstrike, elastic, chronicle, rapid7)", r.Platform))
		} else {
			if r.Title != "" && len(r.Title) > constraints.MaxNameLength {
				res.add(file, title, "title",
					fmt.Sprintf("exceeds max length %d for %s (got %d)", constraints.MaxNameLength, platform, len(r.Title)))
			}
			if r.Query != "" && len(r.Query) > constraints.MaxQueryLength {
				res.add(file, title, "query",
					fmt.Sprintf("exceeds max length %d for %s (got %d)", constraints.MaxQueryLength, platform, len(r.Query)))
			}
		}
	}

	// Query checks
	if r.Query == "" {
		res.add(file, title, "query", "must not be empty")
	} else if r.Platform != "" {
		// Parse query locally if parser is available
		parseQuery(res, r.Query, platform, file, title)
	}

	// Severity checks (only if provided; backend defaults to "medium")
	if r.Severity != "" && !validSeverities[strings.ToLower(r.Severity)] {
		res.add(file, title, "severity",
			fmt.Sprintf("invalid severity %q (valid: low, medium, high, critical)", r.Severity))
	}

	// Kind checks (only if provided; backend defaults to "query")
	if r.Kind != "" && !validKinds[strings.ToLower(r.Kind)] {
		res.add(file, title, "kind",
			fmt.Sprintf("invalid kind %q (valid: query)", r.Kind))
	}

	return res
}

// parseQuery runs platform-specific ANTLR parsers to validate query syntax.
func parseQuery(res *Result, query, platform, file, title string) {
	var parseErrors []string

	switch platform {
	case "splunk", "spl":
		result := spl.ExtractConditions(query)
		parseErrors = result.Errors
	case "sentinel", "kql":
		result := kql.ExtractConditions(query)
		parseErrors = result.Errors
	case "rapid7", "leql", "insightidr":
		result := leql.ExtractConditions(query)
		parseErrors = result.Errors
	default:
		res.add(file, title, "query", fmt.Sprintf("no query parser available for platform %q", platform))
		return
	}

	for _, e := range parseErrors {
		res.add(file, title, "query", fmt.Sprintf("parse error: %s", e))
	}
}

// ValidateAll validates multiple rules, collecting all errors.
func ValidateAll(rules []LoadedDetection) *Result {
	combined := &Result{}
	for _, r := range rules {
		sub := ValidateRule(r.Rule, r.File)
		combined.Errors = append(combined.Errors, sub.Errors...)
	}
	return combined
}

// LoadedDetection pairs a detection with its source file for validation.
type LoadedDetection struct {
	Rule schema.Detection
	File string
}
