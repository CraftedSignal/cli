package validate

import (
	"fmt"
	"strings"

	kql "github.com/craftedsignal/kql-parser"
	leql "github.com/craftedsignal/leql-parser"
	craftedsignal "github.com/craftedsignal/sdk-go"
	spl "github.com/craftedsignal/spl-parser"
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

// ValidationWarning represents a non-blocking validation note.
type ValidationWarning struct {
	File    string
	Title   string
	Field   string
	Message string
}

func (w ValidationWarning) String() string {
	loc := w.File
	if loc == "" {
		loc = w.Title
	}
	return fmt.Sprintf("%s: %s: %s", loc, w.Field, w.Message)
}

// Result holds all validation errors and warnings for a set of rules.
type Result struct {
	Errors   []ValidationError
	Warnings []ValidationWarning
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

func (r *Result) addWarning(file, title, field, msg string) {
	r.Warnings = append(r.Warnings, ValidationWarning{
		File: file, Title: title, Field: field, Message: msg,
	})
}

// ValidateRule validates a single detection rule.
func ValidateRule(r craftedsignal.Detection, file string) *Result {
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
	warningStart := len(res.Warnings)

	switch platform {
	case "splunk", "spl":
		result := spl.ExtractConditions(query)
		warnings, errors := collectSPLDiagnostics(result)
		parseErrors = errors
		for _, warning := range warnings {
			res.addWarning(file, title, "query", warning)
		}
		if len(parseErrors) == 0 && hasOpaqueSPLFilter(result) {
			res.addWarning(file, title, "query", "SPL filter contains an opaque predicate; local validation is incomplete")
		}
		addSPLWarnings(res, result, query, file, title)
	case "sentinel", "kql":
		result := kql.ExtractConditions(query)
		warnings, errors := collectKQLDiagnostics(result)
		parseErrors = errors
		for _, warning := range warnings {
			res.addWarning(file, title, "query", warning)
		}
		if len(parseErrors) == 0 && hasOpaqueKQLFilter(result) {
			res.addWarning(file, title, "query", "KQL filter contains an opaque predicate; local validation is incomplete")
		}
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
	// A join child may also appear in the parser's compatibility Subsearches
	// slice. Keep its first displayed warning within this query.
	seen := make(map[string]bool)
	unique := res.Warnings[:warningStart]
	for _, warning := range res.Warnings[warningStart:] {
		if !seen[warning.Message] {
			seen[warning.Message] = true
			unique = append(unique, warning)
		}
	}
	res.Warnings = unique
}

// collectKQLDiagnostics visits independently returned join results in parser order.
func collectKQLDiagnostics(result *kql.ParseResult) (warnings, errors []string) {
	if result == nil {
		return nil, nil
	}
	warnings = append(warnings, result.Warnings...)
	errors = append(errors, result.Errors...)
	for _, join := range result.Joins {
		childWarnings, childErrors := collectKQLDiagnostics(join.Subsearch)
		warnings = append(warnings, childWarnings...)
		errors = append(errors, childErrors...)
	}
	return warnings, errors
}

// collectSPLDiagnostics visits join and direct-subsearch results in parser order.
func collectSPLDiagnostics(result *spl.ParseResult) (warnings, errors []string) {
	if result == nil {
		return nil, nil
	}
	warnings = append(warnings, result.Warnings...)
	errors = append(errors, result.Errors...)
	for _, join := range result.Joins {
		childWarnings, childErrors := collectSPLDiagnostics(join.Subsearch)
		warnings = append(warnings, childWarnings...)
		errors = append(errors, childErrors...)
	}
	for _, subsearch := range result.Subsearches {
		childWarnings, childErrors := collectSPLDiagnostics(subsearch)
		warnings = append(warnings, childWarnings...)
		errors = append(errors, childErrors...)
	}
	return warnings, errors
}

func hasOpaqueKQLFilter(result *kql.ParseResult) bool {
	if result == nil {
		return false
	}
	if hasOpaqueKQLExpression(result.Expression) {
		return true
	}
	for _, join := range result.Joins {
		if hasOpaqueKQLFilter(join.Subsearch) {
			return true
		}
	}
	return false
}

func hasOpaqueKQLExpression(expr *kql.ConditionExpression) bool {
	if expr == nil {
		return false
	}
	if expr.Operator == kql.BooleanScalar || expr.Operator == kql.BooleanSearch {
		return true
	}
	for _, child := range expr.Children {
		if hasOpaqueKQLExpression(child) {
			return true
		}
	}
	return false
}

func hasOpaqueSPLFilter(result *spl.ParseResult) bool {
	if result == nil || len(result.Errors) != 0 {
		return false
	}
	// An incomplete parent expression can still contain a separately parsed
	// subsearch whose scalar leaf is complete.
	if !result.ExpressionIncomplete && hasOpaqueSPLExpression(result.Expression) {
		return true
	}
	for _, subsearch := range result.Subsearches {
		if hasOpaqueSPLFilter(subsearch) {
			return true
		}
	}
	for _, join := range result.Joins {
		if hasOpaqueSPLFilter(join.Subsearch) {
			return true
		}
	}
	return false
}

func hasOpaqueSPLExpression(expr *spl.ConditionExpression) bool {
	if expr == nil {
		return false
	}
	if expr.Operator == spl.BooleanScalar && expr.Scalar != nil {
		return true
	}
	for _, child := range expr.Children {
		if hasOpaqueSPLExpression(child) {
			return true
		}
	}
	return false
}

// addSPLWarnings adds non-blocking warnings based on SPL parse results.
func addSPLWarnings(res *Result, result *spl.ParseResult, query, file, title string) {
	// Macro detection (backtick syntax — can't validate locally)
	if strings.Contains(query, "`") {
		res.addWarning(file, title, "query", "contains macros (backtick syntax) — cannot validate locally")
	}

	// Join/append usage
	for _, cmd := range result.Commands {
		if cmd == "join" || cmd == "append" {
			res.addWarning(file, title, "query", fmt.Sprintf("uses %s command — may impact test generation accuracy", cmd))
		}
	}

	// Datamodel reference
	if dm, ok := result.ComputedFields["_datamodel"]; ok {
		res.addWarning(file, title, "query", fmt.Sprintf("references datamodel %q", dm))
	}

	// High pipeline complexity
	if len(result.Commands) > 10 {
		res.addWarning(file, title, "query", fmt.Sprintf("high pipeline complexity (%d commands)", len(result.Commands)))
	}
}

// ValidateAll validates multiple rules, collecting all errors.
func ValidateAll(rules []LoadedDetection) *Result {
	combined := &Result{}
	for _, r := range rules {
		sub := ValidateRule(r.Rule, r.File)
		combined.Errors = append(combined.Errors, sub.Errors...)
		combined.Warnings = append(combined.Warnings, sub.Warnings...)
	}
	return combined
}

// LoadedDetection pairs a detection with its source file for validation.
type LoadedDetection struct {
	Rule craftedsignal.Detection
	File string
}
