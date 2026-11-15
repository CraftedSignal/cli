package main

import (
	"bytes"
	"strings"
	"testing"

	internalyaml "github.com/craftedsignal/cli/internal/yaml"
	craftedsignal "github.com/craftedsignal/sdk-go"
)

func TestParserAdoptionPreflightWarnings(t *testing.T) {
	rule := internalyaml.LoadedRule{FilePath: "opaque.yaml", Rule: craftedsignal.Detection{
		Title: "Opaque", Platform: "splunk", Query: `search * | where x="u" OR (x="v" AND len(y)>2)`,
	}}
	result := validateRules([]internalyaml.LoadedRule{rule})
	if !result.Valid() || len(result.Warnings) == 0 {
		t.Fatalf("valid opaque query must carry a non-blocking preflight warning: %+v", result)
	}
	var output bytes.Buffer
	old := errOut
	errOut = &output
	t.Cleanup(func() { errOut = old })
	reportValidationWarnings(result)
	if !strings.Contains(output.String(), "opaque.yaml") || !strings.Contains(output.String(), "Warning") {
		t.Fatalf("preflight warning was not visible: %q", output.String())
	}
}

func TestParserAdoptionKQLPreflightWarnings(t *testing.T) {
	rule := internalyaml.LoadedRule{FilePath: "opaque-kql.yaml", Rule: craftedsignal.Detection{
		Title: "Opaque KQL", Platform: "sentinel", Query: `Events | where EventID == 1 and strlen(Account) > 3`,
	}}
	result := validateRules([]internalyaml.LoadedRule{rule})
	if !result.Valid() || len(result.Warnings) != 1 {
		t.Fatalf("valid opaque KQL must carry one non-blocking preflight warning: %+v", result)
	}
	var output bytes.Buffer
	old := errOut
	errOut = &output
	t.Cleanup(func() { errOut = old })
	reportValidationWarnings(result)
	if !strings.Contains(output.String(), "opaque-kql.yaml") || !strings.Contains(output.String(), "Warning") || !strings.Contains(output.String(), "incomplete") {
		t.Fatalf("KQL preflight warning was not visible: %q", output.String())
	}
}

func TestParserAdoptionSPLScalarPreflightWarning(t *testing.T) {
	const query = `search x=y | where 5<10 OR x="a"`
	rule := internalyaml.LoadedRule{FilePath: "rules/scalar.yaml", Rule: craftedsignal.Detection{
		Title: "Scalar", Platform: "splunk", Query: query,
	}}
	result := validateRules([]internalyaml.LoadedRule{rule})
	if !result.Valid() || len(result.Warnings) != 1 {
		t.Fatalf("valid opaque SPL must carry one non-blocking preflight warning: %+v", result)
	}
	if rule.Rule.Query != query || result.Warnings[0].File != rule.FilePath || result.Warnings[0].Field != "query" {
		t.Fatalf("preflight changed source or lost attribution: query=%q warnings=%+v", rule.Rule.Query, result.Warnings)
	}
	var output bytes.Buffer
	old := errOut
	errOut = &output
	t.Cleanup(func() { errOut = old })
	reportValidationWarnings(result)
	if !strings.Contains(output.String(), rule.FilePath) || !strings.Contains(output.String(), "Warning") || !strings.Contains(output.String(), "incomplete") {
		t.Fatalf("SPL scalar preflight warning was not visible: %q", output.String())
	}
}
