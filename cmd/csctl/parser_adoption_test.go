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

func TestWave2PreflightReportsExactParserDiagnostics(t *testing.T) {
	const kqlQuery = `Events | parse raw with prefix ':' parsed | where EventID == 1`
	const splQuery = `search x=a | join user [ search z=a | mystery y ]`
	rules := []internalyaml.LoadedRule{
		{FilePath: "rules/opaque-kql.yaml", Rule: craftedsignal.Detection{Title: "Opaque stage", Platform: "sentinel", Query: kqlQuery}},
		{FilePath: "rules/join-spl.yaml", Rule: craftedsignal.Detection{Title: "Join child", Platform: "splunk", Query: splQuery}},
	}
	result := validateRules(rules)
	if !result.Valid() || len(result.Warnings) != 5 || rules[0].Rule.Query != kqlQuery || rules[1].Rule.Query != splQuery {
		t.Fatalf("preflight lost original query or parser warnings: %+v", result)
	}
	var output bytes.Buffer
	old := errOut
	errOut = &output
	t.Cleanup(func() { errOut = old })
	reportValidationWarnings(result)
	want := "  Warning: rules/opaque-kql.yaml: query: dataflow:unsupported_stage_dataflow: removed parse stage has unrepresented output\n" +
		"  Warning: rules/opaque-kql.yaml: query: dataflow:unresolved_field_binding: field EventID cannot be resolved in s1\n" +
		"  Warning: rules/join-spl.yaml: query: dataflow:unsupported_stage_dataflow: unsupported field scope for join\n" +
		"  Warning: rules/join-spl.yaml: query: boolean expression unavailable: query contains an unsupported or unrepresented boolean operand\n" +
		"  Warning: rules/join-spl.yaml: query: uses join command — may impact test generation accuracy\n"
	if output.String() != want {
		t.Fatalf("preflight displayed wrong warnings:\ngot: %q\nwant: %q", output.String(), want)
	}
}
