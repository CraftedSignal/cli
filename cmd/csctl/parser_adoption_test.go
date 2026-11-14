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
