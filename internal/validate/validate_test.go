package validate

import (
	"strings"
	"testing"

	craftedsignal "github.com/craftedsignal/sdk-go"
)

func TestValidateRuleRequiredFieldsAndMetadata(t *testing.T) {
	tests := []struct {
		name   string
		rule   craftedsignal.Detection
		fields []string
	}{
		{"empty rule", craftedsignal.Detection{}, []string{"title", "platform", "query"}},
		{"valid sentinel", craftedsignal.Detection{Title: "Failed logins", Platform: "sentinel", Query: "SecurityEvent | where EventID == 4625"}, nil},
		{"case insensitive metadata", craftedsignal.Detection{Title: "Failed logins", Platform: "SENTINEL", Query: "SecurityEvent | where EventID == 4625", Severity: "HIGH", Kind: "QUERY"}, nil},
		{"unsafe title", craftedsignal.Detection{Title: "folder/rule", Platform: "sentinel", Query: "SecurityEvent | where EventID == 4625"}, []string{"title"}},
		{"unknown platform", craftedsignal.Detection{Title: "Rule", Platform: "unknown", Query: "events"}, []string{"platform", "query"}},
		{"unsupported severity", craftedsignal.Detection{Title: "Rule", Platform: "sentinel", Query: "SecurityEvent | where EventID == 4625", Severity: "urgent"}, []string{"severity"}},
		{"unsupported kind", craftedsignal.Detection{Title: "Rule", Platform: "sentinel", Query: "SecurityEvent | where EventID == 4625", Kind: "script"}, []string{"kind"}},
		{"invalid syntax", craftedsignal.Detection{Title: "Rule", Platform: "sentinel", Query: "SecurityEvent | where ("}, []string{"query"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRule(tt.rule, "rules/test.yaml")
			wanted := make(map[string]bool, len(tt.fields))
			for _, field := range tt.fields {
				wanted[field] = true
			}
			if result.Valid() != (len(tt.fields) == 0) {
				t.Fatalf("validation errors = %#v; want fields %v", result.Errors, tt.fields)
			}
			seen := make(map[string]bool)
			for _, failure := range result.Errors {
				if !wanted[failure.Field] || failure.File != "rules/test.yaml" {
					t.Errorf("unexpected validation error: %#v", failure)
				}
				seen[failure.Field] = true
			}
			for _, field := range tt.fields {
				if !seen[field] {
					t.Errorf("missing %q validation error: %#v", field, result.Errors)
				}
			}
		})
	}
}

func TestValidateRuleSentinelNameBoundary(t *testing.T) {
	for _, length := range []int{256, 257} {
		rule := craftedsignal.Detection{Title: strings.Repeat("a", length), Platform: "sentinel", Query: "SecurityEvent | where EventID == 4625"}
		result := ValidateRule(rule, "rule.yaml")
		if result.Valid() != (length == 256) {
			t.Errorf("title length %d: errors = %#v", length, result.Errors)
		}
	}
}

func TestValidateAllRetainsEachSourceFile(t *testing.T) {
	result := ValidateAll([]LoadedDetection{
		{File: "one.yaml", Rule: craftedsignal.Detection{Platform: "sentinel", Query: "SecurityEvent | where EventID == 4625"}},
		{File: "two.yaml", Rule: craftedsignal.Detection{Title: "Rule", Platform: "sentinel"}},
	})
	if len(result.Errors) != 2 || result.Errors[0].File != "one.yaml" || result.Errors[0].Field != "title" || result.Errors[1].File != "two.yaml" || result.Errors[1].Field != "query" {
		t.Fatalf("validation errors lost source attribution: %#v", result.Errors)
	}
}

func TestParserAdoptionQueryDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, platform, query string
		valid, warning        bool
	}{
		{"KQL scalar", "sentinel", `Events | where 5 > 10`, true, false},
		{"LEQL loose", "rapid7", `where(user=admin, loose)`, true, false},
		{"SPL incomplete Boolean", "splunk", `search * | where x="u" OR (x="v" AND len(y)>2)`, true, true},
		{"invalid KQL", "sentinel", `Events | where (`, false, false},
		{"invalid LEQL", "rapid7", `where(`, false, false},
		{"invalid SPL", "splunk", `search * | where (`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := craftedsignal.Detection{Title: "Parser adoption", Platform: tc.platform, Query: tc.query}
			result := ValidateRule(rule, "rule.yaml")
			if result.Valid() != tc.valid {
				t.Fatalf("valid=%v, want %v: errors=%v", result.Valid(), tc.valid, result.Errors)
			}
			if (len(result.Warnings) > 0) != tc.warning {
				t.Fatalf("warning=%v, want %v: warnings=%v", len(result.Warnings) > 0, tc.warning, result.Warnings)
			}
		})
	}
}

func TestParserAdoptionValidateAllRetainsWarnings(t *testing.T) {
	query := `search * | where x="u" OR (x="v" AND len(y)>2)`
	result := ValidateAll([]LoadedDetection{{File: "opaque.yaml", Rule: craftedsignal.Detection{Title: "Opaque", Platform: "splunk", Query: query}}})
	if !result.Valid() || len(result.Warnings) == 0 || result.Warnings[0].File != "opaque.yaml" {
		t.Fatalf("non-blocking warning lost before push/sync preflight: %+v", result)
	}
}
