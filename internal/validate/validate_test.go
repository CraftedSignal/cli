package validate

import (
	"reflect"
	"strings"
	"testing"

	kql "github.com/craftedsignal/kql-parser"
	craftedsignal "github.com/craftedsignal/sdk-go"
	spl "github.com/craftedsignal/spl-parser"
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
		{"KQL scalar", "sentinel", `Events | where 5 > 10`, true, true},
		{"KQL mixed scalar", "sentinel", `Events | where EventID == 1 and strlen(Account) > 3`, true, true},
		{"KQL search", "sentinel", `Events | search "mimikatz"`, true, true},
		{"KQL joined scalar", "sentinel", `Events | join kind=inner (OtherEvents | where strlen(Account) > 3) on Account`, true, true},
		{"KQL supported", "sentinel", `Events | where EventID == 1`, true, false},
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

func TestParserAdoptionKQLWarningsRetainSource(t *testing.T) {
	result := ValidateAll([]LoadedDetection{{File: "opaque-kql.yaml", Rule: craftedsignal.Detection{
		Title: "Opaque KQL", Platform: "sentinel", Query: `Events | where EventID == 1 and strlen(Account) > 3`,
	}}})
	if !result.Valid() || len(result.Warnings) != 1 {
		t.Fatalf("valid opaque KQL must carry one non-blocking warning: %+v", result)
	}
	warning := result.Warnings[0]
	if warning.File != "opaque-kql.yaml" || warning.Title != "Opaque KQL" || warning.Field != "query" || !strings.Contains(warning.Message, "incomplete") {
		t.Fatalf("KQL preflight warning lost attribution or meaning: %+v", warning)
	}
}

func TestSPLScalarAssessabilityWarning(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		valid       bool
		opaque      bool
	}{
		{"numeric predicate", `| where x>42`, true, false},
		{"quoted predicate", `| where x>"42"`, true, false},
		{"search predicate", `search x=y`, true, false},
		{"adjacent wildcard predicates", `search user=* action=*`, true, false},
		{"scalar only", `| where 5<10`, true, true},
		{"multiple scalar leaves", `| where 5<10 OR 8>4`, true, true},
		{"computed scalar", `| where x+1>42`, true, true},
		{"mixed scalar", `| where NOT (5<10) OR x="a"`, true, true},
		{"direct subsearch scalar", `search x=y [ search a=b | where 5<10 ]`, true, true},
		{"nested append scalar", `search x=y | append [ search a=b | where 5<10 ]`, true, true},
		{"nested join scalar", `search x=y | join x [ search a=b | where 5<10 ]`, true, true},
		{"malformed predicate", `| where x >`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateAll([]LoadedDetection{{File: "rules/scalar.yaml", Rule: craftedsignal.Detection{
				Title: "Scalar", Platform: "splunk", Query: tc.query,
			}}})
			if result.Valid() != tc.valid {
				t.Fatalf("valid=%v, want %v: errors=%#v warnings=%#v", result.Valid(), tc.valid, result.Errors, result.Warnings)
			}
			opaque := 0
			for _, warning := range result.Warnings {
				if warning.File != "rules/scalar.yaml" || warning.Title != "Scalar" || warning.Field != "query" {
					t.Errorf("warning lost file attribution: %#v", warning)
				}
				if strings.Contains(warning.Message, "opaque") && strings.Contains(warning.Message, "incomplete") {
					opaque++
				}
			}
			if (opaque == 1) != tc.opaque || opaque > 1 {
				t.Fatalf("opaque assessability warnings=%d, want one=%v: %#v", opaque, tc.opaque, result.Warnings)
			}
		})
	}
}

func TestWave2KQLRootDiagnosticsWithoutScalar(t *testing.T) {
	const query = `Events | parse raw with prefix ':' parsed | where EventID == 1`
	parsed := kql.ExtractConditions(query)
	wantMessages := []string{
		"dataflow:unsupported_stage_dataflow: removed parse stage has unrepresented output",
		"dataflow:unresolved_field_binding: field EventID cannot be resolved in s1",
	}
	if len(parsed.Errors) != 0 || !reflect.DeepEqual(parsed.Warnings, wantMessages) || parsed.Expression == nil || parsed.Expression.Operator != kql.BooleanCondition {
		t.Fatalf("fixture must have real parser warnings without scalar: warnings=%q errors=%q expression=%#v", parsed.Warnings, parsed.Errors, parsed.Expression)
	}
	rule := craftedsignal.Detection{Title: "Opaque stage", Platform: "sentinel", Query: query}
	result := ValidateRule(rule, "rules/opaque-kql.yaml")
	if !result.Valid() || rule.Query != query {
		t.Fatalf("valid opaque query changed or failed: rule=%+v result=%+v", rule, result)
	}
	want := []ValidationWarning{
		{File: "rules/opaque-kql.yaml", Title: "Opaque stage", Field: "query", Message: wantMessages[0]},
		{File: "rules/opaque-kql.yaml", Title: "Opaque stage", Field: "query", Message: wantMessages[1]},
	}
	if !reflect.DeepEqual(result.Warnings, want) {
		t.Fatalf("KQL parser warnings lost text or attribution: got=%+v want=%+v", result.Warnings, want)
	}
	ordinary := ValidateRule(craftedsignal.Detection{Title: "Ordinary", Platform: "sentinel", Query: `Events | where EventID == 1`}, "rules/ordinary.yaml")
	if !ordinary.Valid() || len(ordinary.Warnings) != 0 {
		t.Fatalf("ordinary query gained diagnostics: %+v", ordinary)
	}
}

func TestWave2OrdinarySPLHasNoWarning(t *testing.T) {
	result := ValidateRule(craftedsignal.Detection{Title: "Ordinary SPL", Platform: "splunk", Query: `search x=y`}, "rules/ordinary-spl.yaml")
	if !result.Valid() || len(result.Warnings) != 0 {
		t.Fatalf("ordinary SPL query gained diagnostics: %+v", result)
	}
}

func TestWave2KQLJoinChildDiagnostics(t *testing.T) {
	const query = `Events | join kind=inner (OtherEvents | parse raw with prefix ':' parsed | where EventID == 1) on Account`
	parsed := kql.ExtractConditions(query)
	if len(parsed.Errors) != 0 || len(parsed.Joins) != 1 || parsed.Joins[0].Subsearch == nil || len(parsed.Joins[0].Subsearch.Warnings) != 2 {
		t.Fatalf("fixture needs an independently returned warning child: %+v", parsed)
	}
	result := ValidateRule(craftedsignal.Detection{Title: "Join child", Platform: "sentinel", Query: query}, "rules/join.yaml")
	want := []ValidationWarning{
		{File: "rules/join.yaml", Title: "Join child", Field: "query", Message: "dataflow:unsupported_stage_dataflow: unrepresented join output"},
		{File: "rules/join.yaml", Title: "Join child", Field: "query", Message: "dataflow:unsupported_stage_dataflow: removed parse stage has unrepresented output"},
		{File: "rules/join.yaml", Title: "Join child", Field: "query", Message: "dataflow:unresolved_field_binding: field EventID cannot be resolved in s1"},
	}
	if !result.Valid() || !reflect.DeepEqual(result.Warnings, want) {
		t.Fatalf("KQL join diagnostics lost child or parent attribution: got=%+v want=%+v", result, want)
	}
}

func TestWave2SPLJoinChildWarningDeduplicated(t *testing.T) {
	const query = `search x=a | join user [ search z=a | mystery y ]`
	parsed := spl.ExtractConditions(query)
	if len(parsed.Errors) != 0 || len(parsed.Joins) != 1 || parsed.Joins[0].Subsearch == nil || len(parsed.Subsearches) != 1 ||
		!reflect.DeepEqual(parsed.Joins[0].Subsearch.Warnings, parsed.Subsearches[0].Warnings) {
		t.Fatalf("fixture needs join and compatibility child warnings: %+v", parsed)
	}
	result := ValidateRule(craftedsignal.Detection{Title: "Join child", Platform: "splunk", Query: query}, "rules/join-spl.yaml")
	want := []ValidationWarning{
		{File: "rules/join-spl.yaml", Title: "Join child", Field: "query", Message: "dataflow:unsupported_stage_dataflow: unsupported field scope for join"},
		{File: "rules/join-spl.yaml", Title: "Join child", Field: "query", Message: "boolean expression unavailable: query contains an unsupported or unrepresented boolean operand"},
		{File: "rules/join-spl.yaml", Title: "Join child", Field: "query", Message: "uses join command — may impact test generation accuracy"},
	}
	if !result.Valid() || !reflect.DeepEqual(result.Warnings, want) {
		t.Fatalf("SPL duplicate child warning was lost or repeated: got=%+v want=%+v", result, want)
	}
}

func TestWave2SameWarningKeptForEachFile(t *testing.T) {
	const query = `Events | parse raw with prefix ':' parsed | where EventID == 1`
	result := ValidateAll([]LoadedDetection{
		{File: "rules/one.yaml", Rule: craftedsignal.Detection{Title: "One", Platform: "sentinel", Query: query}},
		{File: "rules/two.yaml", Rule: craftedsignal.Detection{Title: "Two", Platform: "sentinel", Query: query}},
	})
	if !result.Valid() || len(result.Warnings) != 4 {
		t.Fatalf("each file should retain its two parser warnings: %+v", result)
	}
	for i, want := range []struct{ file, title, message string }{
		{"rules/one.yaml", "One", "dataflow:unsupported_stage_dataflow: removed parse stage has unrepresented output"},
		{"rules/one.yaml", "One", "dataflow:unresolved_field_binding: field EventID cannot be resolved in s1"},
		{"rules/two.yaml", "Two", "dataflow:unsupported_stage_dataflow: removed parse stage has unrepresented output"},
		{"rules/two.yaml", "Two", "dataflow:unresolved_field_binding: field EventID cannot be resolved in s1"},
	} {
		got := result.Warnings[i]
		if got.File != want.file || got.Title != want.title || got.Field != "query" || got.Message != want.message {
			t.Fatalf("warning %d lost exact per-file attribution: %+v want=%+v", i, got, want)
		}
	}
}

func TestWave2SyntaxAndSourceFailuresRemainInvalid(t *testing.T) {
	for _, tc := range []struct {
		name, platform, query, message string
		expectedTokens                 bool // the message continues with the grammar's expected-token set
	}{
		{name: "KQL source", platform: "sentinel", query: `Events | join kind=inner (OtherEvents | where () on Account`, message: "parse error: dataflow source unavailable: join child has no authored owner"},
		{name: "KQL syntax", platform: "sentinel", query: `Events | where (`, message: "parse error: no viable alternative at input '('"},
		{name: "SPL syntax", platform: "splunk", query: `| where (`, message: "parse error: mismatched input '<EOF>' expecting {", expectedTokens: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateRule(craftedsignal.Detection{Title: "Bad query", Platform: tc.platform, Query: tc.query}, "rules/bad.yaml")
			if result.Valid() || len(result.Errors) != 1 {
				t.Fatalf("parser failure must invalidate exact source: got=%+v", result)
			}
			got := result.Errors[0]
			// Every grammar addition changes the token inventory; it is not a CLI contract.
			if tc.expectedTokens && strings.HasPrefix(got.Message, tc.message) {
				got.Message = tc.message
			}
			want := ValidationError{File: "rules/bad.yaml", Title: "Bad query", Field: "query", Message: tc.message}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("parser failure must invalidate exact source: got=%+v want=%+v", got, want)
			}
		})
	}
}

func TestWave2CollectorsKeepChildErrorsWhenRootHasNone(t *testing.T) {
	kqlRoot := &kql.ParseResult{Joins: []kql.JoinInfo{{Subsearch: &kql.ParseResult{Errors: []string{"child KQL failure"}}}}}
	_, kqlErrors := collectKQLDiagnostics(kqlRoot)
	if !reflect.DeepEqual(kqlErrors, []string{"child KQL failure"}) {
		t.Fatalf("KQL child failure lost: %q", kqlErrors)
	}
	splRoot := &spl.ParseResult{Joins: []spl.JoinInfo{{Subsearch: &spl.ParseResult{Errors: []string{"child SPL failure"}}}}}
	_, splErrors := collectSPLDiagnostics(splRoot)
	if !reflect.DeepEqual(splErrors, []string{"child SPL failure"}) {
		t.Fatalf("SPL child failure lost: %q", splErrors)
	}
}
