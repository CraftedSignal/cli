package library

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIndexYAMLUsesGuidanceKeys(t *testing.T) {
	idx := &Index{
		Version: IndexVersion,
		Repository: RepositoryInfo{
			Name:      "Acme Library",
			UpdatedAt: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		},
		Entries: []IndexEntry{},
		Guidance: []GuidanceEntry{
			{
				ID:        "baseline-triage",
				Name:      "Baseline Triage",
				Body:      "# Baseline Triage\n\nValidate alert context.",
				Status:    "reviewed",
				AppliesTo: []string{"rule"},
				Tactics:   []string{"execution"},
				Tags:      []string{"endpoint"},
			},
		},
		GuidanceAssignments: []GuidanceAssignment{
			{
				ID:        "endpoint-execution",
				AppliesTo: "rule",
				Guidance:  []string{"baseline-triage"},
				Mode:      "track_reviewed",
				Match: GuidanceAssignmentMatch{
					Tactics: []string{"execution"},
					TagsAny: []string{"endpoint"},
				},
			},
		},
	}

	var out bytes.Buffer
	if err := idx.WriteYAML(&out); err != nil {
		t.Fatalf("WriteYAML: %v", err)
	}
	body := out.String()
	for _, want := range []string{
		"\nguidance:\n",
		"\nguidance_assignments:\n",
		"    guidance:\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected index YAML to contain %q:\n%s", want, body)
		}
	}
	for _, unwanted := range []string{
		"\nguides:\n",
		"\nguidance_books:\n",
		"    guides:\n",
		"    books:\n",
	} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected index YAML not to contain %q:\n%s", unwanted, body)
		}
	}
}

func TestGuidanceEntryDoesNotExposeSeverity(t *testing.T) {
	if _, ok := reflect.TypeOf(GuidanceEntry{}).FieldByName("Severity"); ok {
		t.Fatal("GuidanceEntry should not expose Severity")
	}
}

func TestGuidanceEntryDoesNotExposePlatformOrDataSources(t *testing.T) {
	for _, field := range []string{"Platforms", "DataSources"} {
		if _, ok := reflect.TypeOf(GuidanceEntry{}).FieldByName(field); ok {
			t.Fatalf("GuidanceEntry should not expose %s", field)
		}
	}
	if _, ok := reflect.TypeOf(GuidanceAssignmentMatch{}).FieldByName("Platforms"); ok {
		t.Fatal("GuidanceAssignmentMatch should not expose Platforms")
	}
}
