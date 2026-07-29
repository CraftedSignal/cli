package yaml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	craftedsignal "github.com/craftedsignal/sdk-go"
)

func TestLoadFileParsesOperationalGuidance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rule.yaml")
	input := `title: Suspicious PowerShell
platform: sentinel
query: SecurityEvent
enabled: true
operational_guidance: |
  # Response

  1. Validate the process tree.
  2. Escalate confirmed abuse.
`

	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadFile(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}

	want := "# Response\n\n1. Validate the process tree.\n2. Escalate confirmed abuse.\n"
	if got := rules[0].Rule.OperationalGuidance; got != want {
		t.Fatalf("OperationalGuidance = %q, want %q", got, want)
	}
}

func TestSaveFileWritesOperationalGuidance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rule.yaml")
	rule := craftedsignal.Detection{
		Title:               "Suspicious PowerShell",
		Platform:            "sentinel",
		Query:               "SecurityEvent",
		Enabled:             true,
		OperationalGuidance: "# Response\n\n1. Validate the process tree.\n",
	}

	if err := SaveFile(rule, path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "operational_guidance: |") {
		t.Fatalf("saved YAML does not contain literal operational_guidance:\n%s", data)
	}

	loaded, err := LoadFile(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded[0].Rule.OperationalGuidance; got != rule.OperationalGuidance {
		t.Fatalf("OperationalGuidance = %q, want %q", got, rule.OperationalGuidance)
	}
}

func TestComputeHashIncludesOperationalGuidance(t *testing.T) {
	base := craftedsignal.Detection{
		Title:    "Suspicious PowerShell",
		Platform: "sentinel",
		Query:    "SecurityEvent",
		Enabled:  true,
	}
	withGuidance := base
	withGuidance.OperationalGuidance = "# Response\n\nValidate the process tree.\n"

	baseHash, err := ComputeHash(base)
	if err != nil {
		t.Fatal(err)
	}
	guidanceHash, err := ComputeHash(withGuidance)
	if err != nil {
		t.Fatal(err)
	}
	if baseHash == guidanceHash {
		t.Fatal("hash did not change when operational guidance changed")
	}
}

func TestComputeHashNormalizesOperationalGuidance(t *testing.T) {
	base := craftedsignal.Detection{
		Title:    "Suspicious PowerShell",
		Platform: "sentinel",
		Query:    "SecurityEvent",
		Enabled:  true,
	}
	plain := base
	plain.OperationalGuidance = "Validate alert context"
	normalized := base
	normalized.OperationalGuidance = "Validate alert context\n"

	plainHash, err := ComputeHash(plain)
	if err != nil {
		t.Fatal(err)
	}
	normalizedHash, err := ComputeHash(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if plainHash != normalizedHash {
		t.Fatal("hash changed for equivalent normalized operational guidance")
	}
}
