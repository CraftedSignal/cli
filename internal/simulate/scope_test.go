package simulate

import (
	"os"
	"path/filepath"
	"testing"
)

const validScopeYAML = `
scope:
  allow_all: false
  adapters: [stratus, atomic, mimikatz]
  techniques:
    - T1003.001
    - T1059.001
    - T1558.003
  targets:
    - host: win-lab-01
      os: windows
    - env: aws-staging
      profile: red-team-role
  constraints:
    max_concurrent: 3
    cleanup: always
    timeout: 300s

bindings:
  - technique: T1003.001
    detections: [D-0042, D-0087]
  - technique: T1059.001
    detections: [D-0101]
`

func writeTempScope(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "simulations.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadScope_Valid(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}

	if cfg.Scope.AllowAll {
		t.Error("expected allow_all to be false")
	}
	if len(cfg.Scope.Adapters) != 3 {
		t.Errorf("expected 3 adapters, got %d", len(cfg.Scope.Adapters))
	}
	if len(cfg.Scope.Techniques) != 3 {
		t.Errorf("expected 3 techniques, got %d", len(cfg.Scope.Techniques))
	}
	if len(cfg.Scope.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(cfg.Scope.Targets))
	}
	if cfg.Scope.Constraints.MaxConcurrent != 3 {
		t.Errorf("expected max_concurrent=3, got %d", cfg.Scope.Constraints.MaxConcurrent)
	}
	if cfg.Scope.Constraints.Cleanup != "always" {
		t.Errorf("expected cleanup=always, got %s", cfg.Scope.Constraints.Cleanup)
	}
	if cfg.Scope.Constraints.Timeout.Seconds() != 300 {
		t.Errorf("expected timeout=300s, got %v", cfg.Scope.Constraints.Timeout)
	}
	if len(cfg.Bindings) != 2 {
		t.Errorf("expected 2 bindings, got %d", len(cfg.Bindings))
	}
}

func TestLoadScope_NonexistentFile(t *testing.T) {
	_, err := LoadScope("/tmp/nonexistent-scope-file-12345.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadScope_EmptyFile(t *testing.T) {
	path := writeTempScope(t, "")
	cfg, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope on empty file: %v", err)
	}
	// Default zero values should be safe to use.
	if cfg.Scope.AllowAll {
		t.Error("expected allow_all to default to false")
	}
	if len(cfg.Scope.Adapters) != 0 {
		t.Error("expected no adapters")
	}
}

func TestLoadScope_MinimalAllowAll(t *testing.T) {
	path := writeTempScope(t, `
scope:
  allow_all: true
`)
	cfg, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if !cfg.Scope.AllowAll {
		t.Error("expected allow_all to be true")
	}
}

func TestIsAllowed_AllowAll(t *testing.T) {
	cfg := &ScopeConfig{Scope: Scope{AllowAll: true}}
	if !cfg.IsAllowed("T9999.999", "unknown-adapter") {
		t.Error("allow_all=true should permit any combo")
	}
}

func TestIsAllowed_AllowedCombo(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, _ := LoadScope(path)

	if !cfg.IsAllowed("T1003.001", "stratus") {
		t.Error("T1003.001 + stratus should be allowed")
	}
	if !cfg.IsAllowed("T1059.001", "atomic") {
		t.Error("T1059.001 + atomic should be allowed")
	}
}

func TestIsAllowed_DisallowedTechnique(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, _ := LoadScope(path)

	if cfg.IsAllowed("T9999.999", "stratus") {
		t.Error("unlisted technique should be denied")
	}
}

func TestIsAllowed_DisallowedAdapter(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, _ := LoadScope(path)

	if cfg.IsAllowed("T1003.001", "unknown-adapter") {
		t.Error("unlisted adapter should be denied")
	}
}

func TestIsAllowed_EmptyLists(t *testing.T) {
	cfg := &ScopeConfig{Scope: Scope{AllowAll: false}}
	// Empty adapters and techniques lists should allow anything (no restriction).
	if !cfg.IsAllowed("T1003.001", "stratus") {
		t.Error("empty lists should allow any combo when allow_all=false")
	}
}

func TestGetBindings(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, _ := LoadScope(path)

	bindings := cfg.GetBindings("T1003.001")
	if len(bindings) != 2 {
		t.Fatalf("expected 2 detections for T1003.001, got %d", len(bindings))
	}
	if bindings[0] != "D-0042" || bindings[1] != "D-0087" {
		t.Errorf("unexpected bindings: %v", bindings)
	}
}

func TestGetBindings_NoMatch(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, _ := LoadScope(path)

	if cfg.GetBindings("T9999.999") != nil {
		t.Error("expected nil for unbound technique")
	}
}

func TestGetTarget_ByHost(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, _ := LoadScope(path)

	target := cfg.GetTarget("win-lab-01")
	if target == nil {
		t.Fatal("expected to find target win-lab-01")
	}
	if target.OS != "windows" {
		t.Errorf("expected os=windows, got %s", target.OS)
	}
}

func TestGetTarget_ByEnv(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, _ := LoadScope(path)

	target := cfg.GetTarget("aws-staging")
	if target == nil {
		t.Fatal("expected to find target aws-staging")
	}
	if target.Profile != "red-team-role" {
		t.Errorf("expected profile=red-team-role, got %s", target.Profile)
	}
}

func TestGetTarget_NotFound(t *testing.T) {
	path := writeTempScope(t, validScopeYAML)
	cfg, _ := LoadScope(path)

	if cfg.GetTarget("nonexistent") != nil {
		t.Error("expected nil for unknown target")
	}
}
