package adapters

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/craftedsignal/cli/internal/simulate"
)

func TestLoadAtomicFile_Embedded(t *testing.T) {
	af, err := loadAtomicFile("T1547.001")
	if err != nil {
		t.Fatalf("loadAtomicFile: %v", err)
	}
	if af.AttackTechnique != "T1547.001" {
		t.Errorf("attack_technique = %q, want T1547.001", af.AttackTechnique)
	}
	if len(af.AtomicTests) == 0 {
		t.Error("expected at least one atomic test")
	}
}

func TestPickRunnableTest_OSAware(t *testing.T) {
	af, err := loadAtomicFile("T1003.001") // windows-only in the subset
	if err != nil {
		t.Fatalf("loadAtomicFile: %v", err)
	}
	got := pickRunnableTest(af)
	if runtime.GOOS == "windows" {
		if got == nil {
			t.Error("expected a runnable test on windows")
		}
	} else if got != nil {
		t.Errorf("windows-only technique should not be runnable on %s", runtime.GOOS)
	}
}

func TestList_ExcludesUnrunnable(t *testing.T) {
	a := &atomicAdapter{}
	techs, err := a.List(simulate.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, tech := range techs {
		af, err := loadAtomicFile(tech.ID)
		if err != nil {
			t.Errorf("listed technique %s has no loadable atomic: %v", tech.ID, err)
			continue
		}
		if pickRunnableTest(af) == nil {
			t.Errorf("listed technique %s has no runnable test on this host", tech.ID)
		}
	}
	if runtime.GOOS != "windows" {
		for _, tech := range techs {
			if tech.ID == "T1003.001" {
				t.Error("windows-only T1003.001 should not be listed on non-windows host")
			}
		}
	}
}

func TestSubstituteAtomicArgs(t *testing.T) {
	got := substituteAtomicArgs("a #{x} b #{x}", map[string]atomicArg{"x": {Default: "Z"}})
	if got != "a Z b Z" {
		t.Errorf("substituteAtomicArgs = %q, want %q", got, "a Z b Z")
	}
}

// TestExecute_OverridePath drives the full load→plan→execute→cleanup pipeline
// against a temp atomics clone, exercising CSCTL_ATOMICS_PATH without touching
// the real (privileged / networked) embedded atomics.
func TestExecute_OverridePath(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "atomics", "T9999")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const yaml = `attack_technique: T9999
display_name: Test
atomic_tests:
- name: unix echo
  supported_platforms: [linux, macos]
  executor:
    name: sh
    command: echo atomic_marker_#{tag}
    cleanup_command: 'true'
  input_arguments:
    tag:
      default: ok
- name: windows echo
  supported_platforms: [windows]
  executor:
    name: command_prompt
    command: echo atomic_marker_#{tag}
  input_arguments:
    tag:
      default: ok
`
	if err := os.WriteFile(filepath.Join(dir, "T9999.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSCTL_ATOMICS_PATH", base)

	a := &atomicAdapter{}
	plan, err := a.Plan("T9999")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !strings.Contains(plan.CommandPreview, "atomic_marker_ok") {
		t.Errorf("CommandPreview = %q, want substituted marker", plan.CommandPreview)
	}

	res, err := a.Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Errorf("Execute not successful: stderr=%q exit=%d", res.Stderr, res.ExitCode)
	}
	// command_prompt echo on Windows prints the literal text; sh echo on unix too.
	if !strings.Contains(res.Stdout, "atomic_marker_ok") {
		t.Errorf("stdout = %q, want marker", res.Stdout)
	}

	if err := a.Cleanup(context.Background(), plan); err != nil {
		t.Errorf("Cleanup: %v", err)
	}
}
