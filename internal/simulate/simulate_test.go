package simulate

import (
	"context"
	"testing"
	"time"
)

// stubAdapter is a minimal BASAdapter for testing.
type stubAdapter struct {
	name       string
	kind       AdapterKind
	available  bool
	techniques []Technique
}

func (s *stubAdapter) Name() string      { return s.name }
func (s *stubAdapter) Kind() AdapterKind { return s.kind }
func (s *stubAdapter) Available() bool    { return s.available }

func (s *stubAdapter) List(f Filter) ([]Technique, error) {
	var out []Technique
	for _, t := range s.techniques {
		if f.TechniqueID != "" && t.ID != f.TechniqueID {
			continue
		}
		if f.Platform != "" {
			found := false
			for _, p := range t.Platforms {
				if p == f.Platform {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		out = append(out, t)
	}
	return out, nil
}

func (s *stubAdapter) Plan(techniqueID string) (*ExecutionPlan, error) {
	return &ExecutionPlan{
		TechniqueID:    techniqueID,
		AdapterName:    s.name,
		ExecMode:       Local,
		CommandPreview: "echo test",
	}, nil
}

func (s *stubAdapter) Execute(_ context.Context, plan *ExecutionPlan) (*ExecutionResult, error) {
	return &ExecutionResult{
		Success:   true,
		StartTime: time.Now(),
		EndTime:   time.Now(),
		ExitCode:  0,
	}, nil
}

func (s *stubAdapter) Cleanup(_ context.Context, _ *ExecutionPlan) error { return nil }

// --- Type tests ---

func TestAdapterKindString(t *testing.T) {
	tests := []struct {
		kind AdapterKind
		want string
	}{
		{Framework, "framework"},
		{Tool, "tool"},
		{AdapterKind(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("AdapterKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestExecModeString(t *testing.T) {
	tests := []struct {
		mode ExecMode
		want string
	}{
		{Local, "local"},
		{RemoteSSH, "remote-ssh"},
		{RemoteWinRM, "remote-winrm"},
		{CloudAPI, "api"},
		{ExecMode(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("ExecMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

// --- Registry tests ---

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	a := &stubAdapter{name: "stratus", kind: Framework, available: true}

	if err := reg.Register(a); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := reg.Get("stratus")
	if got == nil {
		t.Fatal("Get returned nil for registered adapter")
	}
	if got.Name() != "stratus" {
		t.Errorf("Name = %q, want %q", got.Name(), "stratus")
	}
}

func TestRegistryDuplicateRegister(t *testing.T) {
	reg := NewRegistry()
	a := &stubAdapter{name: "atomic"}
	if err := reg.Register(a); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := reg.Register(a); err == nil {
		t.Fatal("expected error on duplicate Register, got nil")
	}
}

func TestRegistryGetMissing(t *testing.T) {
	reg := NewRegistry()
	if got := reg.Get("nonexistent"); got != nil {
		t.Errorf("Get(nonexistent) = %v, want nil", got)
	}
}

func TestRegistryAll(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&stubAdapter{name: "a"})
	_ = reg.Register(&stubAdapter{name: "b"})
	_ = reg.Register(&stubAdapter{name: "c"})

	all := reg.All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d adapters, want 3", len(all))
	}
}

func TestRegistryForTechnique(t *testing.T) {
	reg := NewRegistry()

	stratus := &stubAdapter{
		name: "stratus",
		techniques: []Technique{
			{ID: "stratus.aws.credential-access.get-secret-value"},
			{ID: "stratus.aws.defense-evasion.stop-cloudtrail"},
		},
	}
	atomic := &stubAdapter{
		name: "atomic",
		techniques: []Technique{
			{ID: "T1003.001"},
			{ID: "T1059.001"},
		},
	}
	_ = reg.Register(stratus)
	_ = reg.Register(atomic)

	// Should find stratus only
	found := reg.ForTechnique("stratus.aws.credential-access.get-secret-value")
	if len(found) != 1 || found[0].Name() != "stratus" {
		t.Errorf("ForTechnique returned %v, want [stratus]", names(found))
	}

	// Should find atomic only
	found = reg.ForTechnique("T1003.001")
	if len(found) != 1 || found[0].Name() != "atomic" {
		t.Errorf("ForTechnique returned %v, want [atomic]", names(found))
	}

	// No match
	found = reg.ForTechnique("nonexistent")
	if len(found) != 0 {
		t.Errorf("ForTechnique(nonexistent) returned %v, want empty", names(found))
	}
}

func TestStubAdapterPlanAndExecute(t *testing.T) {
	a := &stubAdapter{name: "test", available: true}
	plan, err := a.Plan("T1003.001")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.TechniqueID != "T1003.001" {
		t.Errorf("plan.TechniqueID = %q, want %q", plan.TechniqueID, "T1003.001")
	}

	result, err := a.Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
}

func names(adapters []BASAdapter) []string {
	out := make([]string, len(adapters))
	for i, a := range adapters {
		out[i] = a.Name()
	}
	return out
}
