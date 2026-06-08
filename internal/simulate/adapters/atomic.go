package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/craftedsignal/cli/internal/simulate"
)

// atomicAdapter runs official Atomic Red Team tests via an in-repo runner. Test
// definitions come from an embedded vendored subset, or a full local clone when
// CSCTL_ATOMICS_PATH is set (see atomic_loader.go).
type atomicAdapter struct{}

// atomicTechniques is the catalog the adapter advertises. A technique is only
// surfaced by List when its atomic file has a test runnable on the current host.
var atomicTechniques = []simulate.Technique{
	{ID: "T1003.001", Name: "LSASS Memory Dump", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1003.003", Name: "NTDS.dit Copy", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1059.001", Name: "PowerShell Execution", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1059.003", Name: "Windows Command Shell", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1053.005", Name: "Scheduled Task", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1547.001", Name: "Registry Run Keys / Startup Folder", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1562.001", Name: "Disable or Modify Security Tools", Platforms: []simulate.Platform{simulate.Windows, simulate.Linux}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1070.001", Name: "Clear Windows Event Logs", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1105", Name: "Ingress Tool Transfer", Platforms: []simulate.Platform{simulate.Windows, simulate.Linux, simulate.MacOS}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1078.004", Name: "Cloud Accounts", Platforms: []simulate.Platform{simulate.AWS, simulate.Azure, simulate.GCP}, ExecModes: []simulate.ExecMode{simulate.CloudAPI}},
	{ID: "T1136.001", Name: "Create Local Account", Platforms: []simulate.Platform{simulate.Windows, simulate.Linux, simulate.MacOS}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1218.011", Name: "Rundll32 Execution", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
}

// atomicObservables holds the detection-field hints per technique. The atomic
// YAML carries no observables, so these stay curated alongside the catalog.
var atomicObservables = map[string][]simulate.Observable{
	"T1003.001": {{Field: "TargetImage", Value: "*lsass.exe"}, {Field: "GrantedAccess", Value: "0x1010"}},
	"T1003.003": {{Field: "CommandLine", Value: "*ntdsutil*"}, {Field: "TargetFilename", Value: "*ntds.dit*"}},
	"T1059.001": {{Field: "Image", Value: "*powershell.exe"}, {Field: "CommandLine", Value: "*powershell*"}},
	"T1059.003": {{Field: "Image", Value: "*cmd.exe"}, {Field: "CommandLine", Value: "*cmd*"}},
	"T1053.005": {{Field: "Image", Value: "*schtasks.exe"}, {Field: "CommandLine", Value: "*schtasks*/create*"}},
	"T1547.001": {{Field: "TargetObject", Value: `*\CurrentVersion\Run*`}},
	"T1562.001": {{Field: "CommandLine", Value: "*Set-MpPreference*DisableRealtimeMonitoring*"}},
	"T1070.001": {{Field: "Image", Value: "*wevtutil.exe"}, {Field: "CommandLine", Value: "*wevtutil*cl*"}},
	"T1105":     {{Field: "CommandLine", Value: "*certutil*urlcache*"}},
	"T1078.004": {{Field: "EventID", Value: "ConsoleLogin"}},
	"T1136.001": {{Field: "CommandLine", Value: "*net*user*/add*"}, {Field: "TargetUserName", Value: "*"}, {Field: "EventID", Value: "4720"}},
	"T1218.011": {{Field: "Image", Value: "*rundll32.exe"}, {Field: "CommandLine", Value: "*rundll32*"}},
}

func NewAtomic() simulate.BASAdapter {
	return &atomicAdapter{}
}

func (a *atomicAdapter) Name() string               { return "atomic" }
func (a *atomicAdapter) Kind() simulate.AdapterKind { return simulate.Framework }

// Available reports whether the atomic runner is wired up. The embedded atomics
// are always present; per-technique and per-OS runnability is enforced in List
// and Plan, so this is true whenever the adapter is registered.
func (a *atomicAdapter) Available() bool { return true }

// List returns the catalog techniques, filtered to those whose atomic file has a
// test that can actually run on this host. This keeps "no adapters found" honest:
// a Windows-only technique simply isn't listed on a non-Windows runner.
func (a *atomicAdapter) List(filter simulate.Filter) ([]simulate.Technique, error) {
	var out []simulate.Technique
	for _, t := range atomicTechniques {
		if filter.TechniqueID != "" && t.ID != filter.TechniqueID {
			continue
		}
		if filter.Platform != "" && !containsPlatform(t.Platforms, filter.Platform) {
			continue
		}
		af, err := loadAtomicFile(t.ID)
		if err != nil {
			continue // no vendored/override atomic for this technique
		}
		if pickRunnableTest(af) == nil {
			continue // nothing runnable on this host/OS
		}
		out = append(out, t)
	}
	return out, nil
}

func (a *atomicAdapter) Plan(techniqueID string) (*simulate.ExecutionPlan, error) {
	af, err := loadAtomicFile(techniqueID)
	if err != nil {
		return nil, fmt.Errorf("no atomic test bundled for %s: %w", techniqueID, err)
	}
	test := pickRunnableTest(af)
	if test == nil {
		return nil, fmt.Errorf("technique %s has no atomic test runnable on %s", techniqueID, runtime.GOOS)
	}

	command := substituteAtomicArgs(test.Executor.Command, test.InputArguments)

	execMode := simulate.Local
	for _, t := range atomicTechniques {
		if t.ID == techniqueID && len(t.ExecModes) > 0 {
			execMode = t.ExecModes[0]
			break
		}
	}

	return &simulate.ExecutionPlan{
		TechniqueID:    techniqueID,
		AdapterName:    a.Name(),
		ExecMode:       execMode,
		CommandPreview: firstLine(command),
		Observables:    atomicObservables[techniqueID],
	}, nil
}

func (a *atomicAdapter) Execute(ctx context.Context, plan *simulate.ExecutionPlan) (*simulate.ExecutionResult, error) {
	af, err := loadAtomicFile(plan.TechniqueID)
	if err != nil {
		return nil, fmt.Errorf("no atomic test bundled for %s: %w", plan.TechniqueID, err)
	}
	test := pickRunnableTest(af)
	if test == nil {
		return nil, fmt.Errorf("technique %s has no atomic test runnable on %s", plan.TechniqueID, runtime.GOOS)
	}
	if test.Executor.ElevationRequired && !isElevated() {
		return nil, fmt.Errorf("atomic test for %s requires elevation (run with sudo / as Administrator)", plan.TechniqueID)
	}

	command := substituteAtomicArgs(test.Executor.Command, test.InputArguments)

	start := time.Now()
	var stdout, stderr bytes.Buffer
	cmd := atomicCommand(ctx, test.Executor.Name, command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result := &simulate.ExecutionResult{
		Success:   runErr == nil,
		StartTime: start,
		EndTime:   time.Now(),
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
	}
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	} else if runErr != nil {
		result.ExitCode = -1
	}
	return result, nil
}

func (a *atomicAdapter) Cleanup(ctx context.Context, plan *simulate.ExecutionPlan) error {
	af, err := loadAtomicFile(plan.TechniqueID)
	if err != nil {
		return err
	}
	test := pickRunnableTest(af)
	if test == nil || strings.TrimSpace(test.Executor.CleanupCommand) == "" {
		return nil // nothing to undo
	}
	command := substituteAtomicArgs(test.Executor.CleanupCommand, test.InputArguments)
	return atomicCommand(ctx, test.Executor.Name, command).Run()
}

// atomicCommand builds the exec.Cmd for an atomic executor.
func atomicCommand(ctx context.Context, executor, command string) *exec.Cmd {
	switch executor {
	case "command_prompt":
		return exec.CommandContext(ctx, "cmd", "/c", command)
	case "powershell":
		bin := "powershell"
		if _, err := exec.LookPath("pwsh"); err == nil {
			bin = "pwsh"
		}
		return exec.CommandContext(ctx, bin, "-NoProfile", "-Command", command)
	default: // sh, bash
		return exec.CommandContext(ctx, "sh", "-c", command)
	}
}

// isElevated is a best-effort privilege check. On Windows we assume the caller
// has the rights they claim (a proper token check isn't worth the dependency).
func isElevated() bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return os.Geteuid() == 0
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
