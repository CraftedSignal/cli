package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/craftedsignal/cli/internal/simulate"
)

// atomicAdapter integrates with the atomic-go-team binary.
type atomicAdapter struct{}

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

func NewAtomic() simulate.BASAdapter {
	return &atomicAdapter{}
}

func (a *atomicAdapter) Name() string          { return "atomic" }
func (a *atomicAdapter) Kind() simulate.AdapterKind { return simulate.Framework }

func (a *atomicAdapter) Available() bool {
	_, err := exec.LookPath("atomic-go-team")
	return err == nil
}

func (a *atomicAdapter) List(filter simulate.Filter) ([]simulate.Technique, error) {
	var out []simulate.Technique
	for _, t := range atomicTechniques {
		if filter.TechniqueID != "" && t.ID != filter.TechniqueID {
			continue
		}
		if filter.Platform != "" && !containsPlatform(t.Platforms, filter.Platform) {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func (a *atomicAdapter) Plan(techniqueID string) (*simulate.ExecutionPlan, error) {
	for _, t := range atomicTechniques {
		if t.ID == techniqueID {
			return &simulate.ExecutionPlan{
				TechniqueID:    techniqueID,
				AdapterName:    a.Name(),
				ExecMode:       t.ExecModes[0],
				CommandPreview: fmt.Sprintf("atomic-go-team run %s", techniqueID),
			}, nil
		}
	}
	return nil, fmt.Errorf("technique %s not found in atomic catalog", techniqueID)
}

func (a *atomicAdapter) Execute(ctx context.Context, plan *simulate.ExecutionPlan) (*simulate.ExecutionResult, error) {
	start := time.Now()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "atomic-go-team", "run", plan.TechniqueID)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &simulate.ExecutionResult{
		Success:   err == nil,
		StartTime: start,
		EndTime:   time.Now(),
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	} else if err != nil {
		result.ExitCode = -1
	}
	return result, nil
}

func (a *atomicAdapter) Cleanup(ctx context.Context, plan *simulate.ExecutionPlan) error {
	cmd := exec.CommandContext(ctx, "atomic-go-team", "cleanup", plan.TechniqueID)
	return cmd.Run()
}

// containsPlatform checks whether a slice contains the given platform.
func containsPlatform(platforms []simulate.Platform, p simulate.Platform) bool {
	for _, pl := range platforms {
		if pl == p {
			return true
		}
	}
	return false
}

// containsExecMode checks whether a slice contains the given exec mode.
func containsExecMode(modes []simulate.ExecMode, m simulate.ExecMode) bool {
	for _, mode := range modes {
		if mode == m {
			return true
		}
	}
	return false
}

// splitCommand is a helper to split a command preview into binary and args.
func splitCommand(preview string) (string, []string) {
	parts := strings.Fields(preview)
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}
