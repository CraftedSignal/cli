package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
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
		if t.ID != techniqueID {
			continue
		}
		plan := &simulate.ExecutionPlan{
			TechniqueID:    techniqueID,
			AdapterName:    a.Name(),
			ExecMode:       t.ExecModes[0],
			CommandPreview: fmt.Sprintf("atomic-go-team run %s", techniqueID),
		}
		switch techniqueID {
		case "T1003.001":
			plan.Observables = []simulate.Observable{
				{Field: "TargetImage", Value: "*lsass.exe"},
				{Field: "GrantedAccess", Value: "0x1010"},
			}
		case "T1003.003":
			plan.Observables = []simulate.Observable{
				{Field: "CommandLine", Value: "*ntdsutil*"},
				{Field: "TargetFilename", Value: "*ntds.dit*"},
			}
		case "T1059.001":
			plan.Observables = []simulate.Observable{
				{Field: "Image", Value: "*powershell.exe"},
				{Field: "CommandLine", Value: "*powershell*"},
			}
		case "T1059.003":
			plan.Observables = []simulate.Observable{
				{Field: "Image", Value: "*cmd.exe"},
				{Field: "CommandLine", Value: "*cmd*"},
			}
		case "T1053.005":
			plan.Observables = []simulate.Observable{
				{Field: "Image", Value: "*schtasks.exe"},
				{Field: "CommandLine", Value: "*schtasks*/create*"},
			}
		case "T1547.001":
			plan.Observables = []simulate.Observable{
				{Field: "TargetObject", Value: `*\CurrentVersion\Run*`},
			}
		case "T1562.001":
			plan.Observables = []simulate.Observable{
				{Field: "CommandLine", Value: "*Set-MpPreference*DisableRealtimeMonitoring*"},
			}
		case "T1070.001":
			plan.Observables = []simulate.Observable{
				{Field: "Image", Value: "*wevtutil.exe"},
				{Field: "CommandLine", Value: "*wevtutil*cl*"},
			}
		case "T1105":
			plan.Observables = []simulate.Observable{
				{Field: "CommandLine", Value: "*certutil*urlcache*"},
			}
		case "T1078.004":
			plan.Observables = []simulate.Observable{
				{Field: "EventID", Value: "ConsoleLogin"},
			}
		case "T1136.001":
			plan.Observables = []simulate.Observable{
				{Field: "CommandLine", Value: "*net*user*/add*"},
				{Field: "TargetUserName", Value: "*"},
				{Field: "EventID", Value: "4720"},
			}
		case "T1218.011":
			plan.Observables = []simulate.Observable{
				{Field: "Image", Value: "*rundll32.exe"},
				{Field: "CommandLine", Value: "*rundll32*"},
			}
		}
		return plan, nil
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

