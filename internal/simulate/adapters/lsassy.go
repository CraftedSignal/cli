package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/craftedsignal/cli/internal/simulate"
)

// lsassyAdapter integrates with lsassy for remote LSASS credential dumping.
type lsassyAdapter struct{}

var lsassyTechniques = []simulate.Technique{
	{ID: "T1003.001", Name: "Remote LSASS Dump via SMB", Platforms: []simulate.Platform{simulate.Linux, simulate.MacOS, simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
}

func NewLsassy() simulate.BASAdapter {
	return &lsassyAdapter{}
}

func (l *lsassyAdapter) Name() string               { return "lsassy" }
func (l *lsassyAdapter) Kind() simulate.AdapterKind  { return simulate.Tool }

func (l *lsassyAdapter) Available() bool {
	_, err := exec.LookPath("lsassy")
	return err == nil
}

func (l *lsassyAdapter) List(filter simulate.Filter) ([]simulate.Technique, error) {
	var out []simulate.Technique
	for _, t := range lsassyTechniques {
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

func (l *lsassyAdapter) Plan(techniqueID string) (*simulate.ExecutionPlan, error) {
	if techniqueID != "T1003.001" {
		return nil, fmt.Errorf("technique %s not supported by lsassy adapter", techniqueID)
	}

	return &simulate.ExecutionPlan{
		TechniqueID:    techniqueID,
		AdapterName:    l.Name(),
		ExecMode:       simulate.Local,
		CommandPreview: "lsassy -d <domain> -u <user> -p <pass> <target>",
		EstimatedLogs:  []string{"Security", "Sysmon"},
		Observables: []simulate.Observable{
			{Field: "Image", Value: "*lsassy*"},
			{Field: "TargetImage", Value: "*lsass.exe"},
			{Field: "GrantedAccess", Value: "0x1010"},
		},
	}, nil
}

func (l *lsassyAdapter) Execute(ctx context.Context, plan *simulate.ExecutionPlan) (*simulate.ExecutionResult, error) {
	if plan.Target == "" {
		return nil, fmt.Errorf("lsassy requires a target host in the execution plan")
	}

	start := time.Now()

	// Build the lsassy command. Target is required; domain/user/pass come from
	// the plan's Target field which should be in the format expected by the caller.
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "lsassy", plan.Target)
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

func (l *lsassyAdapter) Cleanup(_ context.Context, _ *simulate.ExecutionPlan) error {
	// lsassy does not leave persistent artifacts that need cleanup.
	return nil
}
