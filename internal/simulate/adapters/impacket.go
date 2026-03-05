package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/craftedsignal/cli/internal/simulate"
)

// impacketAdapter integrates with the Impacket suite of Python tools.
type impacketAdapter struct{}

var impacketTechniques = []simulate.Technique{
	{ID: "T1003.003", Name: "NTDS.dit Dump (secretsdump)", Platforms: []simulate.Platform{simulate.Linux, simulate.MacOS, simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1569.002", Name: "Service Execution (psexec)", Platforms: []simulate.Platform{simulate.Linux, simulate.MacOS, simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1047", Name: "WMI Execution (wmiexec)", Platforms: []simulate.Platform{simulate.Linux, simulate.MacOS, simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1021.002", Name: "SMB Execution (smbexec)", Platforms: []simulate.Platform{simulate.Linux, simulate.MacOS, simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
}

// impacketBinaries maps technique IDs to the corresponding impacket binary name.
var impacketBinaries = map[string]string{
	"T1003.003": "impacket-secretsdump",
	"T1569.002": "impacket-psexec",
	"T1047":     "impacket-wmiexec",
	"T1021.002": "impacket-smbexec",
}

func NewImpacket() simulate.BASAdapter {
	return &impacketAdapter{}
}

func (i *impacketAdapter) Name() string               { return "impacket" }
func (i *impacketAdapter) Kind() simulate.AdapterKind  { return simulate.Tool }

func (i *impacketAdapter) Available() bool {
	// Check for the most common impacket binary as a proxy for the suite.
	_, err := exec.LookPath("impacket-secretsdump")
	return err == nil
}

func (i *impacketAdapter) List(filter simulate.Filter) ([]simulate.Technique, error) {
	var out []simulate.Technique
	for _, t := range impacketTechniques {
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

func (i *impacketAdapter) Plan(techniqueID string) (*simulate.ExecutionPlan, error) {
	binary, ok := impacketBinaries[techniqueID]
	if !ok {
		return nil, fmt.Errorf("technique %s not supported by impacket adapter", techniqueID)
	}

	return &simulate.ExecutionPlan{
		TechniqueID:    techniqueID,
		AdapterName:    i.Name(),
		ExecMode:       simulate.Local,
		CommandPreview: fmt.Sprintf("%s <domain>/<user>:<pass>@<target>", binary),
	}, nil
}

func (i *impacketAdapter) Execute(ctx context.Context, plan *simulate.ExecutionPlan) (*simulate.ExecutionResult, error) {
	binary, ok := impacketBinaries[plan.TechniqueID]
	if !ok {
		return nil, fmt.Errorf("technique %s not supported by impacket adapter", plan.TechniqueID)
	}

	if plan.Target == "" {
		return nil, fmt.Errorf("impacket requires a target in the execution plan")
	}

	start := time.Now()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, plan.Target)
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

func (i *impacketAdapter) Cleanup(_ context.Context, _ *simulate.ExecutionPlan) error {
	// Impacket tools do not have a built-in cleanup mechanism.
	return nil
}
