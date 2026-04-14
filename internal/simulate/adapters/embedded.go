package adapters

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/craftedsignal/cli/internal/simulate"
)

// embeddedAdapter implements BAS techniques natively in Go with zero external dependencies.
type embeddedAdapter struct{}

var embeddedTechniques = []simulate.Technique{
	{ID: "T1105", Name: "Ingress Tool Transfer", Platforms: []simulate.Platform{simulate.Windows, simulate.Linux, simulate.MacOS}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1136.001", Name: "Create Local Account", Platforms: []simulate.Platform{simulate.Linux, simulate.MacOS}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1059.004", Name: "Unix Shell Execution", Platforms: []simulate.Platform{simulate.Linux, simulate.MacOS}, ExecModes: []simulate.ExecMode{simulate.Local}},
	{ID: "T1070.004", Name: "File Deletion", Platforms: []simulate.Platform{simulate.Windows, simulate.Linux, simulate.MacOS}, ExecModes: []simulate.ExecMode{simulate.Local}},
}

func NewEmbedded() simulate.BASAdapter {
	return &embeddedAdapter{}
}

func (e *embeddedAdapter) Name() string               { return "embedded" }
func (e *embeddedAdapter) Kind() simulate.AdapterKind  { return simulate.Framework }
func (e *embeddedAdapter) Available() bool             { return true }

func (e *embeddedAdapter) List(filter simulate.Filter) ([]simulate.Technique, error) {
	var out []simulate.Technique
	for _, t := range embeddedTechniques {
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

func (e *embeddedAdapter) Plan(techniqueID string) (*simulate.ExecutionPlan, error) {
	for _, t := range embeddedTechniques {
		if t.ID != techniqueID {
			continue
		}
		plan := &simulate.ExecutionPlan{
			TechniqueID: techniqueID,
			AdapterName: e.Name(),
			ExecMode:    t.ExecModes[0],
		}
		switch techniqueID {
		case "T1105":
			plan.CommandPreview = "Download EICAR test payload via HTTPS → temp file (triggers AV/EDR)"
			plan.EstimatedLogs = []string{"proxy", "endpoint"}
			plan.Observables = []simulate.Observable{
				{Field: "TargetFilename", Value: "*csctl-t1105*"},
				{Field: "DestinationHostname", Value: "*eicar.org*"},
			}
		case "T1136.001":
			if runtime.GOOS == "darwin" {
				plan.CommandPreview = "dscl . -create /Users/csctl_test_user (requires root)"
				plan.Observables = []simulate.Observable{
					{Field: "CommandLine", Value: "*dscl*create*/Users/csctl_test_user*"},
					{Field: "TargetUserName", Value: "csctl_test_user"},
				}
			} else {
				plan.CommandPreview = "useradd csctl_test_user (requires root)"
				plan.Observables = []simulate.Observable{
					{Field: "CommandLine", Value: "*useradd*csctl_test_user*"},
					{Field: "TargetUserName", Value: "csctl_test_user"},
				}
			}
			plan.EstimatedLogs = []string{"auth", "endpoint"}
		case "T1059.004":
			plan.CommandPreview = "sh -c 'echo csctl_simulation_marker_$(date +%s)'"
			plan.EstimatedLogs = []string{"endpoint", "process"}
			plan.Observables = []simulate.Observable{
				{Field: "Image", Value: "*sh"},
				{Field: "CommandLine", Value: "*csctl_simulation_marker*"},
			}
		case "T1070.004":
			plan.CommandPreview = "create temp file with marker content, then delete it"
			plan.EstimatedLogs = []string{"endpoint"}
			plan.Observables = []simulate.Observable{
				{Field: "TargetFilename", Value: "*csctl-t1070*"},
			}
		}
		return plan, nil
	}
	return nil, fmt.Errorf("technique %s not found in embedded catalog", techniqueID)
}

func (e *embeddedAdapter) Execute(ctx context.Context, plan *simulate.ExecutionPlan) (*simulate.ExecutionResult, error) {
	start := time.Now()
	var stdout bytes.Buffer

	var execErr error
	switch plan.TechniqueID {
	case "T1105":
		execErr = executeT1105(ctx, plan, &stdout)
	case "T1136.001":
		execErr = executeT1136001(ctx, &stdout)
	case "T1059.004":
		execErr = executeT1059004(ctx, &stdout)
	case "T1070.004":
		execErr = executeT1070004(&stdout)
	default:
		return nil, fmt.Errorf("technique %s not implemented in embedded adapter", plan.TechniqueID)
	}

	result := &simulate.ExecutionResult{
		Success:   execErr == nil,
		StartTime: start,
		EndTime:   time.Now(),
		Stdout:    stdout.String(),
	}
	if execErr != nil {
		result.Stderr = execErr.Error()
		result.ExitCode = 1
	}
	return result, nil
}

func (e *embeddedAdapter) Cleanup(ctx context.Context, plan *simulate.ExecutionPlan) error {
	switch plan.TechniqueID {
	case "T1105":
		return cleanupT1105(plan)
	case "T1136.001":
		return cleanupT1136001(ctx)
	case "T1059.004", "T1070.004":
		return nil // no-op
	default:
		return fmt.Errorf("technique %s not implemented in embedded adapter", plan.TechniqueID)
	}
}

// --- T1105: Ingress Tool Transfer ---

// EICAR test string — the standard antivirus test file.
// It is NOT malicious but triggers AV/EDR detections by design.
// See https://www.eicar.org/download-anti-malware-testfile/
const eicarTestString = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// t1105URL serves the EICAR test file over HTTPS. This is the official
// distribution endpoint from eicar.org for testing HTTP-based file transfers.
const t1105URL = "https://secure.eicar.org/eicar.com.txt"

func t1105Path() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("csctl-t1105-%d", time.Now().Unix()))
}

func executeT1105(ctx context.Context, plan *simulate.ExecutionPlan, stdout *bytes.Buffer) error {
	dest := t1105Path()

	// Try to download the EICAR test file from the official source.
	// If the download is blocked (by proxy/AV), fall back to writing the
	// EICAR string directly — the file-write itself is the simulation event.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t1105URL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "csctl-simulation/1.0")

	var n int64
	var source string
	resp, err := http.DefaultClient.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		f, fErr := os.Create(dest)
		if fErr != nil {
			return fmt.Errorf("creating temp file: %w", fErr)
		}
		n, err = io.Copy(f, resp.Body)
		if err2 := f.Close(); err2 != nil && err == nil {
			err = err2
		}
		if err != nil {
			return fmt.Errorf("writing downloaded content: %w", err)
		}
		source = t1105URL
	} else {
		// Fallback: write EICAR string directly
		if resp != nil {
			_ = resp.Body.Close()
		}
		if wErr := os.WriteFile(dest, []byte(eicarTestString), 0644); wErr != nil {
			return fmt.Errorf("writing EICAR test file: %w", wErr)
		}
		n = int64(len(eicarTestString))
		source = "EICAR test string (embedded, download blocked)"
	}

	plan.Target = dest
	fmt.Fprintf(stdout, "Source: %s\n", source)
	fmt.Fprintf(stdout, "Wrote EICAR test payload (%d bytes) → %s\n", n, dest)
	return nil
}

func cleanupT1105(plan *simulate.ExecutionPlan) error {
	if plan.Target == "" {
		// Try to find the most recent file matching the pattern
		matches, _ := filepath.Glob(filepath.Join(os.TempDir(), "csctl-t1105-*"))
		if len(matches) == 0 {
			return nil
		}
		for _, m := range matches {
			_ = os.Remove(m)
		}
		return nil
	}
	return os.Remove(plan.Target)
}

// --- T1136.001: Create Local Account ---

const testUsername = "csctl_test_user"

func executeT1136001(ctx context.Context, stdout *bytes.Buffer) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("T1136.001 requires root privileges (run with sudo)")
	}

	switch runtime.GOOS {
	case "darwin":
		commands := [][]string{
			{"dscl", ".", "-create", "/Users/" + testUsername},
			{"dscl", ".", "-create", "/Users/" + testUsername, "UserShell", "/usr/bin/false"},
			{"dscl", ".", "-create", "/Users/" + testUsername, "NFSHomeDirectory", "/var/empty"},
		}
		for _, args := range commands {
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("running %v: %s: %w", args, string(out), err)
			}
		}
		fmt.Fprintf(stdout, "Created local user %s (macOS dscl)\n", testUsername)
	case "linux":
		cmd := exec.CommandContext(ctx, "useradd", "--shell", "/usr/sbin/nologin", "--no-create-home", testUsername)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("useradd: %s: %w", string(out), err)
		}
		fmt.Fprintf(stdout, "Created local user %s (useradd)\n", testUsername)
	default:
		return fmt.Errorf("T1136.001 not supported on %s", runtime.GOOS)
	}
	return nil
}

func cleanupT1136001(ctx context.Context) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.CommandContext(ctx, "dscl", ".", "-delete", "/Users/"+testUsername)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("dscl delete: %s: %w", string(out), err)
		}
	case "linux":
		cmd := exec.CommandContext(ctx, "userdel", testUsername)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("userdel: %s: %w", string(out), err)
		}
	default:
		return fmt.Errorf("T1136.001 cleanup not supported on %s", runtime.GOOS)
	}
	return nil
}

// --- T1059.004: Unix Shell Execution ---

func executeT1059004(ctx context.Context, stdout *bytes.Buffer) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", "echo csctl_simulation_marker_$(date +%s)")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("shell execution: %s: %w", string(out), err)
	}
	fmt.Fprintf(stdout, "Shell output: %s", string(out))
	return nil
}

// --- T1070.004: File Deletion ---

func executeT1070004(stdout *bytes.Buffer) error {
	path := filepath.Join(os.TempDir(), fmt.Sprintf("csctl-t1070-%d", time.Now().Unix()))

	if err := os.WriteFile(path, []byte("csctl simulation marker - file deletion test\n"), 0644); err != nil {
		return fmt.Errorf("creating marker file: %w", err)
	}
	fmt.Fprintf(stdout, "Created marker file: %s\n", path)

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("deleting marker file: %w", err)
	}
	fmt.Fprintf(stdout, "Deleted marker file: %s\n", path)
	return nil
}
