package adapters

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
func (e *embeddedAdapter) Kind() simulate.AdapterKind { return simulate.Framework }
func (e *embeddedAdapter) Available() bool            { return true }

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
	result.Status, result.BlockEvidence = executionStatus(ctx, execErr)
	return result, nil
}

// executionStatus derives an embedded technique's status from the error it
// returned: a *simulate.BlockedError carries its own evidence, and any other
// failure is classified like an external command's.
func executionStatus(ctx context.Context, execErr error) (simulate.ExecutionStatus, string) {
	if execErr == nil {
		return simulate.StatusExecuted, ""
	}
	var blocked *simulate.BlockedError
	if errors.As(execErr, &blocked) {
		return simulate.StatusBlocked, blocked.Evidence
	}
	return simulate.Classify(ctx, execErr, "", "")
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

// t1105URL serves the EICAR test file over HTTPS. Tests point it at a local server.
var t1105URL = "https://secure.eicar.org/eicar.com.txt"

// t1105QuarantineWait is how long T1105 waits before checking whether an
// antivirus removed the downloaded file.
var t1105QuarantineWait = 3 * time.Second

// t1105Proxy picks the proxy for T1105's download. Tests replace it, because
// http.ProxyFromEnvironment reads the environment only once per process.
var t1105Proxy = http.ProxyFromEnvironment

// t1105Client downloads through the configured proxy. A proxy that refuses
// the HTTPS tunnel is a block, but Go returns that refusal as a transport
// error, so the response status check never sees it.
func t1105Client() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = t1105Proxy
	transport.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
		if refusedByProxy(res.StatusCode) {
			return &simulate.BlockedError{Evidence: fmt.Sprintf("proxy refused the download tunnel with HTTP %d", res.StatusCode)}
		}
		return nil
	}
	return &http.Client{Transport: transport}
}

func t1105Path() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("csctl-t1105-%d", time.Now().Unix()))
}

func executeT1105(ctx context.Context, plan *simulate.ExecutionPlan, stdout *bytes.Buffer) error {
	dest := t1105Path()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t1105URL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "csctl-simulation/1.0")

	resp, err := t1105Client().Do(req)
	if err != nil {
		var blocked *simulate.BlockedError
		if errors.As(err, &blocked) {
			return blocked
		}
		if downloadCut(err) {
			return &simulate.BlockedError{Evidence: "download connection was reset"}
		}
		return fmt.Errorf("downloading test file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if refusedByProxy(resp.StatusCode) {
			return &simulate.BlockedError{Evidence: fmt.Sprintf("download refused with HTTP %d", resp.StatusCode)}
		}
		return fmt.Errorf("downloading test file: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	n, err := io.Copy(f, resp.Body)
	if closeErr := f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		if downloadCut(err) {
			return &simulate.BlockedError{Evidence: "download connection was reset"}
		}
		return fmt.Errorf("writing downloaded content: %w", err)
	}

	plan.Target = dest
	fmt.Fprintf(stdout, "Source: %s\n", t1105URL)
	fmt.Fprintf(stdout, "Wrote EICAR test payload (%d bytes) → %s\n", n, dest)
	if quarantined(ctx, dest, t1105QuarantineWait) {
		return &simulate.BlockedError{Evidence: "downloaded file was removed right after writing"}
	}
	return nil
}

// refusedByProxy reports HTTP statuses a filtering proxy returns when it
// refuses a download. 407 (proxy authentication required) is left out:
// a real implant reuses the signed-in user's proxy credentials, so csctl
// failing to authenticate says nothing about whether a control would stop
// the download.
func refusedByProxy(code int) bool {
	return code == http.StatusForbidden || code == http.StatusUnavailableForLegalReasons
}

// downloadCut reports transport errors that mean something cut an
// established download, as an inline antivirus or proxy does. An unreachable
// network is not a block.
func downloadCut(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "forcibly closed")
}

// quarantined waits, then reports whether the file at path disappeared.
func quarantined(ctx context.Context, path string, wait time.Duration) bool {
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return false
		}
	}
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
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
