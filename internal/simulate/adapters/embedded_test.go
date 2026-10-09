package adapters

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/craftedsignal/cli/internal/simulate"
)

func useT1105Server(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	oldURL, oldWait := t1105URL, t1105QuarantineWait
	t1105URL, t1105QuarantineWait = srv.URL, 0
	t.Cleanup(func() { t1105URL, t1105QuarantineWait = oldURL, oldWait })
	t.Setenv("TMPDIR", t.TempDir())
}

func TestT1105ReportsBlockedWhenTheDownloadIsRefused(t *testing.T) {
	useT1105Server(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "blocked by policy", http.StatusForbidden)
	})
	result, err := NewEmbedded().Execute(context.Background(), &simulate.ExecutionPlan{TechniqueID: "T1105"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status != simulate.StatusBlocked || result.BlockEvidence == "" {
		t.Fatalf("Status=%q evidence=%q, want blocked with evidence", result.Status, result.BlockEvidence)
	}
	if files, _ := filepath.Glob(filepath.Join(os.TempDir(), "csctl-t1105-*")); len(files) != 0 {
		t.Fatalf("a blocked download must not write a file, found %v", files)
	}
}

func TestT1105ExecutesWhenTheDownloadSucceeds(t *testing.T) {
	// A harmless payload: writing the real EICAR string in a unit test can
	// trip the developer machine's own antivirus.
	useT1105Server(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("csctl T1105 test payload"))
	})
	plan := &simulate.ExecutionPlan{TechniqueID: "T1105"}
	result, err := NewEmbedded().Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status != simulate.StatusExecuted {
		t.Fatalf("Status = %q, want executed (stderr %q)", result.Status, result.Stderr)
	}
	if _, err := os.Stat(plan.Target); err != nil {
		t.Fatalf("downloaded file missing: %v", err)
	}
}

func TestQuarantinedDetectsARemovedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if quarantined(context.Background(), path, 0) {
		t.Fatal("an existing file is not quarantined")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !quarantined(context.Background(), path, 0) {
		t.Fatal("a removed file is quarantined")
	}
}

func TestT1105ReportsBlockedWhenTheProxyRefusesTheTunnel(t *testing.T) {
	// A loopback proxy that refuses every HTTPS tunnel. The download target
	// is a reserved .invalid name, so nothing can reach a real host even if
	// the proxy override stopped working.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "blocked by policy", http.StatusForbidden)
			return
		}
		http.Error(w, "unexpected request", http.StatusBadRequest)
	}))
	t.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}

	oldProxy, oldURL, oldWait := t1105Proxy, t1105URL, t1105QuarantineWait
	t.Cleanup(func() { t1105Proxy, t1105URL, t1105QuarantineWait = oldProxy, oldURL, oldWait })
	t1105Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	t1105URL, t1105QuarantineWait = "https://t1105-target.invalid/payload", 0
	t.Setenv("TMPDIR", t.TempDir())

	result, err := NewEmbedded().Execute(context.Background(), &simulate.ExecutionPlan{TechniqueID: "T1105"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status != simulate.StatusBlocked || result.BlockEvidence == "" {
		t.Fatalf("Status=%q evidence=%q (stderr %q), want blocked with evidence", result.Status, result.BlockEvidence, result.Stderr)
	}
	if files, _ := filepath.Glob(filepath.Join(os.TempDir(), "csctl-t1105-*")); len(files) != 0 {
		t.Fatalf("a refused tunnel must not write a file, found %v", files)
	}
}

func TestEmbeddedExecutionStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want simulate.ExecutionStatus
	}{
		{"success", nil, simulate.StatusExecuted},
		{"blocked", &simulate.BlockedError{Evidence: "download refused with HTTP 403"}, simulate.StatusBlocked},
		{"wrapped blocked", fmt.Errorf("downloading test file: %w", &simulate.BlockedError{Evidence: "x"}), simulate.StatusBlocked},
		{"access denied while writing", fmt.Errorf("creating marker file: %w", &os.PathError{Op: "open", Path: `C:\Temp\marker`, Err: errors.New("Access is denied.")}), simulate.StatusBlocked},
		{"missing privilege", errors.New("T1136.001 requires root privileges (run with sudo)"), simulate.StatusDidNotRun},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, evidence := executionStatus(context.Background(), tc.err)
			if status != tc.want {
				t.Fatalf("status = %q, want %q", status, tc.want)
			}
			if blocked := status == simulate.StatusBlocked; blocked != (evidence != "") {
				t.Fatalf("evidence = %q for status %q, want evidence exactly when blocked", evidence, status)
			}
		})
	}
}
