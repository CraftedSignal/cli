package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
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
