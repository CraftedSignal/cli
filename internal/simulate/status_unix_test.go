//go:build !windows

package simulate

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestClassifyTreatsSIGKILLAsBlocked(t *testing.T) {
	err := exec.Command("sh", "-c", "kill -9 $$").Run()
	got, _ := Classify(context.Background(), err, "", "")
	if got != StatusBlocked {
		t.Fatalf("Classify() = %q, want blocked for a process killed with SIGKILL", got)
	}
}

func TestResultFromCommandRecordsExitCodeAndStatus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("sh", "-c", "echo partial; exit 3")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	result := ResultFromCommand(context.Background(), start, cmd.Run(), stdout.String(), stderr.String())
	if result.Success || result.ExitCode != 3 {
		t.Fatalf("Success=%v ExitCode=%d, want false and 3", result.Success, result.ExitCode)
	}
	if result.Status != StatusDidNotRun {
		t.Fatalf("Status = %q, want did_not_run", result.Status)
	}
}
