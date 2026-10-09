package simulate

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// ExecutionStatus says whether a technique ran, was stopped by a security
// control, or failed for another reason.
type ExecutionStatus string

const (
	StatusExecuted  ExecutionStatus = "executed"
	StatusBlocked   ExecutionStatus = "blocked"
	StatusDidNotRun ExecutionStatus = "did_not_run"
)

// blockMarkers are output fragments that mean a security control stopped the
// technique, as opposed to a missing tool or a missing privilege.
var blockMarkers = []string{
	"access is denied",
	"access denied",
	"0x00000005", // ERROR_ACCESS_DENIED as printed by mimikatz
	"contains a virus",
	"potentially unwanted software",
	"blocked by group policy",
	"has been blocked",
}

// Classify derives the execution status of a finished command from its run
// error and output. A context that ended (timeout or cancel) means the
// technique did not finish, so it never counts as blocked.
func Classify(ctx context.Context, runErr error, stdout, stderr string) (ExecutionStatus, string) {
	if ctx.Err() != nil {
		return StatusDidNotRun, ""
	}
	if marker, ok := findBlockMarker(stdout + "\n" + stderr); ok {
		return StatusBlocked, "output: " + marker
	}
	if runErr == nil {
		return StatusExecuted, ""
	}
	if killedBySignal(runErr) {
		return StatusBlocked, "process was killed"
	}
	return StatusDidNotRun, ""
}

// ResultFromCommand builds the result of an adapter that ran one external
// command, classifying it with Classify.
func ResultFromCommand(ctx context.Context, start time.Time, runErr error, stdout, stderr string) *ExecutionResult {
	result := &ExecutionResult{
		Success:   runErr == nil,
		StartTime: start,
		EndTime:   time.Now(),
		Stdout:    stdout,
		Stderr:    stderr,
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	} else if runErr != nil {
		result.ExitCode = -1
	}
	result.Status, result.BlockEvidence = Classify(ctx, runErr, stdout, stderr)
	return result
}

func findBlockMarker(output string) (string, bool) {
	lower := strings.ToLower(output)
	for _, marker := range blockMarkers {
		if strings.Contains(lower, marker) {
			return marker, true
		}
	}
	return "", false
}

// killedBySignal reports whether the process was terminated with SIGKILL,
// which EDR agents on Linux and macOS use to stop a process.
func killedBySignal(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}
