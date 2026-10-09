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

// blockMarkers are output fragments that usually mean a security control
// stopped the technique. Access-denied text can also mean a missing privilege
// or failed credentials, so the evidence quotes the matching line for the
// person who confirms the outcome.
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
	if line, ok := findBlockLine(stdout + "\n" + stderr); ok {
		return StatusBlocked, "output: " + line
	}
	if runErr != nil {
		// A control that refuses to launch the tool shows up only in the
		// launch error, e.g. "fork/exec mimikatz.exe: Operation did not
		// complete successfully because the file contains a virus ...".
		if line, ok := findBlockLine(runErr.Error()); ok {
			return StatusBlocked, "error: " + line
		}
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

// maxEvidenceLine caps the output line quoted as block evidence.
const maxEvidenceLine = 200

// findBlockLine returns the first line of output that contains a block
// marker, trimmed and capped at maxEvidenceLine characters.
func findBlockLine(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		for _, marker := range blockMarkers {
			if strings.Contains(lower, marker) {
				line = strings.TrimSpace(line)
				if r := []rune(line); len(r) > maxEvidenceLine {
					line = string(r[:maxEvidenceLine])
				}
				return line, true
			}
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
