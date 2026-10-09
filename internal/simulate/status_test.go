package simulate

import (
	"context"
	"errors"
	"testing"
)

func TestClassify(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name   string
		ctx    context.Context
		runErr error
		stdout string
		stderr string
		want   ExecutionStatus
	}{
		{"clean run", context.Background(), nil, "done", "", StatusExecuted},
		{"mimikatz access denied with exit 0", context.Background(), nil,
			"ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)", "", StatusBlocked},
		{"windows access denied", context.Background(), errors.New("exit status 1"), "", "Access is denied.", StatusBlocked},
		{"defender virus message", context.Background(), errors.New("exit status 1"), "",
			"Operation did not complete successfully because the file contains a virus or potentially unwanted software.", StatusBlocked},
		{"missing tool", context.Background(), errors.New(`exec: "mimikatz.exe": executable file not found in %PATH%`), "", "", StatusDidNotRun},
		{"timed out", cancelled, errors.New("signal: killed"), "", "", StatusDidNotRun},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, evidence := Classify(tc.ctx, tc.runErr, tc.stdout, tc.stderr)
			if got != tc.want {
				t.Fatalf("Classify() = %q, want %q", got, tc.want)
			}
			if got == StatusBlocked && evidence == "" {
				t.Fatal("a blocked run must carry evidence")
			}
		})
	}
}
