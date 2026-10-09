//go:build windows

package simulate

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// defenderLog is the event channel Microsoft Defender writes detections to.
// Event 1116 means malware was detected, 1117 that Defender acted on it.
const defenderLog = "Microsoft-Windows-Windows Defender/Operational"

// defenderQuery is the wevtutil XPath query for Defender detections between
// since and until.
func defenderQuery(since, until time.Time) string {
	return fmt.Sprintf("*[System[(EventID=1116 or EventID=1117) and TimeCreated[@SystemTime>='%s' and @SystemTime<='%s']]]",
		since.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339))
}

// DefenderBlockEvidence reports a Microsoft Defender detection logged between
// since and until. It waits until `until` first, because Defender logs a
// detection shortly after it acts.
func DefenderBlockEvidence(ctx context.Context, since, until time.Time) (string, bool) {
	if wait := time.Until(until); wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return "", false
		}
	}
	out, err := exec.CommandContext(ctx, "wevtutil", "qe", defenderLog,
		"/q:"+defenderQuery(since, until), "/f:xml", "/c:5", "/rd:true").Output()
	if err != nil {
		return "", false
	}
	return parseDefenderEvents(string(out))
}
