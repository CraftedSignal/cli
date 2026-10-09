//go:build !windows

package simulate

import (
	"context"
	"time"
)

// DefenderBlockEvidence only reads the Windows Defender log; other platforms
// have none.
func DefenderBlockEvidence(context.Context, time.Time, time.Time) (string, bool) {
	return "", false
}
