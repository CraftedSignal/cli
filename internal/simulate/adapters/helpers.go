package adapters

import (
	"slices"

	"github.com/craftedsignal/cli/internal/simulate"
)

// containsPlatform checks whether a slice contains the given platform.
func containsPlatform(platforms []simulate.Platform, p simulate.Platform) bool {
	return slices.Contains(platforms, p)
}
