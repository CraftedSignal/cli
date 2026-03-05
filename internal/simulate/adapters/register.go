package adapters

import "github.com/craftedsignal/cli/internal/simulate"

// RegisterAll registers every built-in BAS adapter with the given registry.
func RegisterAll(reg *simulate.Registry) {
	// Errors are intentionally ignored here because duplicate registration
	// is not expected for built-in adapters.
	_ = reg.Register(NewAtomic())
	_ = reg.Register(NewMimikatz())
	_ = reg.Register(NewLsassy())
	_ = reg.Register(NewImpacket())
}
