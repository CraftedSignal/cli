package simulate

import (
	"fmt"
	"sync"
)

// Registry holds all registered BAS adapters and provides lookup methods.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]BASAdapter
}

// NewRegistry creates an empty adapter registry.
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[string]BASAdapter),
	}
}

// Register adds an adapter. It returns an error if an adapter with the same name is already registered.
func (r *Registry) Register(a BASAdapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := a.Name()
	if _, exists := r.adapters[name]; exists {
		return fmt.Errorf("adapter %q already registered", name)
	}
	r.adapters[name] = a
	return nil
}

// Get returns the adapter with the given name, or nil if not found.
func (r *Registry) Get(name string) BASAdapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.adapters[name]
}

// All returns every registered adapter.
func (r *Registry) All() []BASAdapter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]BASAdapter, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a)
	}
	return out
}

// ForTechnique returns adapters that list a technique matching the given ID.
// It calls List on each adapter, so it may be slow if adapters do I/O.
func (r *Registry) ForTechnique(techniqueID string) []BASAdapter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []BASAdapter
	for _, a := range r.adapters {
		techs, err := a.List(Filter{TechniqueID: techniqueID})
		if err != nil {
			continue
		}
		for _, t := range techs {
			if t.ID == techniqueID {
				out = append(out, a)
				break
			}
		}
	}
	return out
}
