package simulate

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ScopeConfig represents a parsed simulations.yaml scope file that governs
// which simulations are allowed to run.
type ScopeConfig struct {
	Scope    Scope     `yaml:"scope"`
	Bindings []Binding `yaml:"bindings"`
}

// Scope defines the allowed adapters, techniques, targets, and constraints.
type Scope struct {
	AllowAll    bool        `yaml:"allow_all"`
	Adapters    []string    `yaml:"adapters"`
	Techniques  []string    `yaml:"techniques"`
	Targets     []Target    `yaml:"targets"`
	Constraints Constraints `yaml:"constraints"`
}

// Target describes a host or cloud environment that simulations may target.
type Target struct {
	Host    string `yaml:"host,omitempty"`
	OS      string `yaml:"os,omitempty"`
	Env     string `yaml:"env,omitempty"`
	Profile string `yaml:"profile,omitempty"`
}

// Constraints limit how simulations execute.
type Constraints struct {
	MaxConcurrent int           `yaml:"max_concurrent"`
	Cleanup       string        `yaml:"cleanup"`
	Timeout       time.Duration `yaml:"timeout"`
}

// Binding maps a technique to the detection rules that should fire.
type Binding struct {
	Technique  string   `yaml:"technique"`
	Detections []string `yaml:"detections"`
}

// LoadScope reads and parses a scope file from disk.
func LoadScope(path string) (*ScopeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scope file: %w", err)
	}

	var cfg ScopeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing scope file: %w", err)
	}

	return &cfg, nil
}

// IsAllowed reports whether the given technique and adapter combination is
// permitted by this scope configuration. When allow_all is true every
// combination is permitted. Otherwise the technique must appear in the
// techniques list (or the list must be empty) AND the adapter must appear in
// the adapters list (or the list must be empty).
func (s *ScopeConfig) IsAllowed(techniqueID, adapterName string) bool {
	if s.Scope.AllowAll {
		return true
	}

	if len(s.Scope.Techniques) > 0 && !contains(s.Scope.Techniques, techniqueID) {
		return false
	}

	if len(s.Scope.Adapters) > 0 && !contains(s.Scope.Adapters, adapterName) {
		return false
	}

	return true
}

// GetBindings returns the detection IDs explicitly bound to the given technique.
// Returns nil when no binding exists.
func (s *ScopeConfig) GetBindings(techniqueID string) []string {
	for _, b := range s.Bindings {
		if b.Technique == techniqueID {
			return b.Detections
		}
	}
	return nil
}

// GetTarget looks up a target by host name or env name. Returns nil if no
// match is found.
func (s *ScopeConfig) GetTarget(name string) *Target {
	for i := range s.Scope.Targets {
		t := &s.Scope.Targets[i]
		if t.Host == name || t.Env == name {
			return t
		}
	}
	return nil
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
