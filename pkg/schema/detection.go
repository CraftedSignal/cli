package schema

// Detection represents a detection rule in YAML format.
type Detection struct {
	ID          string   `yaml:"id,omitempty" json:"id,omitempty"`
	Title       string   `yaml:"title" json:"title"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Platform    string   `yaml:"platform" json:"platform"`
	Query       string   `yaml:"query,omitempty" json:"query,omitempty"`
	Severity    string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	Kind        string   `yaml:"kind,omitempty" json:"kind,omitempty"`
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Frequency   string   `yaml:"frequency,omitempty" json:"frequency,omitempty"`
	Period      string   `yaml:"period,omitempty" json:"period,omitempty"`
	Tactics     []string `yaml:"tactics,omitempty" json:"tactics,omitempty"`
	Techniques  []string `yaml:"techniques,omitempty" json:"techniques,omitempty"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Groups      []string `yaml:"groups,omitempty" json:"groups,omitempty"`
}
