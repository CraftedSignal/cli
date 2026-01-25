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
	Tests       *Tests   `yaml:"tests,omitempty" json:"tests,omitempty"`
}

// Tests contains test cases for validating detection rules.
type Tests struct {
	Positive []Test `yaml:"positive,omitempty" json:"positive,omitempty"` // Should trigger the detection
	Negative []Test `yaml:"negative,omitempty" json:"negative,omitempty"` // Should NOT trigger the detection
}

// Test represents a single test case with sample log data.
type Test struct {
	Name        string                   `yaml:"name" json:"name"`
	Description string                   `yaml:"description,omitempty" json:"description,omitempty"`
	Data        []map[string]interface{} `yaml:"data" json:"data"`
}
