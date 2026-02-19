package schema

import "encoding/json"

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
// Data can be provided as YAML via 'data' or as a JSON string via 'json'.
type Test struct {
	Name        string                   `yaml:"name" json:"name"`
	Description string                   `yaml:"description,omitempty" json:"description,omitempty"`
	Data        []map[string]interface{} `yaml:"data,omitempty" json:"data,omitempty"`
	JSON        string                   `yaml:"json,omitempty" json:"json,omitempty"`
}

// GetData returns the test data, parsing from JSON if the json field is used.
// Returns nil if neither data nor json is provided, or if JSON parsing fails.
func (t *Test) GetData() []map[string]interface{} {
	if len(t.Data) > 0 {
		return t.Data
	}
	if t.JSON != "" {
		var data []map[string]interface{}
		if err := json.Unmarshal([]byte(t.JSON), &data); err != nil {
			// Try parsing as single object and wrap in array
			var single map[string]interface{}
			if err := json.Unmarshal([]byte(t.JSON), &single); err == nil {
				return []map[string]interface{}{single}
			}
			return nil
		}
		return data
	}
	return nil
}
