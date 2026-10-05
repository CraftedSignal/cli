package schema

// LibraryExport is the YAML document for reusable local library content.
type LibraryExport struct {
	Version int           `yaml:"version" json:"version"`
	Items   []LibraryItem `yaml:"items" json:"items"`
}

// LibraryItem uses type to distinguish reusable templates from active rules.
// Valid values are: rule_template, hunt_template, guide.
type LibraryItem struct {
	Type                string         `yaml:"type" json:"type"`
	ID                  string         `yaml:"id" json:"id"`
	Name                string         `yaml:"name" json:"name"`
	Description         string         `yaml:"description,omitempty" json:"description,omitempty"`
	Query               string         `yaml:"query,omitempty" json:"query,omitempty"`
	QueryType           string         `yaml:"query_type,omitempty" json:"query_type,omitempty"`
	Queries             []LibraryQuery `yaml:"queries,omitempty" json:"queries,omitempty"`
	Severity            string         `yaml:"severity,omitempty" json:"severity,omitempty"`
	Tactics             []string       `yaml:"tactics,omitempty" json:"tactics,omitempty"`
	Techniques          []string       `yaml:"techniques,omitempty" json:"techniques,omitempty"`
	Tags                []string       `yaml:"tags,omitempty" json:"tags,omitempty"`
	Date                string         `yaml:"date,omitempty" json:"date,omitempty"`
	Author              string         `yaml:"author,omitempty" json:"author,omitempty"`
	Version             string         `yaml:"version,omitempty" json:"version,omitempty"`
	File                string         `yaml:"file,omitempty" json:"file,omitempty"`
	References          []string       `yaml:"references,omitempty" json:"references,omitempty"`
	DataSources         []string       `yaml:"data_sources,omitempty" json:"data_sources,omitempty"`
	Tests               *LibraryTests  `yaml:"tests,omitempty" json:"tests,omitempty"`
	OperationalGuidance string         `yaml:"operational_guidance,omitempty" json:"operational_guidance,omitempty"`
	Body                string         `yaml:"body,omitempty" json:"body,omitempty"`
	Summary             string         `yaml:"summary,omitempty" json:"summary,omitempty"`
	Status              string         `yaml:"status,omitempty" json:"status,omitempty"`
	AppliesTo           []string       `yaml:"applies_to,omitempty" json:"applies_to,omitempty"`
}

type LibraryQuery struct {
	Title     string `yaml:"title" json:"title"`
	Query     string `yaml:"query" json:"query"`
	QueryType string `yaml:"query_type,omitempty" json:"query_type,omitempty"`
}

type LibraryTests struct {
	Positive []LibraryTest `yaml:"positive,omitempty" json:"positive,omitempty"`
	Negative []LibraryTest `yaml:"negative,omitempty" json:"negative,omitempty"`
}

type LibraryTest struct {
	Name        string                   `yaml:"name" json:"name"`
	Description string                   `yaml:"description,omitempty" json:"description,omitempty"`
	Data        []map[string]interface{} `yaml:"data,omitempty" json:"data,omitempty"`
	JSON        string                   `yaml:"json,omitempty" json:"json,omitempty"`
}
