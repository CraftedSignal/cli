package yaml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/cli/pkg/schema"
	"gopkg.in/yaml.v3"
)

// LoadedRule represents a rule loaded from a file.
type LoadedRule struct {
	Rule     schema.Detection
	FilePath string
	Hash     string
}

// LoadError represents a file that failed to load.
type LoadError struct {
	Path string
	Err  error
}

func (e LoadError) Error() string {
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

// LoadAll loads all YAML files from a directory recursively.
func LoadAll(root string) ([]LoadedRule, error) {
	rules, errors := LoadAllLenient(root)
	if len(errors) > 0 {
		return nil, errors[0]
	}
	return rules, nil
}

// LoadAllLenient loads all YAML files, returning successfully loaded rules
// and a list of errors for files that failed to load.
func LoadAllLenient(root string) ([]LoadedRule, []LoadError) {
	var rules []LoadedRule
	var loadErrors []LoadError

	absRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, []LoadError{{Path: root, Err: fmt.Errorf("failed to resolve root path: %w", err)}}
	}

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			loadErrors = append(loadErrors, LoadError{Path: path, Err: err})
			return nil
		}

		// Skip symlinks to prevent path traversal
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Verify resolved path stays within root directory (resolve symlinks in path components)
		absPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			loadErrors = append(loadErrors, LoadError{Path: path, Err: fmt.Errorf("failed to resolve path: %w", err)})
			return nil
		}
		if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
			loadErrors = append(loadErrors, LoadError{Path: path, Err: fmt.Errorf("path traversal detected")})
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		loaded, err := LoadFile(path, root)
		if err != nil {
			loadErrors = append(loadErrors, LoadError{Path: path, Err: err})
			return nil
		}

		rules = append(rules, loaded...)
		return nil
	})

	return rules, loadErrors
}

// LoadFile loads rules from a single YAML file.
func LoadFile(path, root string) ([]LoadedRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Calculate relative path for folder-based groups
	relPath, _ := filepath.Rel(root, path)
	folderGroups := extractFolderGroups(relPath)

	// Try to parse as single document first
	var single schema.Detection
	if err := yaml.Unmarshal(data, &single); err == nil && single.Title != "" {
		// Merge folder groups with explicit groups
		single.Groups = mergeGroups(folderGroups, single.Groups)

		hash, err := ComputeHash(single)
		if err != nil {
			return nil, fmt.Errorf("failed to compute hash for %s: %w", path, err)
		}

		return []LoadedRule{{
			Rule:     single,
			FilePath: path,
			Hash:     hash,
		}}, nil
	}

	// Try as array
	var multiple []schema.Detection
	if err := yaml.Unmarshal(data, &multiple); err == nil {
		var rules []LoadedRule
		for _, r := range multiple {
			r.Groups = mergeGroups(folderGroups, r.Groups)
			hash, err := ComputeHash(r)
			if err != nil {
				return nil, fmt.Errorf("failed to compute hash for %s: %w", path, err)
			}
			rules = append(rules, LoadedRule{
				Rule:     r,
				FilePath: path,
				Hash:     hash,
			})
		}
		return rules, nil
	}

	return nil, fmt.Errorf("invalid YAML format")
}

// SaveFile saves a rule to a YAML file with pretty formatting.
func SaveFile(rule schema.Detection, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	var buf strings.Builder
	timestamp := time.Now().Format("2006-01-02 15:04")
	fmt.Fprintf(&buf, "# %s\n# Generated %s\n\n", rule.Title, timestamp)

	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(4)

	// Build a custom node for prettier output
	node := buildDetectionNode(rule)
	if err := encoder.Encode(node); err != nil {
		return err
	}
	_ = encoder.Close()

	return os.WriteFile(path, []byte(buf.String()), 0644)
}

// buildDetectionNode creates a yaml.Node with pretty formatting.
func buildDetectionNode(rule schema.Detection) *yaml.Node {
	root := &yaml.Node{Kind: yaml.MappingNode}

	// Helper to add a field with optional blank line before
	addField := func(key, value string, style yaml.Style, blankBefore bool) {
		if value == "" {
			return
		}
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
		if blankBefore {
			keyNode.HeadComment = "\n"
		}
		valNode := &yaml.Node{Kind: yaml.ScalarNode, Value: value, Style: style}
		root.Content = append(root.Content, keyNode, valNode)
	}

	// Helper to add string slice
	addSlice := func(key string, values []string) {
		if len(values) == 0 {
			return
		}
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
		seqNode := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, v := range values {
			seqNode.Content = append(seqNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: v})
		}
		root.Content = append(root.Content, keyNode, seqNode)
	}

	// Section 1: Identity
	addField("title", rule.Title, 0, false)
	addField("id", rule.ID, 0, false)

	// Description - use literal style if multi-line
	if rule.Description != "" {
		style := yaml.Style(0)
		if strings.Contains(rule.Description, "\n") {
			style = yaml.LiteralStyle
		}
		addField("description", rule.Description, style, false)
	}

	// Section 2: Query (with blank line before)
	if rule.Query != "" {
		addField("query", rule.Query, yaml.LiteralStyle, true)
	}

	// Section 3: Metadata (with blank line before)
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "platform", HeadComment: "\n"}
	valNode := &yaml.Node{Kind: yaml.ScalarNode, Value: rule.Platform}
	root.Content = append(root.Content, keyNode, valNode)

	addSlice("groups", rule.Groups)
	addField("severity", rule.Severity, 0, false)
	addField("kind", rule.Kind, 0, false)

	// Enabled
	keyNode = &yaml.Node{Kind: yaml.ScalarNode, Value: "enabled"}
	valNode = &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("%t", rule.Enabled)}
	root.Content = append(root.Content, keyNode, valNode)

	addField("frequency", rule.Frequency, 0, false)
	addField("period", rule.Period, 0, false)

	// Lists
	addSlice("tactics", rule.Tactics)
	addSlice("techniques", rule.Techniques)
	addSlice("tags", rule.Tags)

	// Section 4: Tests (with blank line before)
	if rule.Tests != nil && (len(rule.Tests.Positive) > 0 || len(rule.Tests.Negative) > 0) {
		testsKeyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "tests", HeadComment: "\n"}
		testsNode := buildTestsNode(rule.Tests)
		root.Content = append(root.Content, testsKeyNode, testsNode)
	}

	return root
}

// buildTestsNode creates a yaml.Node for tests with pretty formatting.
func buildTestsNode(tests *schema.Tests) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode}

	buildTestList := func(testList []schema.Test) *yaml.Node {
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for _, t := range testList {
			testNode := &yaml.Node{Kind: yaml.MappingNode}

			// Name - quote if it looks like a number
			nameStyle := yaml.Style(0)
			if looksLikeNumber(t.Name) {
				nameStyle = yaml.DoubleQuotedStyle
			}
			testNode.Content = append(testNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: "name"},
				&yaml.Node{Kind: yaml.ScalarNode, Value: t.Name, Style: nameStyle},
			)

			// Description
			if t.Description != "" {
				style := yaml.Style(0)
				if strings.Contains(t.Description, "\n") {
					style = yaml.LiteralStyle
				}
				testNode.Content = append(testNode.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: "description"},
					&yaml.Node{Kind: yaml.ScalarNode, Value: t.Description, Style: style},
				)
			}

			// Data or JSON
			if t.JSON != "" {
				// JSON inline (flow style)
				testNode.Content = append(testNode.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: "json"},
					&yaml.Node{Kind: yaml.ScalarNode, Value: t.JSON, Tag: "!!str"},
				)
			} else if len(t.Data) > 0 {
				dataNode := &yaml.Node{Kind: yaml.SequenceNode}
				for _, entry := range t.Data {
					entryNode := &yaml.Node{Kind: yaml.MappingNode}
					for k, v := range entry {
						valStr := fmt.Sprintf("%v", v)
						valStyle := yaml.Style(0)
						if looksLikeNumber(valStr) {
							valStyle = yaml.DoubleQuotedStyle
						}
						entryNode.Content = append(entryNode.Content,
							&yaml.Node{Kind: yaml.ScalarNode, Value: k},
							&yaml.Node{Kind: yaml.ScalarNode, Value: valStr, Style: valStyle},
						)
					}
					dataNode.Content = append(dataNode.Content, entryNode)
				}
				testNode.Content = append(testNode.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: "data"},
					dataNode,
				)
			}

			seq.Content = append(seq.Content, testNode)
		}
		return seq
	}

	if len(tests.Positive) > 0 {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "positive"},
			buildTestList(tests.Positive),
		)
	}
	if len(tests.Negative) > 0 {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "negative"},
			buildTestList(tests.Negative),
		)
	}

	return node
}

// looksLikeNumber returns true if the string could be parsed as a number.
func looksLikeNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' && c != '-' && c != '+' && c != 'e' && c != 'E' {
			return false
		}
	}
	return true
}

func extractFolderGroups(relPath string) []string {
	dir := filepath.Dir(relPath)
	if dir == "." {
		return nil
	}

	parts := strings.Split(dir, string(filepath.Separator))
	var groups []string
	for _, p := range parts {
		if p != "" && p != "." {
			groups = append(groups, p)
		}
	}
	return groups
}

func mergeGroups(folder, explicit []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, g := range folder {
		if !seen[g] {
			seen[g] = true
			result = append(result, g)
		}
	}
	for _, g := range explicit {
		if !seen[g] {
			seen[g] = true
			result = append(result, g)
		}
	}

	return result
}

// ComputeHash computes a hash of the detection's sync-relevant fields.
// This must match the backend's computeDetectionHash function.
func ComputeHash(r schema.Detection) (string, error) {
	testsHash := computeTestsHash(r.Tests)
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%v|%s|%s",
		r.Title, r.Description, r.Platform, r.Query, r.Severity, r.Kind,
		r.Frequency, r.Period, sortedSlice(r.Tactics), sortedSlice(r.Techniques),
		sortedSlice(r.Tags), r.Enabled, sortedSlice(r.Groups), testsHash)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

// sortedSlice returns a sorted copy of the slice as a joined string.
func sortedSlice(s []string) string {
	if len(s) == 0 {
		return ""
	}
	sorted := make([]string, len(s))
	copy(sorted, s)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// computeTestsHash creates a deterministic hash of tests.
func computeTestsHash(tests *schema.Tests) string {
	if tests == nil {
		return ""
	}
	var parts []string
	for _, t := range tests.Positive {
		parts = append(parts, serializeTest("positive", t))
	}
	for _, t := range tests.Negative {
		parts = append(parts, serializeTest("negative", t))
	}
	// Sort for deterministic ordering
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// serializeTest converts a test to a deterministic string representation.
func serializeTest(testType string, t schema.Test) string {
	// For data, serialize with sorted keys
	dataStr := serializeTestData(t.Data)
	return fmt.Sprintf("%s:%s:%s:%s:%s", testType, t.Name, t.Description, dataStr, t.JSON)
}

// serializeTestData converts test data to a deterministic string.
func serializeTestData(data []map[string]interface{}) string {
	if len(data) == 0 {
		return ""
	}
	var entries []string
	for _, entry := range data {
		entries = append(entries, serializeMap(entry))
	}
	return strings.Join(entries, ",")
}

// serializeMap converts a map to a deterministic string with sorted keys.
func serializeMap(m map[string]interface{}) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}
