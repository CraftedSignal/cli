package yaml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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

// LoadAll loads all YAML files from a directory recursively.
func LoadAll(root string) ([]LoadedRule, error) {
	var rules []LoadedRule

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		loaded, err := LoadFile(path, root)
		if err != nil {
			return fmt.Errorf("failed to load %s: %w", path, err)
		}

		rules = append(rules, loaded...)
		return nil
	})

	return rules, err
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

		return []LoadedRule{{
			Rule:     single,
			FilePath: path,
			Hash:     ComputeHash(single),
		}}, nil
	}

	// Try as array
	var multiple []schema.Detection
	if err := yaml.Unmarshal(data, &multiple); err == nil {
		var rules []LoadedRule
		for _, r := range multiple {
			r.Groups = mergeGroups(folderGroups, r.Groups)
			rules = append(rules, LoadedRule{
				Rule:     r,
				FilePath: path,
				Hash:     ComputeHash(r),
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
	buf.WriteString(fmt.Sprintf("# %s\n# Generated %s\n\n", rule.Title, timestamp))

	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(4)

	// Build a custom node for prettier output
	node := buildDetectionNode(rule)
	if err := encoder.Encode(node); err != nil {
		return err
	}
	encoder.Close()

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
func ComputeHash(r schema.Detection) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%v|%v|%v",
		r.Title, r.Description, r.Platform, r.Query, r.Severity, r.Kind,
		r.Frequency, r.Period, r.Tactics, r.Techniques, r.Tags)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
