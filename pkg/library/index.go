package library

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// IndexVersion is the current index format version.
const IndexVersion = 1

// Index represents a library repository index file.
type Index struct {
	Version    int            `json:"version" yaml:"version"`
	Repository RepositoryInfo `json:"repository" yaml:"repository"`
	SigningKey string         `json:"signing_key_id,omitempty" yaml:"signing_key_id,omitempty"`
	Signature  string         `json:"signature,omitempty" yaml:"signature,omitempty"`
	Entries    []IndexEntry   `json:"entries" yaml:"entries"`
}

// RepositoryInfo contains metadata about the library repository.
type RepositoryInfo struct {
	Name       string    `json:"name" yaml:"name"`
	URL        string    `json:"url,omitempty" yaml:"url,omitempty"`
	Maintainer string    `json:"maintainer,omitempty" yaml:"maintainer,omitempty"`
	UpdatedAt  time.Time `json:"updated_at" yaml:"updated_at"`
}

// IndexEntry represents a single entry in the library index.
type IndexEntry struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	QueryType   string   `json:"query_type" yaml:"query_type"` // spl, kql, leql, rapid7
	Severity    string   `json:"severity" yaml:"severity"`     // critical, high, medium, low
	Author      string   `json:"author,omitempty" yaml:"author,omitempty"`
	Version     string   `json:"version,omitempty" yaml:"version,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`

	// File reference and integrity
	File   string `json:"file" yaml:"file"`     // Relative path to query file
	SHA256 string `json:"sha256" yaml:"sha256"` // Hash of the query file

	// MITRE ATT&CK mapping
	MITRETactics    []string `json:"mitre_tactics,omitempty" yaml:"mitre_tactics,omitempty"`
	MITRETechniques []string `json:"mitre_techniques,omitempty" yaml:"mitre_techniques,omitempty"`

	// Searchable metadata
	Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	DataSources []string `json:"data_sources,omitempty" yaml:"data_sources,omitempty"`
}

// LibraryEntry represents a detection query in YAML format.
type LibraryEntry struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Query       string   `yaml:"query"`
	QueryType   string   `yaml:"query_type"`
	Severity    string   `yaml:"severity"`
	Tactics     []string `yaml:"tactics"`
	Techniques  []string `yaml:"techniques"`
	Tags        []string `yaml:"tags"`
	Author      string   `yaml:"author"`
	Version     string   `yaml:"version"`
}

// GenerateIndex scans a directory for query files and generates an index.
func GenerateIndex(dir string, repoName string) (*Index, error) {
	index := &Index{
		Version: IndexVersion,
		Repository: RepositoryInfo{
			Name:      repoName,
			UpdatedAt: time.Now().UTC(),
		},
		Entries: []IndexEntry{},
	}

	// Walk the directory looking for YAML files
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		// Skip index files themselves
		base := strings.ToLower(filepath.Base(path))
		if strings.HasPrefix(base, "library.index") {
			return nil
		}

		// Try to parse as a library entry
		entry, err := parseQueryFile(path, dir)
		if err != nil {
			// Skip files that aren't valid library entries
			return nil
		}

		index.Entries = append(index.Entries, *entry)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return index, nil
}

// parseQueryFile reads a query file and extracts metadata for the index.
func parseQueryFile(path string, baseDir string) (*IndexEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse the YAML to extract metadata
	var entry LibraryEntry
	if err := yaml.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	// Validate required fields
	if entry.ID == "" || entry.Name == "" || entry.Query == "" {
		return nil, fmt.Errorf("missing required fields")
	}

	// Calculate file hash
	hash := sha256.Sum256(data)

	// Get relative path
	relPath, err := filepath.Rel(baseDir, path)
	if err != nil {
		relPath = path
	}

	return &IndexEntry{
		ID:              entry.ID,
		Name:            entry.Name,
		Description:     entry.Description,
		QueryType:       entry.QueryType,
		Severity:        entry.Severity,
		Author:          entry.Author,
		Version:         entry.Version,
		MITRETactics:    entry.Tactics,
		MITRETechniques: entry.Techniques,
		Tags:            entry.Tags,
		File:            relPath,
		SHA256:          fmt.Sprintf("%x", hash),
	}, nil
}

// Sign signs the index entries with an Ed25519 private key.
func (idx *Index) Sign(privateKey ed25519.PrivateKey, keyID string) error {
	// Serialize entries for signing (deterministic JSON)
	entriesJSON, err := json.Marshal(idx.Entries)
	if err != nil {
		return fmt.Errorf("failed to serialize entries: %w", err)
	}

	// Sign the entries
	signature := ed25519.Sign(privateKey, entriesJSON)

	idx.SigningKey = keyID
	idx.Signature = base64.StdEncoding.EncodeToString(signature)

	return nil
}

// Verify verifies the index signature using an Ed25519 public key.
func (idx *Index) Verify(publicKey ed25519.PublicKey) error {
	if idx.Signature == "" {
		return fmt.Errorf("index is not signed")
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(idx.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Serialize entries for verification (deterministic JSON)
	entriesJSON, err := json.Marshal(idx.Entries)
	if err != nil {
		return fmt.Errorf("failed to serialize entries: %w", err)
	}

	// Verify signature
	if !ed25519.Verify(publicKey, entriesJSON, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// WriteYAML writes the index to a writer in YAML format.
func (idx *Index) WriteYAML(w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	return encoder.Encode(idx)
}

// WriteJSON writes the index to a writer in JSON format.
func (idx *Index) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(idx)
}

// LoadIndex loads an index from a file (YAML or JSON based on extension).
func LoadIndex(path string) (*Index, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var index Index
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		err = json.Unmarshal(data, &index)
	} else {
		err = yaml.Unmarshal(data, &index)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse index: %w", err)
	}

	return &index, nil
}

// GenerateKeyPair generates a new Ed25519 key pair for signing.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// LoadPrivateKey loads an Ed25519 private key from a file (base64 encoded).
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Decode base64
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("invalid key encoding: %w", err)
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(keyBytes))
	}

	return ed25519.PrivateKey(keyBytes), nil
}

// LoadPublicKey loads an Ed25519 public key from a file (base64 encoded).
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Decode base64
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("invalid key encoding: %w", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(keyBytes))
	}

	return ed25519.PublicKey(keyBytes), nil
}

// SavePrivateKey saves an Ed25519 private key to a file (base64 encoded).
func SavePrivateKey(path string, key ed25519.PrivateKey) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return os.WriteFile(path, []byte(encoded), 0600)
}

// SavePublicKey saves an Ed25519 public key to a file (base64 encoded).
func SavePublicKey(path string, key ed25519.PublicKey) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return os.WriteFile(path, []byte(encoded), 0644)
}
