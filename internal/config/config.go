package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the CLI configuration.
type Config struct {
	URL      string `yaml:"url"`
	Defaults struct {
		Path     string `yaml:"path"`
		Platform string `yaml:"platform"`
	} `yaml:"defaults"`
}

// Load reads configuration from .csctl.yaml in the current directory or parents.
func Load() (*Config, error) {
	path, err := findConfigFile()
	if err != nil {
		return &Config{}, nil // Return empty config if not found
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// GetToken returns the API token from environment variable.
func GetToken() string {
	return os.Getenv("CSCTL_TOKEN")
}

func findConfigFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		path := filepath.Join(dir, ".csctl.yaml")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", os.ErrNotExist
}