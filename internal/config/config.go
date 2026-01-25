package config

import (
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config represents the CLI configuration.
type Config struct {
	URL      string `yaml:"url"`
	Token    string `yaml:"token"`
	Insecure bool   `yaml:"insecure"`
	Defaults struct {
		Path     string `yaml:"path"`
		Platform string `yaml:"platform"`
	} `yaml:"defaults"`
}

// Load reads configuration from .csctl.yaml and environment variables.
// Environment variables take precedence over file configuration.
// Supported env vars: CSCTL_URL, CSCTL_TOKEN, CSCTL_INSECURE, CSCTL_PATH, CSCTL_PLATFORM
func Load() (*Config, error) {
	return LoadFromPath("")
}

// LoadFromPath reads configuration from a specific file and environment variables.
// If configPath is empty, it searches for .csctl.yaml in current and parent directories.
// Environment variables take precedence over file configuration.
func LoadFromPath(configPath string) (*Config, error) {
	cfg := &Config{}

	// Load from specified path or find config file
	var path string
	var err error
	if configPath != "" {
		path = configPath
	} else {
		path, err = findConfigFile()
	}

	if path != "" && err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	// Environment variables override file configuration
	if url := os.Getenv("CSCTL_URL"); url != "" {
		cfg.URL = url
	}
	if token := os.Getenv("CSCTL_TOKEN"); token != "" {
		cfg.Token = token
	}
	if insecure := os.Getenv("CSCTL_INSECURE"); insecure != "" {
		cfg.Insecure, _ = strconv.ParseBool(insecure)
	}
	if path := os.Getenv("CSCTL_PATH"); path != "" {
		cfg.Defaults.Path = path
	}
	if platform := os.Getenv("CSCTL_PLATFORM"); platform != "" {
		cfg.Defaults.Platform = platform
	}

	return cfg, nil
}

// GetToken returns the API token from config or environment.
// Deprecated: Use Load().Token instead.
func GetToken() string {
	cfg, _ := Load()
	return cfg.Token
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
