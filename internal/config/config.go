package config

import (
	"fmt"
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

// Load reads project defaults from .csctl.yaml and connection settings from
// environment variables. Implicit project files cannot select a credential
// destination or disable TLS verification.
// Environment variables take precedence over file configuration.
// Supported env vars: CSCTL_URL, CSCTL_TOKEN, CSCTL_INSECURE, CSCTL_PATH, CSCTL_PLATFORM
func Load() (*Config, error) {
	return LoadFromPath("")
}

// LoadFromPath reads configuration from a specific file and environment variables.
// If configPath is empty, it searches for project defaults in .csctl.yaml in the
// current and parent directories. Connection settings require an explicitly
// selected file, environment variables, or command-line flags.
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
		if configPath == "" && (cfg.URL != "" || cfg.Token != "" || cfg.Insecure) {
			return nil, fmt.Errorf("automatically discovered config %s contains connection settings; review the file and select it explicitly with --config, or move url/token/insecure to flags or CSCTL environment variables", path)
		}

		// Warn if token is stored in config file (should use CSCTL_TOKEN env var)
		if cfg.Token != "" {
			fmt.Fprintf(os.Stderr, "WARNING: token found in config file %s -- use CSCTL_TOKEN env var instead\n", path)
		}

		// Check file permissions
		if info, statErr := os.Stat(path); statErr == nil {
			perm := info.Mode().Perm()
			if perm&0077 != 0 {
				fmt.Fprintf(os.Stderr, "WARNING: config file %s has permissive permissions %04o -- recommend 0600\n", path, perm)
			}
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
