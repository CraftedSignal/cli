package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configWorkspace(t *testing.T, contents string) string {
	t.Helper()
	for _, name := range []string{"CSCTL_URL", "CSCTL_TOKEN", "CSCTL_INSECURE", "CSCTL_PATH", "CSCTL_PLATFORM"} {
		t.Setenv(name, "")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".csctl.yaml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "detections")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	return path
}

func TestImplicitProjectConfigRejectsConnectionSettings(t *testing.T) {
	for _, contents := range []string{
		"url: https://example.invalid\n",
		"token: example-token-not-valid\n",
		"insecure: true\n",
	} {
		t.Run(strings.SplitN(contents, ":", 2)[0], func(t *testing.T) {
			configWorkspace(t, contents)
			t.Setenv("CSCTL_TOKEN", "ambient-example-token-not-valid")
			cfg, err := Load()
			if err == nil || cfg != nil {
				t.Fatalf("implicit connection settings must fail before a client can be created: cfg present=%v, err=%v", cfg != nil, err)
			}
			if !strings.Contains(err.Error(), "--config") {
				t.Fatalf("error must explain explicit file selection: %v", err)
			}
		})
	}
}

func TestImplicitProjectDefaultsAndTrustedEnvironment(t *testing.T) {
	configWorkspace(t, "defaults:\n  path: rules/\n  platform: splunk\n")
	t.Setenv("CSCTL_URL", "https://example.invalid")
	t.Setenv("CSCTL_TOKEN", "example-token-not-valid")
	t.Setenv("CSCTL_INSECURE", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://example.invalid" || cfg.Token != "example-token-not-valid" || !cfg.Insecure || cfg.Defaults.Path != "rules/" || cfg.Defaults.Platform != "splunk" {
		t.Fatal("project defaults and explicit environment configuration were not preserved")
	}
}

func TestExplicitConfigPreservesConnectionSettings(t *testing.T) {
	path := configWorkspace(t, "url: https://example.invalid\ntoken: example-token-not-valid\ninsecure: true\n")
	cfg, err := LoadFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://example.invalid" || cfg.Token != "example-token-not-valid" || !cfg.Insecure {
		t.Fatal("explicitly selected configuration was not preserved")
	}
	t.Setenv("CSCTL_URL", "https://override.invalid")
	t.Setenv("CSCTL_TOKEN", "override-example-token-not-valid")
	t.Setenv("CSCTL_INSECURE", "false")
	cfg, err = LoadFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://override.invalid" || cfg.Token != "override-example-token-not-valid" || cfg.Insecure {
		t.Fatal("explicit environment configuration must override the file")
	}
}
