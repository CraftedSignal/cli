package adapters

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// embeddedAtomics holds a minimal vendored subset of the official Atomic Red
// Team test catalog (one file per technique the atomic adapter lists), in the
// upstream redcanaryco/atomic-red-team schema and directory layout. The full
// catalog can be supplied at runtime via CSCTL_ATOMICS_PATH (see loadAtomicFile).
//
//go:embed atomics
var embeddedAtomics embed.FS

// atomicArg is one input_argument; only the default is needed for substitution.
type atomicArg struct {
	Default string `yaml:"default"`
}

// atomicExecutor mirrors the subset of the atomic `executor` block we run.
type atomicExecutor struct {
	Name              string `yaml:"name"`
	Command           string `yaml:"command"`
	CleanupCommand    string `yaml:"cleanup_command"`
	ElevationRequired bool   `yaml:"elevation_required"`
}

// atomicTest is a single test case within a technique file.
type atomicTest struct {
	Name               string               `yaml:"name"`
	SupportedPlatforms []string             `yaml:"supported_platforms"`
	InputArguments     map[string]atomicArg `yaml:"input_arguments"`
	Executor           atomicExecutor       `yaml:"executor"`
}

// atomicFile is one Txxxx.yaml technique definition.
type atomicFile struct {
	AttackTechnique string       `yaml:"attack_technique"`
	DisplayName     string       `yaml:"display_name"`
	AtomicTests     []atomicTest `yaml:"atomic_tests"`
}

// loadAtomicFile reads the atomic YAML for a technique. If CSCTL_ATOMICS_PATH is
// set it reads from that on-disk clone (full upstream layout: <base>/atomics/<id>/<id>.yaml);
// otherwise it falls back to the embedded vendored subset.
func loadAtomicFile(technique string) (*atomicFile, error) {
	var data []byte
	var err error
	if base := os.Getenv("CSCTL_ATOMICS_PATH"); base != "" {
		data, err = os.ReadFile(filepath.Join(base, "atomics", technique, technique+".yaml"))
	} else {
		// embed.FS always uses forward slashes regardless of host OS.
		data, err = embeddedAtomics.ReadFile("atomics/" + technique + "/" + technique + ".yaml")
	}
	if err != nil {
		return nil, err
	}
	var af atomicFile
	if err := yaml.Unmarshal(data, &af); err != nil {
		return nil, fmt.Errorf("parse atomic %s: %w", technique, err)
	}
	return &af, nil
}

// atomicOS maps runtime.GOOS to the platform tokens used in atomic YAML.
func atomicOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	default:
		return "linux"
	}
}

// executorRunnable reports whether an atomic executor can run on this host.
func executorRunnable(name string) bool {
	switch name {
	case "sh", "bash":
		return runtime.GOOS != "windows"
	case "command_prompt":
		return runtime.GOOS == "windows"
	case "powershell":
		if _, err := exec.LookPath("pwsh"); err == nil {
			return true
		}
		_, err := exec.LookPath("powershell")
		return err == nil
	default:
		return false
	}
}

// pickRunnableTest returns the first test that both supports the current OS and
// has an executor runnable on this host, or nil if none qualifies.
func pickRunnableTest(af *atomicFile) *atomicTest {
	osName := atomicOS()
	for i := range af.AtomicTests {
		t := &af.AtomicTests[i]
		if !containsFold(t.SupportedPlatforms, osName) {
			continue
		}
		if !executorRunnable(t.Executor.Name) {
			continue
		}
		return t
	}
	return nil
}

// substituteAtomicArgs replaces #{name} placeholders with their default values.
func substituteAtomicArgs(s string, args map[string]atomicArg) string {
	for k, v := range args {
		s = strings.ReplaceAll(s, "#{"+k+"}", v.Default)
	}
	return s
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}
