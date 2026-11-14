package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craftedsignal/cli/internal/config"
)

func TestConfigErrorStopsCommand(t *testing.T) {
	if os.Getenv("CSCTL_CONFIG_ERROR_TEST") == "1" {
		flag.CommandLine = flag.NewFlagSet("csctl", flag.ExitOnError)
		os.Args = []string{"csctl", "version"}
		main()
		return
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".csctl.yaml"), []byte("defaults: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigErrorStopsCommand$")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CSCTL_CONFIG_ERROR_TEST=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("invalid project config must stop the command")
	}
	if !strings.Contains(string(output), "Error: failed to load config:") || strings.Contains(string(output), "csctl dev") {
		t.Fatalf("expected a configuration error before command execution, got %q", output)
	}
}

func TestInsecureFlagPrecedence(t *testing.T) {
	for _, tt := range []struct {
		name       string
		args       []string
		configured bool
		want       bool
	}{
		{name: "explicit false overrides config", args: []string{"--insecure=false"}, configured: true, want: false},
		{name: "explicit true overrides config", args: []string{"--insecure"}, configured: false, want: true},
		{name: "omitted retains config", configured: true, want: true},
		{name: "verified by default", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			value := flags.Bool("insecure", false, "")
			if err := flags.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			if got := resolveInsecure(flags, *value, &config.Config{Insecure: tt.configured}); got != tt.want {
				t.Fatalf("TLS verification override = %v, want %v", got, tt.want)
			}
		})
	}
}
