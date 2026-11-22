package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The CLI has no parser-model JSON command. Its real validate command exposes
// the naming defect as a false downstream field-not-in-scope warning.
func TestWave5KQLValidateAggregateOutput(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"documented default", `Events | summarize buildschema(value) | where isnotnull(schema_value)`},
		{"explicit alias", `Events | summarize Schema=buildschema(value) | where isnotnull(Schema)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "schema.yaml")
			rule := "title: Schema output\nplatform: sentinel\nquery: " + tc.query + "\n"
			if err := os.WriteFile(file, []byte(rule), 0600); err != nil {
				t.Fatal(err)
			}
			stdout, err := os.CreateTemp(t.TempDir(), "stdout")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stdout.Close() })
			var stderr bytes.Buffer
			code := func() int {
				previousOut, previousErr := os.Stdout, errOut
				os.Stdout, errOut = stdout, &stderr
				defer func() { os.Stdout, errOut = previousOut, previousErr }()
				return cmdValidate(nil, nil, dir)
			}()
			output, err := os.ReadFile(stdout.Name())
			if err != nil {
				t.Fatal(err)
			}
			want := "  ok " + file + "\n\n1 files valid\n"
			if code != ExitSuccess || stderr.Len() != 0 || string(output) != want {
				t.Fatalf("valid aggregate output acquired a false CLI diagnostic: code=%d stderr=%q\ngot: %q\nwant: %q", code, stderr.String(), output, want)
			}
		})
	}
}
