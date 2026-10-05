package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/pkg/schema"
)

func TestValidateLibraryExportRejectsActiveRuleType(t *testing.T) {
	doc := &schema.LibraryExport{
		Version: 1,
		Items: []schema.LibraryItem{{
			Type: "rule",
			ID:   "active-rule",
			Name: "Active Rule",
		}},
	}
	err := validateLibraryExport(doc)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "rule_template") {
		t.Fatalf("expected rule_template guidance, got %q", err.Error())
	}
}

func TestSyncLibraryFileAppliesExistingYAML(t *testing.T) {
	var got api.LibraryImportRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/library/import" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("missing auth header")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"success":true,"results":[{"type":"rule_template","id":"suspicious-powershell","name":"Suspicious PowerShell","action":"created"}],"created":1}}`))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "library.yaml")
	if err := os.WriteFile(path, []byte(`version: 1
items:
  - type: rule_template
    id: suspicious-powershell
    name: Suspicious PowerShell
    query_type: kql
    query: SecurityEvent
`), 0o644); err != nil {
		t.Fatal(err)
	}

	atomic := true
	if code := syncLibraryFile(server.URL, "test-token", path, "from test", &atomic, nil); code != ExitSuccess {
		t.Fatalf("expected success, got exit code %d", code)
	}
	if got.Message != "from test" {
		t.Fatalf("message = %q", got.Message)
	}
	if got.Atomic == nil || !*got.Atomic {
		t.Fatalf("atomic flag not sent")
	}
	if len(got.Items) != 1 || got.Items[0].Type != "rule_template" {
		t.Fatalf("unexpected items: %#v", got.Items)
	}
}

func TestSyncLibraryFileBootstrapsMissingYAML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/library/export" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("format") != "json" {
			t.Fatalf("expected format=json, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"version":1,"items":[{"type":"guide","id":"credential-access-response","name":"Credential Access Response","body":"## Runbook\nReview sign-ins."}]}}`))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "library.yaml")
	atomic := true
	if code := syncLibraryFile(server.URL, "test-token", path, "", &atomic, nil); code != ExitSuccess {
		t.Fatalf("expected success, got exit code %d", code)
	}
	doc, err := loadLibraryExport(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Items) != 1 || doc.Items[0].Type != "guide" {
		t.Fatalf("unexpected exported document: %#v", doc)
	}
}
