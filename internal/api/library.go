package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/craftedsignal/cli/pkg/schema"
)

type LibraryImportRequest struct {
	Items   []schema.LibraryItem `json:"items"`
	Message string               `json:"message"`
	Atomic  *bool                `json:"atomic,omitempty"`
}

type LibraryImportResponse struct {
	Success    bool                  `json:"success"`
	RolledBack bool                  `json:"rolled_back,omitempty"`
	Results    []LibraryImportResult `json:"results"`
	Created    int                   `json:"created"`
	Updated    int                   `json:"updated"`
	Unchanged  int                   `json:"unchanged"`
	Errors     int                   `json:"errors"`
}

type LibraryImportResult struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Action string `json:"action"`
	Error  string `json:"error,omitempty"`
}

type LibrarySyncStatus struct {
	Items []LibrarySyncStatusItem `json:"items"`
}

type LibrarySyncStatusItem struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Hash      string `json:"hash"`
	Revision  int    `json:"revision"`
	UpdatedAt string `json:"updated_at"`
}

func (c *Client) ExportLibrary() (*schema.LibraryExport, error) {
	resp, err := c.do(http.MethodGet, "/api/v1/library/export?format=json", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("export library failed (status %d): %s", resp.StatusCode, string(body))
	}
	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed parse response (status %d): %w", resp.StatusCode, err)
	}
	var result schema.LibraryExport
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed parse library export (status %d): %w", resp.StatusCode, err)
	}
	return &result, nil
}

func (c *Client) ImportLibrary(req LibraryImportRequest) (*LibraryImportResponse, error) {
	resp, err := c.do(http.MethodPost, "/api/v1/library/import", req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("import library failed (status %d): %s", resp.StatusCode, string(body))
	}
	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed parse response (status %d): %w", resp.StatusCode, err)
	}
	var result LibraryImportResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed parse library import response (status %d): %w", resp.StatusCode, err)
	}
	return &result, nil
}

func (c *Client) GetLibrarySyncStatus() (*LibrarySyncStatus, error) {
	resp, err := c.do(http.MethodGet, "/api/v1/library/sync-status", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("get library sync status failed (status %d): %s", resp.StatusCode, string(body))
	}
	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed parse response (status %d): %w", resp.StatusCode, err)
	}
	var result LibrarySyncStatus
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed parse library sync status (status %d): %w", resp.StatusCode, err)
	}
	return &result, nil
}
