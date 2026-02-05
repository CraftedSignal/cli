package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/craftedsignal/cli/pkg/schema"
)

// Client is the API client for CraftedSignal platform.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	logger     *slog.Logger
}

// ClientOption configures the client.
type ClientOption func(*Client)

// WithInsecureSkipVerify disables TLS certificate verification.
func WithInsecureSkipVerify() ClientOption {
	return func(c *Client) {
		transport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			transport = &http.Transport{}
		}
		t := transport.Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		c.httpClient.Transport = t
	}
}

// WithLogger sets the logger for the client.
func WithLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// NewClient creates a new API client.
func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// SyncStatusRule represents a rule's sync status.
type SyncStatusRule struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Groups    []string  `json:"groups"`
	Hash      string    `json:"hash"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SyncStatusResponse is the response for sync-status endpoint.
type SyncStatusResponse struct {
	Rules []SyncStatusRule `json:"rules"`
}

// ImportRequest is the request for import endpoint.
type ImportRequest struct {
	Rules     []schema.Detection `json:"rules"`
	Message   string             `json:"message"`
	Mode      string             `json:"mode"`
	Atomic    *bool              `json:"atomic,omitempty"`
	SkipTests bool               `json:"skip_tests,omitempty"`
}

// ImportResult represents a single import result.
type ImportResult struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Action  string `json:"action"`
	Error   string `json:"error,omitempty"`
	Version int    `json:"version"`
}

// ImportResponse is the response for import endpoint.
type ImportResponse struct {
	StatusCode int            `json:"-"` // HTTP status code (not from JSON)
	Success    bool           `json:"success"`
	RolledBack bool           `json:"rolled_back,omitempty"`
	Results    []ImportResult `json:"results"`
	Created    int            `json:"created"`
	Updated    int            `json:"updated"`
	Unchanged  int            `json:"unchanged"`
	Conflicts  int            `json:"conflicts"`
	Errors     int            `json:"errors"`
}

// APIResponse wraps the standard API response format.
type APIResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *APIError       `json:"error,omitempty"`
}

// APIError represents an API error.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *Client) do(method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	c.logger.Debug("API request", slog.String("method", method), slog.String("path", path))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("API request failed", slog.String("method", method), slog.String("path", path), slog.Any("error", err))
		return nil, err
	}

	c.logger.Debug("API response", slog.String("method", method), slog.String("path", path), slog.Int("status", resp.StatusCode))

	return resp, nil
}

// MeResponse represents the authenticated user info.
type MeResponse struct {
	Company    string   `json:"company"`
	APIKeyName string   `json:"api_key_name"`
	Scopes     []string `json:"scopes"`
}

// GetMe returns information about the authenticated API key.
func (c *Client) GetMe() (*MeResponse, error) {
	resp, err := c.do("GET", "/api/v1/me", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid or expired token")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	var result MeResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ValidateToken checks if the token is valid.
func (c *Client) ValidateToken() error {
	_, err := c.GetMe()
	return err
}

// GetSyncStatus fetches the current sync status of all rules.
func (c *Client) GetSyncStatus() (*SyncStatusResponse, error) {
	resp, err := c.do("GET", "/api/v1/detections/sync-status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("failed to get sync status: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	var result SyncStatusResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Export fetches all detections as JSON.
func (c *Client) Export(group string) ([]schema.Detection, error) {
	path := "/api/v1/detections/export?format=json"
	if group != "" {
		path += "&group=" + url.QueryEscape(group)
	}

	resp, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("failed to export: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	var result []schema.Detection
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Import sends rules to the platform.
// If atomic is true (default), the entire import is wrapped in a transaction and rolled back on any error.
func (c *Client) Import(rules []schema.Detection, message, mode string, atomic, skipTests bool) (*ImportResponse, error) {
	req := ImportRequest{
		Rules:     rules,
		Message:   message,
		Mode:      mode,
		Atomic:    &atomic,
		SkipTests: skipTests,
	}

	var resp *http.Response
	var err error
	for attempt := 0; attempt <= 3; attempt++ {
		resp, err = c.do("POST", "/api/v1/detections/import", req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			break
		}
		resp.Body.Close()
		retryAfter := resp.Header.Get("Retry-After")
		wait := parseRetryAfter(retryAfter, time.Duration(attempt+1)*2*time.Second)
		c.logger.Warn("rate limited, retrying", slog.Duration("wait", wait), slog.Int("attempt", attempt+1))
		time.Sleep(wait)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("authentication failed (status %d)", resp.StatusCode)
	}

	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	var result ImportResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse import data (status %d): %w", resp.StatusCode, err)
	}

	result.StatusCode = resp.StatusCode
	return &result, nil
}

// RunTestsRequest is the request for POST /api/v1/detections/test.
type RunTestsRequest struct {
	DetectionIDs []string `json:"detection_ids"`
}

// RunTestsResult represents the test trigger result for a single detection.
type RunTestsResult struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Action     string `json:"action"` // "started", "skipped", "error"
	WorkflowID string `json:"workflow_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RunTestsResponse is the response for POST /api/v1/detections/test.
type RunTestsResponse struct {
	Results []RunTestsResult `json:"results"`
	Started int              `json:"started"`
	Skipped int              `json:"skipped"`
	Errors  int              `json:"errors"`
}

// RunTests triggers test execution for the given detection IDs.
func (c *Client) RunTests(detectionIDs []string) (*RunTestsResponse, error) {
	req := RunTestsRequest{DetectionIDs: detectionIDs}

	resp, err := c.do("POST", "/api/v1/detections/test", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("test request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	var result RunTestsResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse test data (status %d): %w", resp.StatusCode, err)
	}

	return &result, nil
}

// TestFailure represents a single failed test case.
type TestFailure struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // positive, negative
	Error   string `json:"error,omitempty"`
	Matches int    `json:"matches,omitempty"`
}

// TestStatusResult represents the test status of a single detection.
type TestStatusResult struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	TestStatus  string        `json:"test_status"` // no_tests, passing, failing, error, pending
	FailedTests []TestFailure `json:"failed_tests,omitempty"`
}

// TestStatusResponse is the response for GET /api/v1/detections/test-status.
type TestStatusResponse struct {
	Results []TestStatusResult `json:"results"`
	Passed  int                `json:"passed"`
	Failed  int                `json:"failed"`
	Pending int                `json:"pending"`
}

// GetTestStatus polls the test status for the given detection IDs.
func (c *Client) GetTestStatus(detectionIDs []string) (*TestStatusResponse, error) {
	ids := ""
	for i, id := range detectionIDs {
		if i > 0 {
			ids += ","
		}
		ids += id
	}

	resp, err := c.do("GET", "/api/v1/detections/test-status?ids="+ids, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("test status request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	var result TestStatusResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse test status (status %d): %w", resp.StatusCode, err)
	}

	return &result, nil
}

// DeployRequest is the request for POST /api/v1/detections/deploy.
type DeployRequest struct {
	DetectionIDs  []string `json:"detection_ids"`
	OverrideTests bool     `json:"override_tests"`
}

// DeployResult represents the result of deploying a single detection.
type DeployResult struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Action string `json:"action"` // "deployed", "error"
	Error  string `json:"error,omitempty"`
}

// DeployResponse is the response for POST /api/v1/detections/deploy.
type DeployResponse struct {
	Results  []DeployResult `json:"results"`
	Deployed int            `json:"deployed"`
	Failed   int            `json:"failed"`
}

// Deploy triggers deployment for the given detection IDs.
func (c *Client) Deploy(detectionIDs []string, overrideTests bool) (*DeployResponse, error) {
	req := DeployRequest{DetectionIDs: detectionIDs, OverrideTests: overrideTests}

	resp, err := c.do("POST", "/api/v1/detections/deploy", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("deploy failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("deploy failed: %s", apiResp.Error.Message)
	}

	var result DeployResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse deploy data (status %d): %w", resp.StatusCode, err)
	}

	return &result, nil
}

func parseRetryAfter(header string, fallback time.Duration) time.Duration {
	if header == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		wait := time.Until(t)
		if wait > 0 {
			return wait
		}
	}
	return fallback
}
