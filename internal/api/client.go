package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
		c.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
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
	Rules   []schema.Detection `json:"rules"`
	Message string             `json:"message"`
	Mode    string             `json:"mode"`
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
	Success   bool           `json:"success"`
	Results   []ImportResult `json:"results"`
	Created   int            `json:"created"`
	Updated   int            `json:"updated"`
	Unchanged int            `json:"unchanged"`
	Conflicts int            `json:"conflicts"`
	Errors    int            `json:"errors"`
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

// ValidateToken checks if the token is valid.
func (c *Client) ValidateToken() error {
	resp, err := c.do("GET", "/api/v1/detections/sync-status", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid or expired token")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}

// GetSyncStatus fetches the current sync status of all rules.
func (c *Client) GetSyncStatus() (*SyncStatusResponse, error) {
	resp, err := c.do("GET", "/api/v1/detections/sync-status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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
		path += "&group=" + group
	}

	resp, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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
func (c *Client) Import(rules []schema.Detection, message, mode string) (*ImportResponse, error) {
	req := ImportRequest{
		Rules:   rules,
		Message: message,
		Mode:    mode,
	}

	resp, err := c.do("POST", "/api/v1/detections/import", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	var result ImportResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
