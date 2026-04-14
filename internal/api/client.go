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
	"time"
)

// Client is the API client for CraftedSignal platform simulation operations.
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
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
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

// detectionTechniquesResponse is a minimal struct for parsing detection techniques.
type detectionTechniquesResponse struct {
	Techniques []string `json:"techniques"`
}

// GetDetectionTechniques fetches the MITRE techniques for a single detection by ID.
func (c *Client) GetDetectionTechniques(detectionID string) ([]string, error) {
	resp, err := c.do("GET", "/api/v1/detections/"+url.PathEscape(detectionID)+"/export", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("failed to get detection: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	var det detectionTechniquesResponse
	if err := json.Unmarshal(apiResp.Data, &det); err != nil {
		return nil, err
	}
	return det.Techniques, nil
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

