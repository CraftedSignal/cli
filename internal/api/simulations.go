package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CreateSimulationRunRequest is the request for creating a simulation run.
type CreateSimulationRunRequest struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Adapter       string `json:"adapter"`
	ExecMode      string `json:"exec_mode"`
	Target        string `json:"target"`
	OS            string `json:"os"`
	StartedAt     string `json:"started_at"`
	CompletedAt   string `json:"completed_at"`
	ExecutionLog  string `json:"execution_log"`
	Observables []struct {
		Field string `json:"field"`
		Value string `json:"value"`
	} `json:"observables,omitempty"`
	TargetDetectionID string `json:"target_detection_id,omitempty"`
}

// SimulationRun represents a simulation run with optional results.
type SimulationRun struct {
	ID            string             `json:"id"`
	TechniqueID   string             `json:"technique_id"`
	TechniqueName string             `json:"technique_name"`
	Adapter       string             `json:"adapter"`
	Status        string             `json:"status"`
	Results       []SimulationResult `json:"results,omitempty"`
}

// SimulationResult represents the detection match result for a simulation.
type SimulationResult struct {
	DetectionID    string `json:"detection_id"`
	DetectionTitle string `json:"detection_title"`
	SiemID         uint64 `json:"siem_id"`
	SiemName       string `json:"siem_name"`
	MatchMethod    string `json:"match_method"`
	Matched        bool   `json:"matched"`
	MatchCount     int    `json:"match_count"`
	BindingSource  string `json:"binding_source"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

// CoverageReport represents MITRE technique coverage from simulations.
type CoverageReport struct {
	TotalTechniques int                 `json:"total_techniques"`
	SimulatedCount  int                 `json:"simulated_count"`
	DetectedCount   int                 `json:"detected_count"`
	Techniques      []TechniqueCoverage `json:"techniques"`
}

// TechniqueCoverage represents the simulation/detection status of a single technique.
type TechniqueCoverage struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
	Simulated   bool   `json:"simulated"`
	Detected    bool   `json:"detected"`
}

// GapsReport contains techniques that were simulated but not detected.
type GapsReport struct {
	Gaps []SimulationGap `json:"gaps"`
}

// SimulationGap represents a technique that was simulated but not detected.
type SimulationGap struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Adapter       string `json:"adapter"`
	LastRunAt     string `json:"last_run_at"`
}

// ScenarioSync represents a simulation scenario for catalog sync.
type ScenarioSync struct {
	TechniqueID    string   `json:"technique_id"`
	TechniqueName  string   `json:"technique_name"`
	Adapter        string   `json:"adapter"`
	Platform       string   `json:"platform"`
	ExecModes      []string `json:"exec_modes"`
	Description    string   `json:"description"`
	CommandPreview string   `json:"command_preview"`
}

// SyncScenarios syncs the adapter's scenario catalog to the platform.
func (c *Client) SyncScenarios(scenarios []ScenarioSync) error {
	resp, err := c.do("POST", "/api/v1/simulations/scenarios/sync", map[string]any{
		"scenarios": scenarios,
	})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("sync scenarios failed (status %d): %s", resp.StatusCode, body)
	}
	return nil
}

// CreateSimulationRun reports a simulation run to the platform and triggers verification.
func (c *Client) CreateSimulationRun(req CreateSimulationRunRequest) (*SimulationRun, error) {
	resp, err := c.do("POST", "/api/v1/simulations/runs", req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("create simulation run failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	var result SimulationRun
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse simulation run (status %d): %w", resp.StatusCode, err)
	}
	return &result, nil
}

// GetSimulationRun retrieves a single simulation run with its results.
func (c *Client) GetSimulationRun(runID string) (*SimulationRun, error) {
	resp, err := c.do("GET", "/api/v1/simulations/runs/"+runID, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("simulation run %s not found", runID)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("get simulation run failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	var result SimulationRun
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse simulation run (status %d): %w", resp.StatusCode, err)
	}
	return &result, nil
}

// TriggerVerification asks the platform to run detection correlation for a simulation run.
func (c *Client) TriggerVerification(runID string) error {
	resp, err := c.do("POST", "/api/v1/simulations/verify/"+runID, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("trigger verification failed (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// PollVerification polls for verification completion. Returns the run with updated results.
func (c *Client) PollVerification(runID string) (*SimulationRun, error) {
	resp, err := c.do("GET", "/api/v1/simulations/verify/"+runID, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("poll verification failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	var result SimulationRun
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse verification result (status %d): %w", resp.StatusCode, err)
	}
	return &result, nil
}

// GetSimulationCoverage retrieves MITRE coverage data from simulations.
func (c *Client) GetSimulationCoverage() (*CoverageReport, error) {
	resp, err := c.do("GET", "/api/v1/simulations/coverage", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("get coverage failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	var result CoverageReport
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse coverage report (status %d): %w", resp.StatusCode, err)
	}
	return &result, nil
}

// GetSimulationGaps retrieves techniques that were simulated but not detected.
func (c *Client) GetSimulationGaps() (*GapsReport, error) {
	resp, err := c.do("GET", "/api/v1/simulations/gaps", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("get gaps failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
	}

	var result GapsReport
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse gaps report (status %d): %w", resp.StatusCode, err)
	}
	return &result, nil
}
