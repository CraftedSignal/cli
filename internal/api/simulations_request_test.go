package api

import (
	"encoding/json"
	"testing"
)

func TestCreateSimulationRunRequestSendsExecutionStatus(t *testing.T) {
	body, err := json.Marshal(CreateSimulationRunRequest{
		TechniqueID:     "T1105",
		ExecutionStatus: "blocked",
		BlockEvidence:   "download refused with HTTP 403",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["execution_status"] != "blocked" || got["block_evidence"] != "download refused with HTTP 403" {
		t.Fatalf("payload = %s", body)
	}
}
