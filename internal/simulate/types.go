package simulate

import "time"

// AdapterKind distinguishes BAS frameworks (many techniques) from standalone tools (one technique).
type AdapterKind int

const (
	Framework AdapterKind = iota
	Tool
)

func (k AdapterKind) String() string {
	switch k {
	case Framework:
		return "framework"
	case Tool:
		return "tool"
	default:
		return "unknown"
	}
}

// Platform represents a target execution environment.
type Platform string

const (
	Windows Platform = "windows"
	Linux   Platform = "linux"
	MacOS   Platform = "macos"
	AWS     Platform = "aws"
	Azure   Platform = "azure"
	GCP     Platform = "gcp"
)

// ExecMode describes how a technique reaches its target.
type ExecMode int

const (
	Local ExecMode = iota
	RemoteSSH
	RemoteWinRM
	CloudAPI
)

func (m ExecMode) String() string {
	switch m {
	case Local:
		return "local"
	case RemoteSSH:
		return "remote-ssh"
	case RemoteWinRM:
		return "remote-winrm"
	case CloudAPI:
		return "api"
	default:
		return "unknown"
	}
}

// Technique is a single attackable technique exposed by an adapter.
type Technique struct {
	ID        string
	Name      string
	Platforms []Platform
	ExecModes []ExecMode
}

// Filter controls which techniques are returned by List.
type Filter struct {
	TechniqueID string
	Platform    Platform
	Tactic      string
	AdapterName string
}

// ExecutionPlan describes what will be executed and against which target.
type ExecutionPlan struct {
	TechniqueID    string
	AdapterName    string
	Target         string   // host, account, or empty for local
	ExecMode       ExecMode
	CommandPreview string   // human-readable preview of what will run
	EstimatedLogs  []string // log sources expected to fire
}

// ExecutionResult captures the outcome of a technique execution.
type ExecutionResult struct {
	Success   bool
	StartTime time.Time
	EndTime   time.Time
	Stdout    string
	Stderr    string
	ExitCode  int
}
