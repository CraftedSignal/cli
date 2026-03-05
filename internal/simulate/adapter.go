package simulate

import "context"

// BASAdapter is implemented by every BAS tool or framework integration.
type BASAdapter interface {
	// Name returns the short adapter identifier, e.g. "stratus", "atomic".
	Name() string

	// Kind returns whether this adapter wraps a multi-technique framework or a single tool.
	Kind() AdapterKind

	// Available reports whether the underlying tool is installed and accessible.
	Available() bool

	// List returns techniques matching the given filter.
	List(filter Filter) ([]Technique, error)

	// Plan builds an execution plan for a specific technique.
	Plan(techniqueID string) (*ExecutionPlan, error)

	// Execute runs a planned technique. The caller owns cancellation via ctx.
	Execute(ctx context.Context, plan *ExecutionPlan) (*ExecutionResult, error)

	// Cleanup reverses side-effects of a previously executed plan.
	Cleanup(ctx context.Context, plan *ExecutionPlan) error
}
