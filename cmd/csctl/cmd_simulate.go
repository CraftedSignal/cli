package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/internal/config"
	"github.com/craftedsignal/cli/internal/simulate"
	"github.com/craftedsignal/cli/internal/simulate/adapters"
)

// newDefaultRegistry returns a registry with all built-in adapters registered.
func newDefaultRegistry() *simulate.Registry {
	reg := simulate.NewRegistry()
	adapters.RegisterAll(reg)
	return reg
}

func cmdSimulate(url, token string, args []string, cfg *config.Config, clientOpts []api.ClientOption, rulePath string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintf(errOut, `Usage: csctl simulate <subcommand> [flags]

Subcommands:
  adapters   List installed adapters and availability
  list       List available techniques (filterable)
  plan       Show execution plan for a technique (dry-run detail)
  run        Execute a simulation (dry-run by default, --live to execute)
  status     Check simulation run status
  cleanup    Clean up simulation artifacts
`)
		return ExitError
	}

	reg := newDefaultRegistry()

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "adapters":
		return cmdSimulateAdapters(reg)
	case "list":
		return cmdSimulateList(reg, subArgs)
	case "plan":
		return cmdSimulatePlan(reg, subArgs)
	case "run":
		return cmdSimulateRun(url, token, reg, subArgs, clientOpts, rulePath)
	case "status":
		return cmdSimulateStatus(url, token, subArgs, clientOpts)
	case "cleanup":
		return cmdSimulateCleanup(reg, subArgs)
	default:
		_, _ = fmt.Fprintf(errOut, "Unknown simulate subcommand: %s\n", sub)
		return ExitError
	}
}

func cmdSimulateAdapters(reg *simulate.Registry) int {
	adapters := reg.All()
	if len(adapters) == 0 {
		fmt.Println("No adapters installed")
		return ExitSuccess
	}

	fmt.Printf("%-20s %-12s %s\n", "NAME", "KIND", "AVAILABLE")
	fmt.Printf("%-20s %-12s %s\n", strings.Repeat("-", 20), strings.Repeat("-", 12), strings.Repeat("-", 9))
	for _, a := range adapters {
		avail := "no"
		if a.Available() {
			avail = "yes"
		}
		fmt.Printf("%-20s %-12s %s\n", a.Name(), a.Kind(), avail)
	}
	return ExitSuccess
}

func cmdSimulateList(reg *simulate.Registry, args []string) int {
	fs := flag.NewFlagSet("simulate list", flag.ExitOnError)
	adapterFlag := fs.String("adapter", "", "Filter by adapter name")
	techniqueFlag := fs.String("technique", "", "Filter by technique ID")
	tacticFlag := fs.String("tactic", "", "Filter by MITRE tactic")
	platformFlag := fs.String("platform", "", "Filter by platform (windows, linux, macos, aws, azure, gcp)")

	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
		return ExitError
	}

	filter := simulate.Filter{
		AdapterName: *adapterFlag,
		TechniqueID: *techniqueFlag,
		Tactic:      *tacticFlag,
	}
	if *platformFlag != "" {
		filter.Platform = simulate.Platform(*platformFlag)
	}

	adapters := reg.All()
	if len(adapters) == 0 {
		fmt.Println("No adapters installed")
		return ExitSuccess
	}

	var count int
	for _, a := range adapters {
		if *adapterFlag != "" && a.Name() != *adapterFlag {
			continue
		}
		techs, err := a.List(filter)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "Error listing techniques from %s: %v\n", a.Name(), err)
			continue
		}
		for _, t := range techs {
			platforms := make([]string, len(t.Platforms))
			for i, p := range t.Platforms {
				platforms[i] = string(p)
			}
			fmt.Printf("  %-16s %-40s [%s] (%s)\n", t.ID, t.Name, strings.Join(platforms, ", "), a.Name())
			count++
		}
	}

	if count == 0 {
		fmt.Println("No techniques found matching filters")
	} else {
		fmt.Printf("\n%d techniques found\n", count)
	}
	return ExitSuccess
}

func cmdSimulatePlan(reg *simulate.Registry, args []string) int {
	fs := flag.NewFlagSet("simulate plan", flag.ExitOnError)
	adapterFlag := fs.String("adapter", "", "Adapter to use")
	targetFlag := fs.String("target", "", "Target host or environment")

	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
		return ExitError
	}

	if fs.NArg() == 0 {
		_, _ = fmt.Fprintln(errOut, "Error: technique ID required")
		_, _ = fmt.Fprintln(errOut, "Usage: csctl simulate plan [flags] <technique-id>")
		return ExitError
	}
	techniqueID := fs.Arg(0)

	adapter, exitCode := resolveAdapter(reg, techniqueID, *adapterFlag)
	if exitCode != ExitSuccess {
		return exitCode
	}

	plan, err := adapter.Plan(techniqueID)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to build plan: %v\n", err)
		return ExitError
	}

	if *targetFlag != "" {
		plan.Target = *targetFlag
	}

	printPlan(plan)
	return ExitSuccess
}

func cmdSimulateRun(url, token string, reg *simulate.Registry, args []string, clientOpts []api.ClientOption, rulePath string) int {
	fs := flag.NewFlagSet("simulate run", flag.ExitOnError)
	live := fs.Bool("live", false, "Execute the simulation (default is dry-run)")
	debug := fs.Bool("debug", false, "Show detailed execution output (stdout/stderr)")
	allowAll := fs.Bool("allow-all", false, "Override scope restrictions")
	adapterFlag := fs.String("adapter", "", "Adapter to use")
	targetFlag := fs.String("target", "", "Target host or environment")
	scopeFlag := fs.String("scope", "", "Path to scope YAML file")
	timeoutFlag := fs.Duration("timeout", 5*time.Minute, "Execution timeout")
	skipCorrelation := fs.Bool("skip-correlation", false, "Skip detection correlation after execution")
	cleanupFlag := fs.Bool("cleanup", true, "Run cleanup after execution")
	ruleFlag := fs.String("rule", "", "Detection rule ID — fetches its techniques and runs them all")
	targetDetectionFlag := fs.String("target-detection", "", "Internal: detection ID to directly correlate with")

	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
		return ExitError
	}

	// --rule mode: fetch techniques from the platform and run each one
	if *ruleFlag != "" {
		if url == "" || token == "" {
			_, _ = fmt.Fprintln(errOut, "Error: --rule requires platform credentials (set CSCTL_URL and CSCTL_TOKEN)")
			return ExitError
		}
		client := api.NewClient(url, token, clientOpts...)
		techniques, err := client.GetDetectionTechniques(*ruleFlag)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "Error: failed to fetch rule techniques: %v\n", err)
			return ExitError
		}
		if len(techniques) == 0 {
			_, _ = fmt.Fprintln(errOut, "Error: rule has no MITRE techniques tagged")
			return ExitError
		}
		fmt.Printf("Rule has %d technique(s): %v\n", len(techniques), techniques)
		exitCode := ExitSuccess
		for _, tid := range techniques {
			// Rebuild args: strip --rule, inject --target-detection, append technique ID
			var runArgs []string
			for _, a := range args {
				if a == "--rule" || a == *ruleFlag {
					continue
				}
				if len(a) > 7 && a[:7] == "--rule=" {
					continue
				}
				runArgs = append(runArgs, a)
			}
			runArgs = append(runArgs, "--target-detection="+*ruleFlag, tid)
			if code := cmdSimulateRun(url, token, reg, runArgs, clientOpts, rulePath); code != ExitSuccess {
				exitCode = code
			}
		}
		return exitCode
	}

	if fs.NArg() == 0 {
		_, _ = fmt.Fprintln(errOut, "Error: technique ID required")
		_, _ = fmt.Fprintln(errOut, "Usage: csctl simulate run [flags] <technique-id>")
		_, _ = fmt.Fprintln(errOut, "       csctl simulate run [flags] --rule <detection-id>")
		return ExitError
	}
	techniqueID := fs.Arg(0)

	// Load scope if provided
	var scope *simulate.ScopeConfig
	if *scopeFlag != "" {
		var err error
		scope, err = simulate.LoadScope(*scopeFlag)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
			return ExitError
		}
	}

	adapter, exitCode := resolveAdapter(reg, techniqueID, *adapterFlag)
	if exitCode != ExitSuccess {
		return exitCode
	}

	// Check scope
	if scope != nil && !*allowAll {
		if !scope.IsAllowed(techniqueID, adapter.Name()) {
			_, _ = fmt.Fprintf(errOut, "Error: technique %s with adapter %s is not allowed by scope\n", techniqueID, adapter.Name())
			_, _ = fmt.Fprintln(errOut, "Use --allow-all to override scope restrictions")
			return ExitError
		}
	}

	plan, err := adapter.Plan(techniqueID)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to build plan: %v\n", err)
		return ExitError
	}

	if *targetFlag != "" {
		plan.Target = *targetFlag
	}

	// Dry-run: show plan and exit
	if !*live {
		fmt.Println("DRY RUN - use --live to execute")
		fmt.Println()
		printPlan(plan)
		return ExitSuccess
	}

	// Live execution
	if !adapter.Available() {
		_, _ = fmt.Fprintf(errOut, "Error: adapter %s is not available (tool not installed?)\n", adapter.Name())
		return ExitError
	}

	if *debug {
		printPlan(plan)
		fmt.Println()
	}

	fmt.Printf("Executing %s via %s...\n", techniqueID, adapter.Name())
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	result, err := adapter.Execute(ctx, plan)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: execution failed: %v\n", err)
		return ExitError
	}

	fmt.Printf("Execution completed (exit code %d, duration %s)\n",
		result.ExitCode, result.EndTime.Sub(result.StartTime).Round(time.Second))

	if *debug && result.Stdout != "" {
		fmt.Printf("\n--- stdout ---\n%s\n", result.Stdout)
	}
	if result.Stderr != "" {
		if *debug {
			fmt.Printf("--- stderr ---\n")
		}
		_, _ = fmt.Fprintf(errOut, "%s\n", result.Stderr)
	}

	// Report to platform
	if url == "" || token == "" {
		if !*skipCorrelation {
			fmt.Println("\nSkipping platform reporting: no URL/token configured")
			fmt.Println("Set url in .csctl.yaml and CSCTL_TOKEN to report runs for detection correlation")
		}
	} else if !*skipCorrelation {
		client := api.NewClient(url, token, clientOpts...)

		// Sync adapter catalog to platform (best-effort, don't block execution)
		if client != nil {
			go func() {
				techniques, err := adapter.List(simulate.Filter{})
				if err != nil {
					return
				}
				var scenarios []api.ScenarioSync
				for _, t := range techniques {
					for _, p := range t.Platforms {
						modes := make([]string, len(t.ExecModes))
						for i, m := range t.ExecModes {
							modes[i] = m.String()
						}
						plan, _ := adapter.Plan(t.ID)
						cmdPreview := ""
						if plan != nil {
							cmdPreview = plan.CommandPreview
						}
						scenarios = append(scenarios, api.ScenarioSync{
							TechniqueID:    t.ID,
							TechniqueName:  t.Name,
							Adapter:        adapter.Name(),
							Platform:       string(p),
							ExecModes:      modes,
							CommandPreview: cmdPreview,
						})
					}
				}
				_ = client.SyncScenarios(scenarios)
			}()
		}

		// Find technique name
		techName := techniqueID
		techs, _ := adapter.List(simulate.Filter{TechniqueID: techniqueID})
		for _, t := range techs {
			if t.ID == techniqueID {
				techName = t.Name
				break
			}
		}

		// Resolve target for reporting: use the machine hostname for local
		// execution, or plan.Target for remote modes (SSH, WinRM, cloud API).
		reportTarget := plan.Target
		if plan.ExecMode == simulate.Local || reportTarget == "" {
			if h, err := os.Hostname(); err == nil {
				reportTarget = h
			} else {
				reportTarget = runtime.GOOS + "/" + runtime.GOARCH
			}
		}

		req := api.CreateSimulationRunRequest{
			TechniqueID:   techniqueID,
			TechniqueName: techName,
			Adapter:       adapter.Name(),
			ExecMode:      plan.ExecMode.String(),
			Target:        reportTarget,
			OS:            runtime.GOOS + "/" + runtime.GOARCH,
			StartedAt:     result.StartTime.UTC().Format(time.RFC3339),
			CompletedAt:   result.EndTime.UTC().Format(time.RFC3339),
			ExecutionLog:  result.Stdout,
		}
		for _, obs := range plan.Observables {
			req.Observables = append(req.Observables, struct {
				Field string `json:"field"`
				Value string `json:"value"`
			}{Field: obs.Field, Value: obs.Value})
		}
		if *targetDetectionFlag != "" {
			req.TargetDetectionID = *targetDetectionFlag
		}
		run, err := client.CreateSimulationRun(req)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "Warning: failed to report run to platform: %v\n", err)
		} else {
			fmt.Printf("Reported as run %s, triggering verification...\n", run.ID)

			if err := client.TriggerVerification(run.ID); err != nil {
				_, _ = fmt.Fprintf(errOut, "Warning: failed to trigger verification: %v\n", err)
			} else {
				// Poll for results
				verifiedRun := pollVerification(client, run.ID)
				if verifiedRun != nil {
					printResults(verifiedRun)
				}
			}
		}
	}

	// Cleanup
	if *cleanupFlag {
		fmt.Println("Running cleanup...")
		if err := adapter.Cleanup(ctx, plan); err != nil {
			_, _ = fmt.Fprintf(errOut, "Warning: cleanup failed: %v\n", err)
		} else {
			fmt.Println("Cleanup complete")
		}
	}

	if !result.Success {
		return ExitError
	}
	return ExitSuccess
}

func cmdSimulateStatus(url, token string, args []string, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("simulate status", flag.ExitOnError)
	runIDFlag := fs.String("run-id", "", "Simulation run ID")

	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
		return ExitError
	}

	runIDStr := *runIDFlag
	if runIDStr == "" && fs.NArg() > 0 {
		runIDStr = fs.Arg(0)
	}
	if runIDStr == "" {
		_, _ = fmt.Fprintln(errOut, "Error: run ID required (--run-id or positional argument)")
		return ExitError
	}

	if url == "" || token == "" {
		_, _ = fmt.Fprintln(errOut, "Error: URL and token required (set via .csctl.yaml and CSCTL_TOKEN)")
		return ExitError
	}

	client := api.NewClient(url, token, clientOpts...)
	run, err := client.GetSimulationRun(runIDStr)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
		return ExitError
	}

	fmt.Printf("Run %s: %s (%s)\n", run.ID, run.TechniqueName, run.TechniqueID)
	fmt.Printf("Adapter: %s\n", run.Adapter)
	fmt.Printf("Status:  %s\n", run.Status)

	if len(run.Results) > 0 {
		fmt.Println()
		printResults(run)
	}

	return ExitSuccess
}

func cmdSimulateCleanup(reg *simulate.Registry, args []string) int {
	fs := flag.NewFlagSet("simulate cleanup", flag.ExitOnError)
	adapterFlag := fs.String("adapter", "", "Adapter to use for cleanup")

	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
		return ExitError
	}

	if fs.NArg() == 0 {
		_, _ = fmt.Fprintln(errOut, "Error: technique ID required")
		_, _ = fmt.Fprintln(errOut, "Usage: csctl simulate cleanup [flags] <technique-id>")
		return ExitError
	}
	techniqueID := fs.Arg(0)

	adapter, exitCode := resolveAdapter(reg, techniqueID, *adapterFlag)
	if exitCode != ExitSuccess {
		return exitCode
	}

	plan, err := adapter.Plan(techniqueID)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to build plan: %v\n", err)
		return ExitError
	}

	fmt.Printf("Cleaning up %s via %s...\n", techniqueID, adapter.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := adapter.Cleanup(ctx, plan); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: cleanup failed: %v\n", err)
		return ExitError
	}

	fmt.Println("Cleanup complete")
	return ExitSuccess
}

// resolveAdapter finds the right adapter for a technique, considering an optional name hint.
func resolveAdapter(reg *simulate.Registry, techniqueID, adapterName string) (simulate.BASAdapter, int) {
	if adapterName != "" {
		a := reg.Get(adapterName)
		if a == nil {
			_, _ = fmt.Fprintf(errOut, "Error: adapter %q not found\n", adapterName)
			return nil, ExitError
		}
		return a, ExitSuccess
	}

	adapters := reg.ForTechnique(techniqueID)
	if len(adapters) == 0 {
		_, _ = fmt.Fprintf(errOut, "Error: no adapters found for technique %s\n", techniqueID)
		return nil, ExitError
	}

	// Prefer the first available adapter.
	for _, a := range adapters {
		if a.Available() {
			return a, ExitSuccess
		}
	}

	// Nothing available — show what exists so the user can install one.
	names := make([]string, len(adapters))
	for i, a := range adapters {
		names[i] = a.Name()
	}
	_, _ = fmt.Fprintf(errOut, "Error: adapters for %s (%s) are all unavailable\n", techniqueID, strings.Join(names, ", "))
	return nil, ExitError
}

// printPlan displays an execution plan in human-readable format.
func printPlan(plan *simulate.ExecutionPlan) {
	fmt.Printf("Technique: %s\n", plan.TechniqueID)
	fmt.Printf("Adapter:   %s\n", plan.AdapterName)
	fmt.Printf("Mode:      %s\n", plan.ExecMode)
	if plan.Target != "" {
		fmt.Printf("Target:    %s\n", plan.Target)
	}
	if plan.CommandPreview != "" {
		fmt.Printf("Command:   %s\n", plan.CommandPreview)
	}
	if len(plan.EstimatedLogs) > 0 {
		fmt.Printf("Expected logs: %s\n", strings.Join(plan.EstimatedLogs, ", "))
	}
}

// pollVerification polls the platform for verification results.
func pollVerification(client *api.Client, runID string) *api.SimulationRun {
	const maxPolls = 24 // 2 minutes at 5s intervals
	const pollInterval = 5 * time.Second

	for range maxPolls {
		time.Sleep(pollInterval)

		run, err := client.PollVerification(runID)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "Warning: poll failed: %v\n", err)
			return nil
		}

		if run.Status == "verified" || run.Status == "completed" {
			return run
		}

		if run.Status == "error" || run.Status == "failed" {
			_, _ = fmt.Fprintf(errOut, "Verification failed (status: %s)\n", run.Status)
			return run
		}
	}

	_, _ = fmt.Fprintln(errOut, "Warning: verification timed out after 2 minutes")
	return nil
}

// printResults displays simulation results in a formatted table.
func printResults(run *api.SimulationRun) {
	fmt.Println("Results:")
	fmt.Printf("  %-35s %-10s %-8s %s\n", "Detection", "SIEM", "Method", "Result")
	fmt.Printf("  %s\n", strings.Repeat("\u2500", 65))

	matched := 0
	for _, r := range run.Results {
		label := r.DetectionTitle
		if r.DetectionID != "" {
			label = fmt.Sprintf("%s (%s)", r.DetectionTitle, r.DetectionID)
		}

		result := "\u2717 missed"
		if r.Matched {
			result = "\u2713 matched"
			matched++
		}
		if r.ErrorMessage != "" {
			result = fmt.Sprintf("! %s", r.ErrorMessage)
		}

		fmt.Printf("  %-35s %-10s %-8s %s\n", label, r.SiemName, r.MatchMethod, result)
	}

	total := len(run.Results)
	pct := 0
	if total > 0 {
		pct = matched * 100 / total
	}
	fmt.Printf("\nCoverage: %d/%d detections fired (%d%%)\n", matched, total, pct)
}
