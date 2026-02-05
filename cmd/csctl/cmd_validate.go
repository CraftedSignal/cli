package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/craftedsignal/cli/internal/config"
	"github.com/craftedsignal/cli/internal/validate"
	internalyaml "github.com/craftedsignal/cli/internal/yaml"
)

func cmdValidate(args []string, cfg *config.Config, rulePath string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	fs.Parse(args)

	path := strings.TrimRight(rulePath, "/")
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	rules, err := internalyaml.LoadAll(path)
	if err != nil {
		fmt.Fprintf(errOut, "Error: validation failed: %v\n", err)
		return ExitError
	}

	errorCount := 0
	warningCount := 0
	for _, r := range rules {
		result := validate.ValidateRule(r.Rule, r.FilePath)
		if !result.Valid() {
			for _, e := range result.Errors {
				fmt.Printf("  ! %s\n", e)
			}
			errorCount++
		} else {
			fmt.Printf("  ok %s\n", r.FilePath)
		}
		for _, w := range result.Warnings {
			fmt.Printf("  ~ %s\n", w)
			warningCount++
		}
	}

	if errorCount > 0 {
		fmt.Fprintf(errOut, "\n%d files have errors\n", errorCount)
		if warningCount > 0 {
			fmt.Printf("%d warnings\n", warningCount)
		}
		return ExitError
	}

	fmt.Printf("\n%d files valid", len(rules))
	if warningCount > 0 {
		fmt.Printf(", %d warnings", warningCount)
	}
	fmt.Println()
	return ExitSuccess
}
