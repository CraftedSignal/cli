package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
	"github.com/craftedsignal/cli/pkg/schema"
	"gopkg.in/yaml.v3"
)

const defaultLibrarySyncFile = "library.yaml"

func cmdLibraryExport(url, token string, args []string, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("library export", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	outputFlag := fs.String("output", defaultLibrarySyncFile, "Output file path, or - for stdout")
	formatFlag := fs.String("format", "yaml", "Output format: yaml or json")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if *tokenFlag != "" {
		token = *tokenFlag
	}

	client, ok := newLibraryClient(url, token, clientOpts)
	if !ok {
		return ExitError
	}
	payload, err := client.ExportLibrary()
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: library export failed: %v\n", err)
		return ExitError
	}
	if payload.Version == 0 {
		payload.Version = 1
	}
	if err := writeLibraryExport(*outputFlag, *formatFlag, payload); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed write library export: %v\n", err)
		return ExitError
	}
	if *outputFlag != "-" {
		fmt.Printf("Exported %d library items to %s\n", len(payload.Items), *outputFlag)
	}
	return ExitSuccess
}

func cmdLibraryApply(url, token string, args []string, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("library apply", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	inputFlag := fs.String("input", defaultLibrarySyncFile, "Input library YAML path, or - for stdin")
	messageFlag := fs.String("m", "", "Import message")
	atomicFlag := fs.Bool("atomic", true, "Rollback all library item changes if any item fails")
	dryRunFlag := fs.Bool("dry-run", false, "Validate and preview without applying")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if *tokenFlag != "" {
		token = *tokenFlag
	}
	if fs.NArg() > 0 {
		*inputFlag = fs.Arg(0)
	}

	doc, err := loadLibraryExport(*inputFlag)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed load library YAML: %v\n", err)
		return ExitError
	}
	if err := validateLibraryExport(doc); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: invalid library YAML: %v\n", err)
		return ExitError
	}
	if *dryRunFlag {
		printLibraryPreview(doc, *inputFlag)
		return ExitSuccess
	}

	client, ok := newLibraryClient(url, token, clientOpts)
	if !ok {
		return ExitError
	}
	resp, err := client.ImportLibrary(api.LibraryImportRequest{
		Items:   doc.Items,
		Message: *messageFlag,
		Atomic:  atomicFlag,
	})
	if resp != nil {
		printLibraryImportResponse(resp)
	}
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: library apply failed: %v\n", err)
		return ExitError
	}
	if resp == nil || !resp.Success || resp.Errors > 0 || resp.RolledBack {
		return ExitError
	}
	return ExitSuccess
}

func cmdLibraryStatus(url, token string, args []string, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("library status", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if *tokenFlag != "" {
		token = *tokenFlag
	}

	client, ok := newLibraryClient(url, token, clientOpts)
	if !ok {
		return ExitError
	}
	status, err := client.GetLibrarySyncStatus()
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: library status failed: %v\n", err)
		return ExitError
	}
	if len(status.Items) == 0 {
		fmt.Println("No local library items")
		return ExitSuccess
	}
	fmt.Printf("%-15s %-36s %-8s %s\n", "TYPE", "ID", "REV", "NAME")
	for _, item := range status.Items {
		fmt.Printf("%-15s %-36s %-8d %s\n", item.Type, item.ID, item.Revision, item.Name)
	}
	return ExitSuccess
}

func syncLibraryFile(url, token, path, message string, atomic *bool, clientOpts []api.ClientOption) int {
	client, ok := newLibraryClient(url, token, clientOpts)
	if !ok {
		return ExitError
	}

	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			payload, exportErr := client.ExportLibrary()
			if exportErr != nil {
				_, _ = fmt.Fprintf(errOut, "Error: library export failed: %v\n", exportErr)
				return ExitError
			}
			if payload.Version == 0 {
				payload.Version = 1
			}
			if writeErr := writeLibraryExport(path, "yaml", payload); writeErr != nil {
				_, _ = fmt.Fprintf(errOut, "Error: failed write %s: %v\n", path, writeErr)
				return ExitError
			}
			fmt.Printf("Exported %d library items to %s\n", len(payload.Items), path)
			return ExitSuccess
		}
		_, _ = fmt.Fprintf(errOut, "Error: cannot access library file %s: %v\n", path, err)
		return ExitError
	}

	doc, err := loadLibraryExport(path)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed load library YAML: %v\n", err)
		return ExitError
	}
	if err := validateLibraryExport(doc); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: invalid library YAML: %v\n", err)
		return ExitError
	}
	resp, err := client.ImportLibrary(api.LibraryImportRequest{
		Items:   doc.Items,
		Message: message,
		Atomic:  atomic,
	})
	if resp != nil {
		printLibraryImportResponse(resp)
	}
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: library sync failed: %v\n", err)
		return ExitError
	}
	if resp == nil || !resp.Success || resp.Errors > 0 || resp.RolledBack {
		return ExitError
	}
	return ExitSuccess
}

func newLibraryClient(url, token string, clientOpts []api.ClientOption) (*api.Client, bool) {
	if url == "" || token == "" {
		_, _ = fmt.Fprintln(errOut, "Error: URL and token required (set via .csctl.yaml and CSCTL_TOKEN)")
		return nil, false
	}
	return api.NewClient(strings.TrimRight(url, "/"), token, clientOpts...), true
}

func loadLibraryExport(path string) (*schema.LibraryExport, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 10<<20))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var doc schema.LibraryExport
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return &doc, nil
}

func writeLibraryExport(path, format string, doc *schema.LibraryExport) error {
	var (
		data []byte
		err  error
	)
	switch strings.ToLower(format) {
	case "", "yaml", "yml":
		data, err = yaml.Marshal(doc)
	case "json":
		data, err = json.MarshalIndent(doc, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return err
	}
	if path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func validateLibraryExport(doc *schema.LibraryExport) error {
	if doc == nil {
		return errors.New("document is empty")
	}
	if len(doc.Items) == 0 {
		return errors.New("items must contain at least one library item")
	}
	for i, item := range doc.Items {
		switch item.Type {
		case "rule_template", "hunt_template", "guide":
		case "":
			return fmt.Errorf("items[%d].type is required; use rule_template, hunt_template, or guide", i)
		case "rule", "detection":
			return fmt.Errorf("items[%d].type %q is an active rule type; use rule_template for reusable library detections", i, item.Type)
		default:
			return fmt.Errorf("items[%d].type %q is invalid; use rule_template, hunt_template, or guide", i, item.Type)
		}
		if strings.TrimSpace(item.ID) == "" {
			return fmt.Errorf("items[%d].id is required", i)
		}
		if strings.TrimSpace(item.Name) == "" {
			return fmt.Errorf("items[%d].name is required", i)
		}
	}
	return nil
}

func printLibraryPreview(doc *schema.LibraryExport, input string) {
	counts := map[string]int{}
	for _, item := range doc.Items {
		counts[item.Type]++
	}
	fmt.Printf("Validated %d library items from %s\n", len(doc.Items), input)
	fmt.Printf("  rule_template: %d\n", counts["rule_template"])
	fmt.Printf("  hunt_template: %d\n", counts["hunt_template"])
	fmt.Printf("  guide: %d\n", counts["guide"])
}

func printLibraryImportResponse(resp *api.LibraryImportResponse) {
	for _, result := range resp.Results {
		name := result.Name
		if name == "" {
			name = result.ID
		}
		fmt.Printf("  %s %s %s", actionSymbol(result.Action), result.Type, name)
		if result.Error != "" {
			fmt.Printf(" (%s)", result.Error)
		}
		fmt.Println()
	}
	if resp.RolledBack {
		fmt.Println("ROLLED BACK: One or more library items failed, all changes reverted")
	}
	fmt.Printf("\nCreated: %d, Updated: %d, Unchanged: %d, Errors: %d\n", resp.Created, resp.Updated, resp.Unchanged, resp.Errors)
}
