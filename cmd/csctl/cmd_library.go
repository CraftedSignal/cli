package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/craftedsignal/cli/pkg/library"
)

func cmdLibrary(args []string) int {
	if len(args) == 0 {
		printLibraryUsage()
		return ExitError
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "index":
		return cmdLibraryIndex(subArgs)
	default:
		_, _ = fmt.Fprintf(errOut, "Unknown library subcommand: %s\n", subcmd)
		printLibraryUsage()
		return ExitError
	}
}

func printLibraryUsage() {
	fmt.Fprintf(os.Stderr, `Usage: csctl library <subcommand> [flags]

Subcommands:
  index     Manage library index files

Run 'csctl library <subcommand> -h' for help on a subcommand.
`)
}

func cmdLibraryIndex(args []string) int {
	if len(args) == 0 {
		printLibraryIndexUsage()
		return ExitError
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "generate":
		return cmdLibraryIndexGenerate(subArgs)
	case "sign":
		return cmdLibraryIndexSign(subArgs)
	case "verify":
		return cmdLibraryIndexVerify(subArgs)
	case "keygen":
		return cmdLibraryIndexKeygen(subArgs)
	default:
		_, _ = fmt.Fprintf(errOut, "Unknown index subcommand: %s\n", subcmd)
		printLibraryIndexUsage()
		return ExitError
	}
}

func printLibraryIndexUsage() {
	fmt.Fprintf(os.Stderr, `Usage: csctl library index <subcommand> [flags]

Subcommands:
  generate  Generate a library index from query files
  sign      Sign a library index with an Ed25519 private key
  verify    Verify a library index signature
  keygen    Generate an Ed25519 key pair for signing

Run 'csctl library index <subcommand> -h' for help on a subcommand.
`)
}

func cmdLibraryIndexGenerate(args []string) int {
	fs := flag.NewFlagSet("library index generate", flag.ExitOnError)
	pathFlag := fs.String("path", ".", "Path to directory containing query files")
	outputFlag := fs.String("output", "library.index.yaml", "Output file path")
	nameFlag := fs.String("name", "Library", "Repository name")
	urlFlag := fs.String("url", "", "Repository URL")
	maintainerFlag := fs.String("maintainer", "", "Repository maintainer")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Generate a library index from query files.

Usage: csctl library index generate [flags]

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Example:
  csctl library index generate -path ./queries -output library.index.yaml -name "My Library"
`)
	}

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(*pathFlag)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: invalid path: %v\n", err)
		return ExitError
	}

	// Check if directory exists
	info, err := os.Stat(absPath)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: cannot access path: %v\n", err)
		return ExitError
	}
	if !info.IsDir() {
		_, _ = fmt.Fprintf(errOut, "Error: path is not a directory: %s\n", absPath)
		return ExitError
	}

	fmt.Printf("Scanning %s for query files...\n", absPath)

	// Generate index
	index, err := library.GenerateIndex(absPath, *nameFlag)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to generate index: %v\n", err)
		return ExitError
	}

	// Set optional metadata
	if *urlFlag != "" {
		index.Repository.URL = *urlFlag
	}
	if *maintainerFlag != "" {
		index.Repository.Maintainer = *maintainerFlag
	}

	fmt.Printf("Found %d entries\n", len(index.Entries))

	// Write output
	outFile, err := os.Create(*outputFlag)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to create output file: %v\n", err)
		return ExitError
	}
	defer func() { _ = outFile.Close() }()

	ext := strings.ToLower(filepath.Ext(*outputFlag))
	if ext == ".json" {
		err = index.WriteJSON(outFile)
	} else {
		err = index.WriteYAML(outFile)
	}
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to write index: %v\n", err)
		return ExitError
	}

	fmt.Printf("Index written to %s\n", *outputFlag)
	return ExitSuccess
}

func cmdLibraryIndexSign(args []string) int {
	fs := flag.NewFlagSet("library index sign", flag.ExitOnError)
	inputFlag := fs.String("input", "library.index.yaml", "Input index file")
	outputFlag := fs.String("output", "", "Output file (defaults to input file)")
	keyFlag := fs.String("key", "", "Path to Ed25519 private key file (base64 encoded)")
	keyIDFlag := fs.String("key-id", "", "Key identifier for the signature")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Sign a library index with an Ed25519 private key.

Usage: csctl library index sign [flags]

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Example:
  csctl library index sign -key signing.key -input library.index.yaml -key-id "mykey-2024"
`)
	}

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	if *keyFlag == "" {
		_, _ = fmt.Fprintf(errOut, "Error: -key flag is required\n")
		fs.Usage()
		return ExitError
	}

	// Load index
	index, err := library.LoadIndex(*inputFlag)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to load index: %v\n", err)
		return ExitError
	}

	// Load private key
	privateKey, err := library.LoadPrivateKey(*keyFlag)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to load private key: %v\n", err)
		return ExitError
	}

	// Sign
	if err := index.Sign(privateKey, *keyIDFlag); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to sign index: %v\n", err)
		return ExitError
	}

	// Determine output path
	output := *outputFlag
	if output == "" {
		output = *inputFlag
	}

	// Write signed index
	outFile, err := os.Create(output)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to create output file: %v\n", err)
		return ExitError
	}
	defer func() { _ = outFile.Close() }()

	ext := strings.ToLower(filepath.Ext(output))
	if ext == ".json" {
		err = index.WriteJSON(outFile)
	} else {
		err = index.WriteYAML(outFile)
	}
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to write index: %v\n", err)
		return ExitError
	}

	fmt.Printf("Index signed and written to %s\n", output)
	if *keyIDFlag != "" {
		fmt.Printf("Key ID: %s\n", *keyIDFlag)
	}
	return ExitSuccess
}

func cmdLibraryIndexVerify(args []string) int {
	fs := flag.NewFlagSet("library index verify", flag.ExitOnError)
	inputFlag := fs.String("input", "library.index.yaml", "Input index file")
	pubkeyFlag := fs.String("pubkey", "", "Path to Ed25519 public key file (base64 encoded)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Verify a library index signature.

Usage: csctl library index verify [flags]

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Example:
  csctl library index verify -pubkey signing.pub -input library.index.yaml
`)
	}

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	if *pubkeyFlag == "" {
		_, _ = fmt.Fprintf(errOut, "Error: -pubkey flag is required\n")
		fs.Usage()
		return ExitError
	}

	// Load index
	index, err := library.LoadIndex(*inputFlag)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to load index: %v\n", err)
		return ExitError
	}

	// Load public key
	publicKey, err := library.LoadPublicKey(*pubkeyFlag)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to load public key: %v\n", err)
		return ExitError
	}

	// Verify
	if err := index.Verify(publicKey); err != nil {
		_, _ = fmt.Fprintf(errOut, "❌ Signature verification FAILED: %v\n", err)
		return ExitError
	}

	fmt.Printf("✓ Signature verified successfully\n")
	if index.SigningKey != "" {
		fmt.Printf("  Key ID: %s\n", index.SigningKey)
	}
	fmt.Printf("  Entries: %d\n", len(index.Entries))
	return ExitSuccess
}

func cmdLibraryIndexKeygen(args []string) int {
	fs := flag.NewFlagSet("library index keygen", flag.ExitOnError)
	outputFlag := fs.String("output", "signing", "Output file prefix (creates .key and .pub files)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Generate an Ed25519 key pair for signing library indexes.

Usage: csctl library index keygen [flags]

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Example:
  csctl library index keygen -output signing

This creates signing.key (private) and signing.pub (public) files.
`)
	}

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	// Generate key pair
	publicKey, privateKey, err := library.GenerateKeyPair()
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to generate key pair: %v\n", err)
		return ExitError
	}

	// Save private key
	privateKeyPath := *outputFlag + ".key"
	if err := library.SavePrivateKey(privateKeyPath, privateKey); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to save private key: %v\n", err)
		return ExitError
	}
	fmt.Printf("Private key saved to %s (keep this secret!)\n", privateKeyPath)

	// Save public key
	publicKeyPath := *outputFlag + ".pub"
	if err := library.SavePublicKey(publicKeyPath, publicKey); err != nil {
		_, _ = fmt.Fprintf(errOut, "Error: failed to save public key: %v\n", err)
		return ExitError
	}
	fmt.Printf("Public key saved to %s\n", publicKeyPath)

	// Also print the public key for convenience
	fmt.Printf("\nPublic key (base64):\n%s\n", base64.StdEncoding.EncodeToString(publicKey))

	return ExitSuccess
}
