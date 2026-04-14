package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	craftedsignal "github.com/craftedsignal/sdk-go"
)

func cmdAuth(url, token string, args []string, clientOpts []craftedsignal.Option) int {
	fs := flag.NewFlagSet("auth", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	_ = fs.Parse(args)

	if *tokenFlag != "" {
		token = *tokenFlag
	}
	if url == "" || token == "" {
		fmt.Println("Not configured")
		fmt.Println("Set URL in .csctl.yaml and token in CSCTL_TOKEN env var")
		return ExitSuccess
	}

	client, err := craftedsignal.NewClient(token, clientOpts...)
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return ExitError
	}
	me, err := client.Me(context.Background())
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return ExitError
	}

	fmt.Printf("Authenticated to %s\n", url)
	fmt.Printf("  Company:  %s\n", me.Company)
	fmt.Printf("  API Key:  %s\n", me.APIKeyName)
	fmt.Printf("  Scopes:   %s\n", strings.Join(me.Scopes, ", "))
	return ExitSuccess
}
