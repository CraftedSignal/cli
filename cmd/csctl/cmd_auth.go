package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/craftedsignal/cli/internal/api"
)

func cmdAuth(url, token string, args []string, clientOpts []api.ClientOption) int {
	fs := flag.NewFlagSet("auth", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "API token")
	fs.Parse(args)

	if *tokenFlag != "" {
		token = *tokenFlag
	}
	if url == "" || token == "" {
		fmt.Println("Not configured")
		fmt.Println("Set URL in .csctl.yaml and token in CSCTL_TOKEN env var")
		return ExitSuccess
	}

	client := api.NewClient(url, token, clientOpts...)
	me, err := client.GetMe()
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
