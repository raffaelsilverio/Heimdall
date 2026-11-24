package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/browser"
	"github.com/spf13/cobra"
)

func newBrowserCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "browser",
		Short: "Inspect the loopback browser worker",
	}
	command.AddCommand(newBrowserHealthCommand())
	return command
}

func newBrowserHealthCommand() *cobra.Command {
	var workerURL string
	var timeout time.Duration
	var jsonOutput bool
	command := &cobra.Command{
		Use:   "health",
		Short: "Perform the authenticated browser worker handshake",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			token := os.Getenv("HEIMDALL_BROWSER_TOKEN")
			if token == "" {
				return fmt.Errorf("HEIMDALL_BROWSER_TOKEN is required")
			}
			client, err := browser.NewClient(browser.Config{BaseURL: workerURL, Token: token, Timeout: timeout})
			if err != nil {
				return err
			}
			health, err := client.Health(cmd.Context())
			if err != nil {
				return err
			}
			if jsonOutput {
				encoded, err := json.MarshalIndent(health, "", "  ")
				if err != nil {
					return fmt.Errorf("encode browser worker health: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Worker protocol: %s\nDriver: %s (%s)\nAvailable: %t\n",
				health.Version, safeSourceText(health.Driver.Name), safeSourceText(health.Driver.Browser), health.Driver.Available)
			return err
		},
	}
	command.Flags().StringVar(&workerURL, "url", "http://127.0.0.1:8090", "Loopback browser worker URL")
	command.Flags().DurationVar(&timeout, "timeout", browser.DefaultTimeout, "Worker request timeout")
	command.Flags().BoolVar(&jsonOutput, "json", false, "Emit the worker health as JSON")
	return command
}
