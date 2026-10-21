
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/raffaelsilverio/Heimdall/internal/config"
	"github.com/raffaelsilverio/Heimdall/providers"
	"github.com/spf13/cobra"
)

var (
	providerFlag string
	modelFlag    string
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Send a prompt to an AI model",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		prompt, err := cmd.Flags().GetString("prompt")
		if err != nil {
			return err
		}

		if strings.TrimSpace(prompt) == "" {
			return fmt.Errorf("prompt is required; use --prompt")
		}

		cfg, err := config.LoadConfig(providerFlag, modelFlag)
		if err != nil {
			return fmt.Errorf("load configuration: %w", err)
		}

		if strings.TrimSpace(cfg.Model) == "" {
			return fmt.Errorf("model is required; use --model or HEIMDALL_MODEL")
		}

		provider, err := providers.New(cfg.Provider, cfg.APIKey)
		if err != nil {
			return err
		}

		response, err := provider.Generate(cmd.Context(), providers.Request{
			Model: cfg.Model,
			Messages: []providers.Message{
				{
					Role:    "user",
					Content: prompt,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("generate response: %w", err)
		}

		fmt.Println(response.Content)
		return nil
	},
}

func init() {
	runCmd.Flags().String("prompt", "", "Prompt to send to the model")
	runCmd.Flags().StringVar(&providerFlag, "provider", "", "AI provider")
	runCmd.Flags().StringVar(&modelFlag, "model", "", "AI model")

	rootCmd.AddCommand(runCmd)
}
