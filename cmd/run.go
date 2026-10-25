package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/config"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/raffaelsilverio/Heimdall/providers"
	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	var providerFlag string
	var modelFlag string
	var promptFlag string
	var sessionID string
	command := &cobra.Command{
		Use:   "run",
		Short: "Send a prompt to an AI model",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(promptFlag) == "" {
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
			messages := []providers.Message{{Role: "user", Content: promptFlag}}
			var database *store.Store
			if strings.TrimSpace(sessionID) != "" {
				database, err = openStore(cmd)
				if err != nil {
					return err
				}
				defer database.Close()
				conversation, err := database.GetSession(cmd.Context(), sessionID)
				if err != nil {
					return err
				}
				if conversation.Kind != "interactive" {
					return fmt.Errorf("session %s is not an interactive session", sessionID)
				}
				if conversation.Status != "open" {
					return fmt.Errorf("session %s is %s", sessionID, conversation.Status)
				}
				if _, err := database.AppendSessionMessage(cmd.Context(), sessionID, "user", promptFlag, "", "", nil, time.Now().UTC()); err != nil {
					return err
				}
				history, err := database.ListSessionMessages(cmd.Context(), sessionID, 100)
				if err != nil {
					return err
				}
				messages = make([]providers.Message, 0, len(history))
				for _, message := range history {
					if message.Role == "system" || message.Role == "user" || message.Role == "assistant" {
						messages = append(messages, providers.Message{Role: message.Role, Content: message.Content})
					}
				}
			}
			response, err := provider.Generate(cmd.Context(), providers.Request{
				Model:    cfg.Model,
				Messages: messages,
			})
			if err != nil {
				return fmt.Errorf("generate response: %w", err)
			}
			if database != nil {
				if _, err := database.AppendSessionMessage(cmd.Context(), sessionID, "assistant", response.Content, provider.Name(), cfg.Model, nil, time.Now().UTC()); err != nil {
					return fmt.Errorf("save assistant response to session: %w", err)
				}
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), response.Content)
			return err
		},
	}
	command.Flags().StringVar(&promptFlag, "prompt", "", "Prompt to send to the model")
	command.Flags().StringVar(&providerFlag, "provider", "", "AI provider")
	command.Flags().StringVar(&modelFlag, "model", "", "AI model")
	command.Flags().StringVar(&sessionID, "session", "", "Persist this turn in an interactive session")
	return command
}
