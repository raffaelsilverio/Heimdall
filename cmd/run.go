package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/raffaelsilverio/Heimdall/providers"
	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	var providerFlag string
	var modelFlag string
	var promptFlag string
	var sessionID string
	var includeMemory bool
	command := &cobra.Command{
		Use:   "run",
		Short: "Send a prompt to an AI model",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if includeMemory && strings.TrimSpace(sessionID) == "" {
				return fmt.Errorf("--include-memory requires --session so memory can be isolated to one program")
			}
			if strings.TrimSpace(promptFlag) == "" {
				return fmt.Errorf("prompt is required; use --prompt")
			}
			cfg, err := loadProviderConfig(cmd, providerFlag, modelFlag)
			if err != nil {
				return fmt.Errorf("load configuration: %w", err)
			}
			if strings.TrimSpace(cfg.Model) == "" {
				return fmt.Errorf("model is required; use --model, HEIMDALL_MODEL or the configured model")
			}
			provider, err := providers.NewWithTimeout(cfg.Provider, cfg.APIKey, cfg.RequestTimeout)
			if err != nil {
				return err
			}
			messages := []providers.Message{{Role: "user", Content: promptFlag}}
			var database *store.Store
			var memoryItems []agent.PlanMemoryItem
			var memoryIDs []string
			var memoryScopeHash string
			var memoryProgramID string
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
				if includeMemory {
					program, err := database.GetProgram(cmd.Context(), conversation.ProgramID)
					if err != nil {
						return err
					}
					if conversation.ScopeHash != program.ScopeHash {
						return fmt.Errorf("session scope is stale; create a session for the current scope before including memory")
					}
					memories, err := database.ListProgramMemories(cmd.Context(), program.ID, 100, time.Now().UTC())
					if err != nil {
						return fmt.Errorf("load current session program memory: %w", err)
					}
					memoryItems, memoryIDs = selectBoundedPlanMemory(program.ID, memories)
					memoryScopeHash = program.ScopeHash
					memoryProgramID = program.ID
				}
				var userMetadata json.RawMessage
				if includeMemory {
					userMetadata, err = json.Marshal(map[string]any{
						"memory_items_sent": len(memoryItems), "memory_ids": memoryIDs,
						"memory_scope_hash": memoryScopeHash, "memory_program_id": memoryProgramID,
					})
					if err != nil {
						return fmt.Errorf("encode memory briefing audit metadata: %w", err)
					}
				}
				if _, err := database.AppendSessionMessage(cmd.Context(), sessionID, "user", promptFlag, "", "", userMetadata, time.Now().UTC()); err != nil {
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
				if includeMemory {
					briefing, err := buildRunMemoryBriefing(conversation.ProgramID, memoryScopeHash, memoryItems)
					if err != nil {
						return err
					}
					messages = append([]providers.Message{briefing}, messages...)
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
	command.Flags().BoolVar(&includeMemory, "include-memory", false, "Send a bounded current-memory briefing for the session's program")
	return command
}
