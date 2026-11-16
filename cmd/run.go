package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
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
			if strings.TrimSpace(sessionID) != "" {
				database, messages, err = prepareRunSession(cmd, sessionID, promptFlag, includeMemory)
				if err != nil {
					return err
				}
				defer database.Close()
			}
			messages, assistantMetadata, err := fitRunContext(messages, cfg.ContextMaxBytes, database != nil)
			if err != nil {
				return err
			}
			response, err := provider.Generate(cmd.Context(), providers.Request{
				Model:    cfg.Model,
				Messages: messages,
			})
			if err != nil {
				return fmt.Errorf("generate response: %w", err)
			}
			if database != nil {
				if _, err := database.AppendSessionMessage(cmd.Context(), sessionID, "assistant", response.Content, provider.Name(), cfg.Model, assistantMetadata, time.Now().UTC()); err != nil {
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

// fitRunContext trims the conversation to the configured byte budget and
// returns the audit metadata that is stored with the assistant turn.
func fitRunContext(messages []providers.Message, budget int, persistAudit bool) ([]providers.Message, json.RawMessage, error) {
	window, err := agent.FitContextWindow(messages, budget)
	if err != nil {
		return nil, nil, fmt.Errorf("fit model context: %w", err)
	}
	if window.Truncated {
		slog.Info("model context trimmed",
			"dropped_messages", window.DroppedMessages,
			"dropped_bytes", window.DroppedBytes,
			"context_bytes", window.TotalBytes,
			"context_budget_bytes", budget,
		)
	}
	if !persistAudit {
		return window.Messages, nil, nil
	}
	metadata, err := json.Marshal(map[string]any{
		"context_bytes":            window.TotalBytes,
		"context_budget_bytes":     budget,
		"context_dropped_messages": window.DroppedMessages,
		"context_dropped_bytes":    window.DroppedBytes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("encode context audit metadata: %w", err)
	}
	return window.Messages, metadata, nil
}

// prepareRunSession opens the session store and builds the bounded message
// history, including the optional current-memory briefing.
func prepareRunSession(cmd *cobra.Command, sessionID, prompt string, includeMemory bool) (*store.Store, []providers.Message, error) {
	database, err := openStore(cmd)
	if err != nil {
		return nil, nil, err
	}
	messages, err := loadRunSession(cmd, database, sessionID, prompt, includeMemory)
	if err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	return database, messages, nil
}

func loadRunSession(cmd *cobra.Command, database *store.Store, sessionID, prompt string, includeMemory bool) ([]providers.Message, error) {
	conversation, err := database.GetSession(cmd.Context(), sessionID)
	if err != nil {
		return nil, err
	}
	if conversation.Kind != "interactive" {
		return nil, fmt.Errorf("session %s is not an interactive session", sessionID)
	}
	if conversation.Status != "open" {
		return nil, fmt.Errorf("session %s is %s", sessionID, conversation.Status)
	}
	memory, err := loadRunMemory(cmd, database, conversation, includeMemory)
	if err != nil {
		return nil, err
	}
	if _, err := database.AppendSessionMessage(cmd.Context(), sessionID, "user", prompt, "", "", memory.userMetadata, time.Now().UTC()); err != nil {
		return nil, err
	}
	messages, err := loadRunHistory(cmd, database, sessionID)
	if err != nil {
		return nil, err
	}
	if includeMemory {
		briefing, err := buildRunMemoryBriefing(conversation.ProgramID, memory.scopeHash, memory.items)
		if err != nil {
			return nil, err
		}
		messages = append([]providers.Message{briefing}, messages...)
	}
	return messages, nil
}

type runMemory struct {
	items        []agent.PlanMemoryItem
	scopeHash    string
	userMetadata json.RawMessage
}

// loadRunMemory resolves the optional same-program memory briefing and encodes
// the audit metadata stored with the user turn.
func loadRunMemory(cmd *cobra.Command, database *store.Store, conversation store.Session, includeMemory bool) (runMemory, error) {
	if !includeMemory {
		return runMemory{}, nil
	}
	program, err := database.GetProgram(cmd.Context(), conversation.ProgramID)
	if err != nil {
		return runMemory{}, err
	}
	if conversation.ScopeHash != program.ScopeHash {
		return runMemory{}, fmt.Errorf("session scope is stale; create a session for the current scope before including memory")
	}
	memories, err := database.ListProgramMemories(cmd.Context(), program.ID, 100, time.Now().UTC())
	if err != nil {
		return runMemory{}, fmt.Errorf("load current session program memory: %w", err)
	}
	items, ids := selectBoundedPlanMemory(program.ID, memories)
	metadata, err := json.Marshal(map[string]any{
		"memory_items_sent": len(items), "memory_ids": ids,
		"memory_scope_hash": program.ScopeHash, "memory_program_id": program.ID,
	})
	if err != nil {
		return runMemory{}, fmt.Errorf("encode memory briefing audit metadata: %w", err)
	}
	return runMemory{items: items, scopeHash: program.ScopeHash, userMetadata: metadata}, nil
}

// loadRunHistory returns the most recent stored turns that a model accepts.
func loadRunHistory(cmd *cobra.Command, database *store.Store, sessionID string) ([]providers.Message, error) {
	history, err := database.ListSessionMessages(cmd.Context(), sessionID, 100)
	if err != nil {
		return nil, err
	}
	messages := make([]providers.Message, 0, len(history))
	for _, message := range history {
		if message.Role == "system" || message.Role == "user" || message.Role == "assistant" {
			messages = append(messages, providers.Message{Role: message.Role, Content: message.Content})
		}
	}
	return messages, nil
}
