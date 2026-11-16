package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/raffaelsilverio/Heimdall/providers"
	"github.com/spf13/cobra"
)

func newAgentProposeCommand() *cobra.Command {
	var providerName, modelName string
	var sendContext, includeMemory bool
	command := &cobra.Command{
		Use:   "propose <program-id>",
		Short: "Ask a model for a policy-checked plan; never executes it",
		Long:  "Sends the program's current structured scope and action policy to the configured model only when --send-context is present. Memory is never sent unless --include-memory is also present; that flag includes only bounded, current memory for this program. The returned plan is validated and displayed; no tools or scans are run.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !sendContext {
				return errors.New("proposal generation sends program scope context to the configured model; pass --send-context to confirm")
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			program, err := database.GetProgram(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			policy, err := database.GetProgramAgentPolicy(cmd.Context(), program.ID)
			if err != nil {
				return err
			}
			pendingReview, err := database.HasPendingProgramSourceReview(cmd.Context(), program.ID)
			if err != nil {
				return err
			}
			schedules, err := database.ListStageSchedules(cmd.Context(), program.ID)
			if err != nil {
				return err
			}
			enabledSchedules := make(map[string]recon.StageLimits)
			for _, stageSchedule := range schedules {
				if stageSchedule.Enabled {
					enabledSchedules[stageSchedule.Stage] = stageSchedule.Limits
				}
			}
			policyContext := agent.ActionPolicyContext{
				Program: program, SourceReviewPending: pendingReview, EnabledSchedules: enabledSchedules,
				Policy: policy,
			}
			var memory []agent.PlanMemoryItem
			if includeMemory {
				memories, err := database.ListProgramMemories(cmd.Context(), program.ID, 100, time.Now().UTC())
				if err != nil {
					return fmt.Errorf("load current program memory: %w", err)
				}
				memory = boundedPlanMemory(program.ID, memories)
			}
			cfg, err := loadProviderConfig(cmd, providerName, modelName)
			if err != nil {
				return fmt.Errorf("load planner model configuration: %w", err)
			}
			if cfg.Model == "" {
				return errors.New("planner model is required; use --model, HEIMDALL_MODEL or the configured model")
			}
			model, err := providers.New(cfg.Provider, cfg.APIKey)
			if err != nil {
				return err
			}
			validation, err := (agent.PolicyAwarePlanner{Policy: agent.ScopeActionPolicy{}}).
				Propose(cmd.Context(), model, cfg.Model, policyContext, memory, time.Now().UTC())
			if err != nil {
				return err
			}
			result := struct {
				Provider    string               `json:"provider"`
				Model       string               `json:"model"`
				ContextSent bool                 `json:"context_sent_to_model"`
				MemoryItems int                  `json:"memory_items_sent"`
				Plan        agent.PlanValidation `json:"plan"`
			}{Provider: model.Name(), Model: cfg.Model, ContextSent: true, MemoryItems: len(memory), Plan: validation}
			encoded, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("encode model proposal result: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
			return err
		},
	}
	command.Flags().StringVar(&providerName, "provider", "", "AI provider")
	command.Flags().StringVar(&modelName, "model", "", "AI model")
	command.Flags().BoolVar(&sendContext, "send-context", false, "Confirm sending this program's structured scope and policy to the model provider")
	command.Flags().BoolVar(&includeMemory, "include-memory", false, "Also send up to 8 current memory notes from this program (requires --send-context)")
	return command
}

const (
	maxProposalMemoryItems      = 8
	maxProposalMemoryContent    = 1500
	maxProposalMemoryTotalBytes = 8 << 10
)

func boundedPlanMemory(programID string, memories []store.ProgramMemory) []agent.PlanMemoryItem {
	items, _ := selectBoundedPlanMemory(programID, memories)
	return items
}

func selectBoundedPlanMemory(programID string, memories []store.ProgramMemory) ([]agent.PlanMemoryItem, []string) {
	programID = strings.TrimSpace(programID)
	result := make([]agent.PlanMemoryItem, 0, maxProposalMemoryItems)
	ids := make([]string, 0, maxProposalMemoryItems)
	totalBytes := 0
	for _, memory := range memories {
		if len(result) >= maxProposalMemoryItems {
			break
		}
		if memory.ProgramID != programID || memory.Status != "active" || memory.ScopeStale || memory.SourceStale || memory.SourceReviewPending {
			continue
		}
		kind := strings.TrimSpace(memory.Kind)
		title := truncateUTF8(strings.TrimSpace(memory.Title), 200)
		content := truncateUTF8(strings.TrimSpace(memory.Content), maxProposalMemoryContent)
		if kind == "" || title == "" || content == "" {
			continue
		}
		sourceKind := strings.TrimSpace(memory.SourceKind)
		itemBytes := len(kind) + len(title) + len(content) + len(sourceKind)
		if totalBytes+itemBytes > maxProposalMemoryTotalBytes {
			break
		}
		result = append(result, agent.PlanMemoryItem{
			Kind: kind, Title: title, Content: content, SourceKind: sourceKind, Confidence: memory.Confidence,
		})
		ids = append(ids, memory.ID)
		totalBytes += itemBytes
	}
	return result, ids
}

func truncateUTF8(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	const suffix = "…"
	maximum -= len(suffix)
	for maximum > 0 && !utf8.ValidString(value[:maximum]) {
		maximum--
	}
	return value[:maximum] + suffix
}
