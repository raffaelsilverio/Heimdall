package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent/execution"
	"github.com/raffaelsilverio/Heimdall/internal/config"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/providers"
	"github.com/spf13/cobra"
)

func newAgentCycleCommand() *cobra.Command {
	var actionRunID, providerName, modelName string
	var maxSteps int
	var sendContext, includeMemory, confirmActiveRequests bool
	command := &cobra.Command{
		Use:   "cycle <program-id>",
		Short: "Run a bounded adaptive cycle using only native HTTP HEAD probes",
		Long:  "The model proposes one next action at a time from scope, policy, bounded results, and optional same-program memory. Every action is policy-checked and metered. This is synchronous, not daemon-dispatched. --send-context consents to model egress; --confirm-active-requests consents to in-scope HEAD requests.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !sendContext {
				return errors.New("adaptive planning sends structured program scope/policy to the model; pass --send-context to confirm")
			}
			if !confirmActiveRequests {
				return errors.New("adaptive execution sends active HTTP HEAD requests; pass --confirm-active-requests to continue")
			}
			if _, err := uuid.Parse(actionRunID); err != nil {
				return errors.New("--action-run-id must be a UUID used as this cycle's idempotency key")
			}
			if maxSteps < 1 || maxSteps > 20 {
				return errors.New("--max-steps must be between 1 and 20")
			}
			cfg, err := config.LoadConfig(providerName, modelName)
			if err != nil {
				return fmt.Errorf("load adaptive planner configuration: %w", err)
			}
			if cfg.Model == "" {
				return errors.New("planner model is required; use --model or HEIMDALL_MODEL")
			}
			model, err := providers.New(cfg.Provider, cfg.APIKey)
			if err != nil {
				return err
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			result, err := (execution.Executor{
				Store: database, Registry: recon.NewDefaultAgentActionRegistry(),
			}).RunAdaptive(cmd.Context(), args[0], actionRunID, model, cfg.Model, includeMemory, maxSteps, time.Now().UTC())
			if result.ActionRunID != "" {
				encoded, encodeErr := json.MarshalIndent(result, "", "  ")
				if encodeErr != nil {
					return fmt.Errorf("encode adaptive cycle result: %w", encodeErr)
				}
				if _, writeErr := fmt.Fprintln(cmd.OutOrStdout(), string(encoded)); writeErr != nil {
					return writeErr
				}
			}
			return err
		},
	}
	command.Flags().StringVar(&actionRunID, "action-run-id", "", "Caller-generated UUID used as the cycle idempotency key")
	command.Flags().StringVar(&providerName, "provider", "", "AI provider")
	command.Flags().StringVar(&modelName, "model", "", "AI model")
	command.Flags().IntVar(&maxSteps, "max-steps", 3, "Maximum model decisions/actions in this synchronous cycle (1-20)")
	command.Flags().BoolVar(&sendContext, "send-context", false, "Confirm sending structured scope, policy, and bounded results to the model provider")
	command.Flags().BoolVar(&includeMemory, "include-memory", false, "Also send up to 8 current memory notes from this program")
	command.Flags().BoolVar(&confirmActiveRequests, "confirm-active-requests", false, "Confirm bounded active HTTP HEAD requests to authorized targets")
	_ = command.MarkFlagRequired("action-run-id")
	_ = command.MarkFlagRequired("send-context")
	_ = command.MarkFlagRequired("confirm-active-requests")
	return command
}
