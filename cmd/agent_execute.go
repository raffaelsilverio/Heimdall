package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/agent/execution"
	"github.com/raffaelsilverio/Heimdall/internal/clock"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/spf13/cobra"
)

func newAgentExecuteCommand() *cobra.Command {
	var actionRunID string
	var confirmActiveRequests bool
	command := &cobra.Command{
		Use:   "execute <program-id>",
		Short: "Execute a bounded policy-authorized native probe plan",
		Long:  "Reads a complete JSON action list from stdin and executes the supplied native probe actions sequentially under one per-run budget. Each action dispatches the reviewed tool named in its `tool` field: one HTTP HEAD per target or one TLS handshake per target. Requires current program authorization, an enabled web schedule, explicit web policy, and --confirm-active-requests. No shell or subprocess tool is available; the executor does not autonomously invent follow-up actions.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmActiveRequests {
				return errors.New("this command sends active native probe requests; pass --confirm-active-requests to continue")
			}
			if _, err := uuid.Parse(actionRunID); err != nil {
				return errors.New("--action-run-id must be a UUID so retries cannot silently replay a run")
			}
			body, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxAgentPlanInputBytes+1))
			if err != nil {
				return fmt.Errorf("read agent action JSON: %w", err)
			}
			if len(body) > maxAgentPlanInputBytes {
				return fmt.Errorf("agent action JSON exceeds %d bytes", maxAgentPlanInputBytes)
			}
			var input agentPlanInput
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil {
				return fmt.Errorf("decode agent action JSON: %w", err)
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				if err == nil {
					return errors.New("agent action input must contain exactly one JSON value")
				}
				return fmt.Errorf("read trailing agent action data: %w", err)
			}
			actions, err := resolveExecutableActions(input)
			if err != nil {
				return err
			}

			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			result, err := (execution.Executor{
				Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}, Clock: clock.System{},
			}).ExecutePlan(cmd.Context(), args[0], actionRunID, actions, time.Now().UTC())
			if result.ActionRunID != "" {
				encoded, encodeErr := json.MarshalIndent(result, "", "  ")
				if encodeErr != nil {
					return fmt.Errorf("encode agent execution result: %w", encodeErr)
				}
				if _, writeErr := fmt.Fprintln(cmd.OutOrStdout(), string(encoded)); writeErr != nil {
					return writeErr
				}
			}
			return err
		},
	}
	command.Flags().StringVar(&actionRunID, "action-run-id", "", "Caller-generated UUID used as the idempotency key for this action run")
	command.Flags().BoolVar(&confirmActiveRequests, "confirm-active-requests", false, "Confirm sending bounded native probe requests (HTTP HEAD or TLS handshake) to the authorized targets")
	_ = command.MarkFlagRequired("action-run-id")
	_ = command.MarkFlagRequired("confirm-active-requests")
	return command
}

// resolveExecutableActions flattens an action list or task graph and enforces
// the native executor's action-count and stage limits.
func resolveExecutableActions(input agentPlanInput) ([]agent.ActionProposal, error) {
	actions, _, err := input.resolve()
	if err != nil {
		return nil, err
	}
	if len(actions) == 0 || len(actions) > 20 {
		return nil, errors.New("native executor accepts between 1 and 20 actions")
	}
	for _, action := range actions {
		if action.Stage != recon.StageWeb {
			return nil, fmt.Errorf("native probes only support stage %q", recon.StageWeb)
		}
	}
	return actions, nil
}
