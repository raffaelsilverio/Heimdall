package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/spf13/cobra"
)

const maxAgentPlanInputBytes = 64 << 10

type agentPlanInput struct {
	Actions []agent.ActionProposal `json:"actions"`
	Tasks   []agent.PlanTask       `json:"tasks"`
}

// resolve returns the dependency-ordered actions for a plan that contains
// either a flat action list or a task graph, never both.
func (input agentPlanInput) resolve() ([]agent.ActionProposal, []agent.PlanTaskSummary, error) {
	if input.Actions != nil && input.Tasks != nil {
		return nil, nil, errors.New("plan input must contain either actions or tasks, not both")
	}
	if input.Actions == nil && input.Tasks == nil {
		return nil, nil, errors.New("plan input is missing the actions or tasks array")
	}
	if input.Tasks == nil {
		return input.Actions, nil, nil
	}
	return agent.OrderPlanTasks(input.Tasks)
}

func newAgentPlanCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "plan <program-id>",
		Short: "Validate a proposed action plan against one program's policy",
		Long:  "Reads a JSON proposal from stdin and returns a policy dry-run. It makes no LLM calls and executes no tools.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxAgentPlanInputBytes+1))
			if err != nil {
				return fmt.Errorf("read plan proposal: %w", err)
			}
			if len(body) > maxAgentPlanInputBytes {
				return fmt.Errorf("plan proposal exceeds %d bytes", maxAgentPlanInputBytes)
			}
			var input agentPlanInput
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil {
				return fmt.Errorf("decode plan proposal JSON: %w", err)
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				if err == nil {
					return errors.New("plan proposal must contain exactly one JSON value")
				}
				return fmt.Errorf("read trailing plan proposal data: %w", err)
			}
			actions, tasks, err := input.resolve()
			if err != nil {
				return err
			}
			if len(actions) == 0 || len(actions) > 20 {
				return errors.New("plan proposal must contain between 1 and 20 actions")
			}

			policyContext, err := loadActionPolicyContext(cmd, args[0])
			if err != nil {
				return err
			}
			result, err := (agent.PolicyAwarePlanner{Policy: agent.ScopeActionPolicy{}}).ValidatePlan(
				cmd.Context(), policyContext, agent.PlanDraft{Actions: actions, Tasks: tasks}, nowUTC(),
			)
			if err != nil {
				return err
			}
			encoded, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("encode plan validation: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
			return err
		},
	}
	return command
}

func nowUTC() time.Time {
	return time.Now().UTC()
}

// loadActionPolicyContext reads the current program, policy, source-review
// state and enabled schedules into one validation context.
func loadActionPolicyContext(cmd *cobra.Command, programID string) (agent.ActionPolicyContext, error) {
	database, err := openStore(cmd)
	if err != nil {
		return agent.ActionPolicyContext{}, err
	}
	defer database.Close()
	program, err := database.GetProgram(cmd.Context(), programID)
	if err != nil {
		return agent.ActionPolicyContext{}, err
	}
	policy, err := database.GetProgramAgentPolicy(cmd.Context(), program.ID)
	if err != nil {
		return agent.ActionPolicyContext{}, err
	}
	pendingReview, err := database.HasPendingProgramSourceReview(cmd.Context(), program.ID)
	if err != nil {
		return agent.ActionPolicyContext{}, err
	}
	schedules, err := database.ListStageSchedules(cmd.Context(), program.ID)
	if err != nil {
		return agent.ActionPolicyContext{}, err
	}
	enabledSchedules := make(map[string]recon.StageLimits)
	for _, schedule := range schedules {
		if schedule.Enabled {
			enabledSchedules[schedule.Stage] = schedule.Limits
		}
	}
	return agent.ActionPolicyContext{
		Program: program, SourceReviewPending: pendingReview, EnabledSchedules: enabledSchedules, Policy: policy,
	}, nil
}
