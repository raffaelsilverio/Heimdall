package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

const defaultApprovalWindow = 24 * time.Hour

func newAgentApprovalsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "approvals",
		Short: "Request, approve, deny, and inspect scoped action approvals",
		Long:  "Approvals authorize exactly one operation: program, scope, policy revision, stage, tool, impact, targets, and request budget. They are single-use and expire.",
	}
	command.AddCommand(newAgentApprovalsListCommand(), newAgentApprovalsRequestCommand(),
		newAgentApprovalsApproveCommand(), newAgentApprovalsDenyCommand())
	return command
}

func newAgentApprovalsListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list <program-id>",
		Short: "List approvals for one program",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withProgramStore(cmd, func(database *store.Store) error {
				approvals, err := database.ListAgentApprovals(cmd.Context(), args[0], 200)
				if err != nil {
					return err
				}
				return writeAgentApprovals(cmd.OutOrStdout(), approvals, nowUTC())
			})
		},
	}
}

func newAgentApprovalsRequestCommand() *cobra.Command {
	var requestedBy string
	var expiresAtValue string
	command := &cobra.Command{
		Use:   "request <program-id>",
		Short: "Request scoped approval for an action plan read from stdin",
		Long:  "Reads the same JSON action list or task graph as `agent plan`. Only REQUIRE_APPROVAL actions produce requests; DENY aborts and ALLOW actions need no approval. No tool or request is executed.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return requestAgentApprovals(cmd, args[0], requestedBy, expiresAtValue)
		},
	}
	command.Flags().StringVar(&requestedBy, "by", "", "Operator requesting the approval (recorded for audit)")
	command.Flags().StringVar(&expiresAtValue, "expires-at", "", "RFC3339 approval expiry (default 24h, capped at program authorization expiry)")
	_ = command.MarkFlagRequired("by")
	return command
}

func requestAgentApprovals(cmd *cobra.Command, programID, requestedBy, expiresAtValue string) error {
	requestedBy = strings.TrimSpace(requestedBy)
	if err := contract.ValidateApprovalActor(requestedBy, "requester"); err != nil {
		return err
	}
	subjects, programExpiresAt, err := approvalSubjectsForRequest(cmd, programID)
	if err != nil {
		return err
	}
	if len(subjects) == 0 {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "No action requires approval under the current policy. Nothing was created.")
		return err
	}
	expiresAt, err := approvalExpiry(expiresAtValue, nowUTC(), programExpiresAt)
	if err != nil {
		return err
	}
	if err := validateApprovalRegistry(recon.NewDefaultAgentActionRegistry(), subjects); err != nil {
		return err
	}
	return withProgramStore(cmd, func(database *store.Store) error {
		for _, subject := range subjects {
			approval, err := database.CreateAgentApprovalRequest(cmd.Context(), programID, subject, requestedBy, expiresAt, nowUTC())
			if err != nil {
				return err
			}
			if err := writeRequestedAgentApproval(cmd.OutOrStdout(), approval); err != nil {
				return err
			}
		}
		return nil
	})
}

func approvalSubjectsForRequest(cmd *cobra.Command, programID string) ([]contract.ApprovalSubject, time.Time, error) {
	input, err := readAgentPlanInput(cmd)
	if err != nil {
		return nil, time.Time{}, err
	}
	actions, tasks, err := input.resolve()
	if err != nil {
		return nil, time.Time{}, err
	}
	policyContext, err := loadActionPolicyContext(cmd, programID)
	if err != nil {
		return nil, time.Time{}, err
	}
	result, err := (agent.PolicyAwarePlanner{Policy: agent.ScopeActionPolicy{}}).ValidatePlan(
		cmd.Context(), policyContext, agent.PlanDraft{Actions: actions, Tasks: tasks}, nowUTC(),
	)
	if err != nil {
		return nil, time.Time{}, err
	}
	subjects, err := approvalSubjectsFromPlan(result)
	if err != nil {
		return nil, time.Time{}, err
	}
	return subjects, policyContext.Program.ExpiresAt, nil
}

func validateApprovalRegistry(registry recon.AgentActionRegistry, subjects []contract.ApprovalSubject) error {
	for _, subject := range subjects {
		if err := validateApprovalTool(registry, subject); err != nil {
			return err
		}
	}
	return nil
}

func writeRequestedAgentApproval(output io.Writer, approval contract.ActionApproval) error {
	_, err := fmt.Fprintf(output,
		"Requested approval %s for %s/%s (%s, %d target(s), budget %d), expires %s, fingerprint %s.\n",
		approval.ID, approval.Subject.Stage, approval.Subject.Tool, approval.Subject.Impact,
		len(approval.Subject.Targets), approval.Subject.RequestBudget,
		approval.ExpiresAt.Format(time.RFC3339), approval.Fingerprint)
	return err
}

func newAgentApprovalsApproveCommand() *cobra.Command {
	var reviewer, note string
	command := &cobra.Command{
		Use:   "approve <program-id> <approval-id>",
		Short: "Approve one pending scoped action",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return decideAgentApproval(cmd, args[0], args[1], true, reviewer, note)
		},
	}
	command.Flags().StringVar(&reviewer, "by", "", "Reviewer approving the action (recorded for audit)")
	command.Flags().StringVar(&note, "note", "", "Optional reviewer note")
	_ = command.MarkFlagRequired("by")
	return command
}

func newAgentApprovalsDenyCommand() *cobra.Command {
	var reviewer, note string
	command := &cobra.Command{
		Use:   "deny <program-id> <approval-id>",
		Short: "Deny one pending scoped action",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(note) == "" {
				return errors.New("--note is required to deny an approval")
			}
			return decideAgentApproval(cmd, args[0], args[1], false, reviewer, note)
		},
	}
	command.Flags().StringVar(&reviewer, "by", "", "Reviewer denying the action (recorded for audit)")
	command.Flags().StringVar(&note, "note", "", "Required reason for denying the action")
	_ = command.MarkFlagRequired("by")
	_ = command.MarkFlagRequired("note")
	return command
}

func decideAgentApproval(cmd *cobra.Command, programID, approvalID string, approve bool, reviewer, note string) error {
	return withProgramStore(cmd, func(database *store.Store) error {
		approval, err := database.DecideAgentApproval(cmd.Context(), programID, approvalID, approve, reviewer, note, nowUTC())
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Approval %s is now %s. It remains single-use and expires at %s.\n",
			approval.ID, approval.Status, approval.ExpiresAt.Format(time.RFC3339))
		return err
	})
}

func readAgentPlanInput(cmd *cobra.Command) (agentPlanInput, error) {
	body, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxAgentPlanInputBytes+1))
	if err != nil {
		return agentPlanInput{}, fmt.Errorf("read agent plan JSON: %w", err)
	}
	if len(body) > maxAgentPlanInputBytes {
		return agentPlanInput{}, fmt.Errorf("agent plan JSON exceeds %d bytes", maxAgentPlanInputBytes)
	}
	var input agentPlanInput
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return agentPlanInput{}, fmt.Errorf("decode agent plan JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return agentPlanInput{}, errors.New("agent plan must contain exactly one JSON value")
		}
		return agentPlanInput{}, fmt.Errorf("read trailing agent plan data: %w", err)
	}
	return input, nil
}

func approvalSubjectsFromPlan(result agent.PlanValidation) ([]contract.ApprovalSubject, error) {
	subjects := make([]contract.ApprovalSubject, 0)
	for _, decision := range result.Decisions {
		switch decision.Decision {
		case contract.DecisionDeny:
			return nil, fmt.Errorf("action %q is denied by policy: %s", decision.Proposal.Stage, decision.Reason)
		case contract.DecisionRequireApproval:
			if decision.ApprovalSubject == nil {
				return nil, errors.New("policy requires approval but did not return a canonical approval subject")
			}
			subjects = append(subjects, *decision.ApprovalSubject)
		}
	}
	return subjects, nil
}

func approvalExpiry(raw string, now, programExpiresAt time.Time) (time.Time, error) {
	expiresAt := now.Add(defaultApprovalWindow)
	if strings.TrimSpace(raw) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
		if err != nil {
			return time.Time{}, fmt.Errorf("parse --expires-at: %w", err)
		}
		expiresAt = parsed.UTC()
	}
	if !expiresAt.After(now) {
		return time.Time{}, errors.New("approval expiry must be in the future")
	}
	if programExpiresAt.Before(expiresAt) {
		expiresAt = programExpiresAt.UTC()
	}
	return expiresAt, nil
}

func validateApprovalTool(registry recon.AgentActionRegistry, subject contract.ApprovalSubject) error {
	spec, err := registry.Lookup(subject.Tool)
	if err != nil {
		return err
	}
	if spec.Stage != subject.Stage || spec.Class != string(subject.Class) {
		return fmt.Errorf("tool %q is registered for %s/%s, not %s/%s", subject.Tool, spec.Stage, spec.Class, subject.Stage, subject.Class)
	}
	if subject.RequestBudget > spec.MaxRequests {
		return fmt.Errorf("action budget %d exceeds tool %q limit %d", subject.RequestBudget, subject.Tool, spec.MaxRequests)
	}
	if len(subject.Targets) > spec.MaxTargets {
		return fmt.Errorf("target count %d exceeds tool %q limit %d", len(subject.Targets), subject.Tool, spec.MaxTargets)
	}
	for _, target := range subject.Targets {
		if len(target) > spec.TargetMaxLength() {
			return fmt.Errorf("target exceeds tool %q maximum length %d", subject.Tool, spec.TargetMaxLength())
		}
	}
	return nil
}

func writeAgentApprovals(output io.Writer, approvals []contract.ActionApproval, now time.Time) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tSTATUS\tSTAGE\tTOOL\tCLASS\tIMPACT\tTARGETS\tBUDGET\tREQUESTED BY\tREVIEWED BY\tEXPIRES\tFINGERPRINT"); err != nil {
		return err
	}
	for _, approval := range approvals {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\n",
			approval.ID, approval.EffectiveStatus(now), approval.Subject.Stage, approval.Subject.Tool,
			approval.Subject.Class, approval.Subject.Impact, len(approval.Subject.Targets), approval.Subject.RequestBudget,
			approval.RequestedBy, approval.ReviewedBy, approval.ExpiresAt.Format(time.RFC3339), approval.Fingerprint); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "Approvals: %d. Approvals are single-use and bound to one exact operation; they never authorize a class or a program in general.\n", len(approvals))
	return err
}
