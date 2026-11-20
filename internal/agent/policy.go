package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

type ActionClass = contract.ActionClass

const (
	ActionPassive    = contract.ActionPassive
	ActionSafeActive = contract.ActionSafeActive
	ActionSensitive  = contract.ActionSensitive
)

type ProgramAgentPolicy = contract.ProgramAgentPolicy

type ActionPolicyContext struct {
	Program             assessment.Program
	SourceReviewPending bool
	EnabledSchedules    map[string]recon.StageLimits
	ActionsUsed         int
	RequestsUsed        int
	MaxProposals        int
	RecentResults       []PlanActionObservation
	Policy              ProgramAgentPolicy
}

type ActionProposal struct {
	Stage          string   `json:"stage"`
	Tool           string   `json:"tool,omitempty"`
	ScopeHash      string   `json:"scope_hash"`
	Targets        []string `json:"targets"`
	EstimatedCalls int      `json:"estimated_calls"`
	Rationale      string   `json:"rationale,omitempty"`
	TaskID         string   `json:"task_id,omitempty"`
}

type AuthorizedAction struct {
	ProgramID      string            `json:"program_id"`
	ScopeHash      string            `json:"scope_hash"`
	PolicyRevision int64             `json:"policy_revision"`
	Stage          string            `json:"stage"`
	Class          ActionClass       `json:"class"`
	Targets        []string          `json:"targets"`
	RequestBudget  int               `json:"request_budget"`
	Limits         recon.StageLimits `json:"limits"`
	ValidUntil     time.Time         `json:"valid_until"`
	Proposal       ActionProposal    `json:"proposal"`
}

// ActionPolicy is the boundary an executor must call immediately before a
// registered tool. It intentionally has no shell or arbitrary-command method.
type ActionPolicy interface {
	Authorize(context.Context, ActionPolicyContext, ActionProposal, time.Time) (AuthorizedAction, error)
	Revalidate(context.Context, ActionPolicyContext, AuthorizedAction, time.Time) error
}

type ScopeActionPolicy struct{}

func (policy ScopeActionPolicy) Authorize(ctx context.Context, policyContext ActionPolicyContext, proposal ActionProposal, now time.Time) (AuthorizedAction, error) {
	if err := ctx.Err(); err != nil {
		return AuthorizedAction{}, err
	}
	now = now.UTC()
	program := policyContext.Program
	if program.ID == "" {
		return AuthorizedAction{}, errors.New("action policy requires a program")
	}
	storedScopeHash, err := assessment.ScopeFingerprint(program.Scope)
	if err != nil || storedScopeHash != program.ScopeHash {
		return AuthorizedAction{}, errors.New("program scope is invalid or its fingerprint is stale")
	}
	if program.Status != assessment.ProgramActive {
		return AuthorizedAction{}, fmt.Errorf("program is %s", program.Status)
	}
	if !program.ExpiresAt.After(now) {
		return AuthorizedAction{}, errors.New("program authorization has expired")
	}
	if policyContext.SourceReviewPending {
		return AuthorizedAction{}, errors.New("program has a pending source review")
	}
	if proposal.ScopeHash == "" || proposal.ScopeHash != program.ScopeHash {
		return AuthorizedAction{}, errors.New("action scope hash is missing or stale")
	}
	if policyContext.Policy.Revision <= 0 {
		return AuthorizedAction{}, errors.New("program agent policy revision is required")
	}
	stage := strings.ToLower(strings.TrimSpace(proposal.Stage))
	class, err := actionClassForStage(stage)
	if err != nil {
		return AuthorizedAction{}, err
	}
	tool, err := normalizeActionTool(proposal.Tool)
	if err != nil {
		return AuthorizedAction{}, err
	}
	if !containsStage(policyContext.Policy.AllowedStages, stage) || !containsActionClass(policyContext.Policy.AllowedClasses, class) {
		return AuthorizedAction{}, fmt.Errorf("stage %q / action class %q is not allowlisted for this program", stage, class)
	}
	limits, scheduleEnabled := policyContext.EnabledSchedules[stage]
	if !scheduleEnabled {
		return AuthorizedAction{}, fmt.Errorf("stage %q is not enabled for this program", stage)
	}
	if err := limits.Validate(); err != nil {
		return AuthorizedAction{}, fmt.Errorf("stage %q has invalid or missing limits: %w", stage, err)
	}
	if policyContext.Policy.MaxActionsPerRun <= 0 || policyContext.Policy.MaxRequestsPerRun <= 0 ||
		policyContext.Policy.MaxRequestsPerAction <= 0 || policyContext.Policy.MaxTargetsPerAction <= 0 {
		return AuthorizedAction{}, errors.New("program agent policy has no positive action, request, and target budgets")
	}
	if err := policy.validateUsedBudget(policyContext, proposal); err != nil {
		return AuthorizedAction{}, err
	}

	maxTargets := policyContext.Policy.MaxTargetsPerAction
	if limits.MaxTargets < maxTargets {
		maxTargets = limits.MaxTargets
	}
	targets, err := authorizedTargets(program.Scope, stage, proposal.Targets, maxTargets)
	if err != nil {
		return AuthorizedAction{}, err
	}
	validUntil := now.Add(time.Minute)
	if program.ExpiresAt.Before(validUntil) {
		validUntil = program.ExpiresAt
	}
	return AuthorizedAction{
		ProgramID: program.ID, ScopeHash: program.ScopeHash, PolicyRevision: policyContext.Policy.Revision,
		Stage: stage, Class: class, Targets: targets, RequestBudget: proposal.EstimatedCalls, Limits: limits,
		ValidUntil: validUntil, Proposal: ActionProposal{
			Stage: stage, Tool: tool, ScopeHash: proposal.ScopeHash, Targets: append([]string(nil), proposal.Targets...),
			EstimatedCalls: proposal.EstimatedCalls, Rationale: proposal.Rationale, TaskID: proposal.TaskID,
		},
	}, nil
}

// validateUsedBudget checks the consumed action and request counters against
// the program budgets before a new action is authorized.
func (policy ScopeActionPolicy) validateUsedBudget(policyContext ActionPolicyContext, proposal ActionProposal) error {
	if policyContext.ActionsUsed < 0 || policyContext.ActionsUsed >= policyContext.Policy.MaxActionsPerRun {
		return errors.New("program agent action budget is exhausted")
	}
	if proposal.EstimatedCalls < 1 || proposal.EstimatedCalls > policyContext.Policy.MaxRequestsPerAction ||
		policyContext.RequestsUsed < 0 || policyContext.RequestsUsed+proposal.EstimatedCalls > policyContext.Policy.MaxRequestsPerRun {
		return errors.New("proposed action exceeds the program request budget")
	}
	return nil
}

func (policy ScopeActionPolicy) Revalidate(ctx context.Context, current ActionPolicyContext, grant AuthorizedAction, now time.Time) error {
	if now.UTC().After(grant.ValidUntil) {
		return errors.New("action grant expired; authorize again")
	}
	if current.Policy.Revision != grant.PolicyRevision {
		return errors.New("program agent policy changed after authorization")
	}
	if current.Program.ID != grant.ProgramID || current.Program.ScopeHash != grant.ScopeHash {
		return errors.New("program or scope changed after action authorization")
	}
	refreshed, err := policy.Authorize(ctx, current, grant.Proposal, now)
	if err != nil {
		return err
	}
	if refreshed.Class != grant.Class || refreshed.Stage != grant.Stage || refreshed.Limits != grant.Limits ||
		refreshed.Proposal.Tool != grant.Proposal.Tool ||
		refreshed.RequestBudget != grant.RequestBudget || !sameStrings(refreshed.Targets, grant.Targets) {
		return errors.New("authorized action no longer matches the current policy")
	}
	return nil
}

func normalizeActionTool(tool string) (string, error) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return recon.AgentHTTPProbeID, nil
	}
	if len(tool) > 64 {
		return "", errors.New("action tool id exceeds 64 bytes")
	}
	for _, character := range tool {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return "", fmt.Errorf("action tool id %q must use lowercase letters, digits, or underscores", tool)
	}
	return tool, nil
}

func actionClassForStage(stage string) (ActionClass, error) {
	class, ok := contract.ActionClassForStage(stage)
	if !ok {
		return "", fmt.Errorf("stage %q is not registered for agent actions", stage)
	}
	return class, nil
}

func authorizedTargets(scope assessment.Scope, stage string, proposed []string, maximum int) ([]string, error) {
	return contract.AuthorizeTargets(scope, stage, proposed, maximum)
}

func containsStage(stages []string, stage string) bool {
	for _, candidate := range stages {
		if strings.EqualFold(strings.TrimSpace(candidate), stage) {
			return true
		}
	}
	return false
}

func containsActionClass(classes []ActionClass, class ActionClass) bool {
	for _, candidate := range classes {
		if candidate == class {
			return true
		}
	}
	return false
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
