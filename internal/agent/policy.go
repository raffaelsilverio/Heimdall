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
	Approvals           []contract.ActionApproval
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
	ProgramID      string                `json:"program_id"`
	ScopeHash      string                `json:"scope_hash"`
	PolicyRevision int64                 `json:"policy_revision"`
	Stage          string                `json:"stage"`
	Tool           string                `json:"tool,omitempty"`
	Class          ActionClass           `json:"class"`
	Impact         contract.ActionImpact `json:"impact,omitempty"`
	Targets        []string              `json:"targets"`
	RequestBudget  int                   `json:"request_budget"`
	ApprovalID     string                `json:"approval_id,omitempty"`
	Limits         recon.StageLimits     `json:"limits"`
	ValidUntil     time.Time             `json:"valid_until"`
	Proposal       ActionProposal        `json:"proposal"`
}

// PolicyDecision is the explicit, auditable result of policy evaluation.
// Candidate is only executable when Decision is ALLOW.
type PolicyDecision struct {
	Decision            contract.Decision     `json:"decision"`
	Reason              string                `json:"reason,omitempty"`
	Impact              contract.ActionImpact `json:"impact,omitempty"`
	ApprovalFingerprint string                `json:"approval_fingerprint,omitempty"`
	ApprovalID          string                `json:"approval_id,omitempty"`
	Candidate           *AuthorizedAction     `json:"candidate,omitempty"`
}

// PolicyDecisionError reports a non-ALLOW decision to callers that only need a
// boolean gate. Callers that must branch on REQUIRE_APPROVAL should use
// Evaluate directly.
type PolicyDecisionError struct {
	Decision contract.Decision
	Reason   string
}

func (err *PolicyDecisionError) Error() string {
	reason := err.Reason
	if reason == "" {
		reason = "action was not allowed by policy"
	}
	return fmt.Sprintf("%s: %s", err.Decision, reason)
}

// IsPolicyDecision reports whether err is a typed non-ALLOW policy decision.
func IsPolicyDecision(err error, decision contract.Decision) bool {
	var policyErr *PolicyDecisionError
	return errors.As(err, &policyErr) && policyErr.Decision == decision
}

// ActionPolicy is the boundary an executor must call immediately before a
// registered tool. It intentionally has no shell or arbitrary-command method.
type ActionPolicy interface {
	Evaluate(context.Context, ActionPolicyContext, ActionProposal, time.Time) (PolicyDecision, error)
	Authorize(context.Context, ActionPolicyContext, ActionProposal, time.Time) (AuthorizedAction, error)
	Revalidate(context.Context, ActionPolicyContext, AuthorizedAction, time.Time) error
}

type ScopeActionPolicy struct{}

func (policy ScopeActionPolicy) Authorize(ctx context.Context, policyContext ActionPolicyContext, proposal ActionProposal, now time.Time) (AuthorizedAction, error) {
	decision, err := policy.Evaluate(ctx, policyContext, proposal, now)
	if err != nil {
		return AuthorizedAction{}, err
	}
	if decision.Decision != contract.DecisionAllow || decision.Candidate == nil {
		return AuthorizedAction{}, &PolicyDecisionError{Decision: decision.Decision, Reason: decision.Reason}
	}
	return *decision.Candidate, nil
}

func (policy ScopeActionPolicy) Evaluate(ctx context.Context, policyContext ActionPolicyContext, proposal ActionProposal, now time.Time) (PolicyDecision, error) {
	if err := ctx.Err(); err != nil {
		return PolicyDecision{}, err
	}
	now = now.UTC()
	if err := validatePolicyContext(policyContext, now); err != nil {
		return denyDecision("", err.Error()), nil
	}
	if proposal.ScopeHash == "" || proposal.ScopeHash != policyContext.Program.ScopeHash {
		return denyDecision("", "action scope hash is missing or stale"), nil
	}
	stage, class, err := policyStageClass(proposal.Stage)
	if err != nil {
		return denyDecision("", err.Error()), nil
	}
	tool, err := normalizeActionTool(proposal.Tool)
	if err != nil {
		return denyDecision("", err.Error()), nil
	}
	impact, ok := contract.ActionImpactForClass(class)
	if !ok {
		return denyDecision("", fmt.Sprintf("action class %q has no impact level", class)), nil
	}
	if err := validatePolicyAllowlist(policyContext.Policy, stage, class); err != nil {
		return denyDecision(impact, err.Error()), nil
	}
	candidate, reason := buildAuthorizedAction(policyContext, proposal, stage, class, impact, tool, now)
	if reason != "" {
		return denyDecision(impact, reason), nil
	}
	fingerprint, err := actionApprovalFingerprint(*candidate)
	if err != nil {
		return denyDecision(impact, err.Error()), nil
	}
	return applyActionApproval(policyContext, candidate, fingerprint, class, now), nil
}

func buildAuthorizedAction(policyContext ActionPolicyContext, proposal ActionProposal, stage string, class ActionClass,
	impact contract.ActionImpact, tool string, now time.Time) (*AuthorizedAction, string) {
	limits, err := policyStageLimits(policyContext, stage)
	if err != nil {
		return nil, err.Error()
	}
	if err := validateUsedBudget(policyContext, proposal); err != nil {
		return nil, err.Error()
	}
	maxTargets := policyContext.Policy.MaxTargetsPerAction
	if limits.MaxTargets < maxTargets {
		maxTargets = limits.MaxTargets
	}
	targets, err := authorizedTargets(policyContext.Program.Scope, stage, proposal.Targets, maxTargets)
	if err != nil {
		return nil, err.Error()
	}
	validUntil := now.Add(time.Minute)
	if policyContext.Program.ExpiresAt.Before(validUntil) {
		validUntil = policyContext.Program.ExpiresAt
	}
	return &AuthorizedAction{
		ProgramID: policyContext.Program.ID, ScopeHash: policyContext.Program.ScopeHash,
		PolicyRevision: policyContext.Policy.Revision, Stage: stage, Tool: tool, Class: class, Impact: impact,
		Targets: targets, RequestBudget: proposal.EstimatedCalls, Limits: limits, ValidUntil: validUntil,
		Proposal: ActionProposal{
			Stage: stage, Tool: tool, ScopeHash: proposal.ScopeHash, Targets: append([]string(nil), proposal.Targets...),
			EstimatedCalls: proposal.EstimatedCalls, Rationale: proposal.Rationale, TaskID: proposal.TaskID,
		},
	}, ""
}

func applyActionApproval(policyContext ActionPolicyContext, candidate *AuthorizedAction, fingerprint string,
	class ActionClass, now time.Time) PolicyDecision {
	decision := PolicyDecision{
		Decision: contract.DecisionAllow, Impact: candidate.Impact, ApprovalFingerprint: fingerprint, Candidate: candidate,
	}
	if !containsActionClass(policyContext.Policy.ApprovalRequiredClasses, class) {
		return decision
	}
	approval, reason := selectActionApproval(policyContext.Approvals, *candidate, fingerprint, now)
	if reason != "" {
		return denyDecision(candidate.Impact, reason)
	}
	if approval == nil {
		decision.Decision = contract.DecisionRequireApproval
		decision.Reason = fmt.Sprintf("action class %q requires a scoped approval; none matches fingerprint %s", class, fingerprint)
		return decision
	}
	if approval.ExpiresAt.Before(candidate.ValidUntil) {
		candidate.ValidUntil = approval.ExpiresAt.UTC()
	}
	candidate.ApprovalID = approval.ID
	decision.ApprovalID = approval.ID
	return decision
}

func denyDecision(impact contract.ActionImpact, reason string) PolicyDecision {
	return PolicyDecision{Decision: contract.DecisionDeny, Reason: reason, Impact: impact}
}

func validatePolicyContext(policyContext ActionPolicyContext, now time.Time) error {
	program := policyContext.Program
	if program.ID == "" {
		return errors.New("action policy requires a program")
	}
	storedScopeHash, err := assessment.ScopeFingerprint(program.Scope)
	if err != nil || storedScopeHash != program.ScopeHash {
		return errors.New("program scope is invalid or its fingerprint is stale")
	}
	if program.Status != assessment.ProgramActive {
		return fmt.Errorf("program is %s", program.Status)
	}
	if !program.ExpiresAt.After(now) {
		return errors.New("program authorization has expired")
	}
	if policyContext.SourceReviewPending {
		return errors.New("program has a pending source review")
	}
	return nil
}

func policyStageClass(raw string) (string, ActionClass, error) {
	stage := strings.ToLower(strings.TrimSpace(raw))
	class, err := actionClassForStage(stage)
	if err != nil {
		return "", "", err
	}
	return stage, class, nil
}

func validatePolicyAllowlist(policy ProgramAgentPolicy, stage string, class ActionClass) error {
	if policy.Revision <= 0 {
		return errors.New("program agent policy revision is required")
	}
	if !containsStage(policy.AllowedStages, stage) || !containsActionClass(policy.AllowedClasses, class) {
		return fmt.Errorf("stage %q / action class %q is not allowlisted for this program", stage, class)
	}
	for _, required := range policy.ApprovalRequiredClasses {
		if !containsActionClass(policy.AllowedClasses, required) {
			return errors.New("program agent policy requires approval for a class it does not allow")
		}
	}
	return nil
}

func policyStageLimits(policyContext ActionPolicyContext, stage string) (recon.StageLimits, error) {
	limits, scheduleEnabled := policyContext.EnabledSchedules[stage]
	if !scheduleEnabled {
		return recon.StageLimits{}, fmt.Errorf("stage %q is not enabled for this program", stage)
	}
	if err := limits.Validate(); err != nil {
		return recon.StageLimits{}, fmt.Errorf("stage %q has invalid or missing limits: %w", stage, err)
	}
	return limits, nil
}

// validateUsedBudget checks the consumed action and request counters against
// the program budgets before a new action is authorized.
func validateUsedBudget(policyContext ActionPolicyContext, proposal ActionProposal) error {
	policy := policyContext.Policy
	if policy.MaxActionsPerRun <= 0 || policy.MaxRequestsPerRun <= 0 ||
		policy.MaxRequestsPerAction <= 0 || policy.MaxTargetsPerAction <= 0 {
		return errors.New("program agent policy has no positive action, request, and target budgets")
	}
	if policyContext.ActionsUsed < 0 || policyContext.ActionsUsed >= policy.MaxActionsPerRun {
		return errors.New("program agent action budget is exhausted")
	}
	if proposal.EstimatedCalls < 1 || proposal.EstimatedCalls > policy.MaxRequestsPerAction ||
		policyContext.RequestsUsed < 0 || policyContext.RequestsUsed+proposal.EstimatedCalls > policy.MaxRequestsPerRun {
		return errors.New("proposed action exceeds the program request budget")
	}
	return nil
}

func (grant AuthorizedAction) ApprovalSubject() (contract.ApprovalSubject, error) {
	return contract.NewApprovalSubject(grant.ProgramID, grant.ScopeHash, grant.PolicyRevision,
		grant.Stage, grant.Tool, grant.Class, grant.Targets, grant.RequestBudget)
}

func actionApprovalFingerprint(grant AuthorizedAction) (string, error) {
	subject, err := grant.ApprovalSubject()
	if err != nil {
		return "", err
	}
	return subject.Fingerprint(), nil
}

// selectActionApproval returns the single usable approval that matches the
// candidate. Ambiguous or tampered records fail closed instead of selecting one.
func selectActionApproval(approvals []contract.ActionApproval, grant AuthorizedAction, fingerprint string, now time.Time) (*contract.ActionApproval, string) {
	var matches []contract.ActionApproval
	for _, approval := range approvals {
		if approval.Fingerprint != fingerprint {
			continue
		}
		if !approval.MatchesGrant(grant.ProgramID, grant.ScopeHash, grant.PolicyRevision, grant.Stage, grant.Tool,
			grant.Class, grant.Targets, grant.RequestBudget) {
			return nil, "an approval matched the fingerprint but not the exact action"
		}
		switch approval.EffectiveStatus(now) {
		case contract.ApprovalApproved:
			matches = append(matches, approval)
		case contract.ApprovalPending:
			return nil, fmt.Sprintf("approval %s is still pending review", approval.ID)
		case contract.ApprovalConsumed:
			return nil, fmt.Sprintf("approval %s was already consumed", approval.ID)
		case contract.ApprovalDenied:
			return nil, fmt.Sprintf("approval %s was denied", approval.ID)
		default:
			return nil, fmt.Sprintf("approval %s has expired", approval.ID)
		}
	}
	if len(matches) == 0 {
		return nil, ""
	}
	if len(matches) > 1 {
		return nil, "multiple approvals match the same action; refusing to choose"
	}
	return &matches[0], ""
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
		refreshed.Tool != grant.Tool || refreshed.Impact != grant.Impact || refreshed.ApprovalID != grant.ApprovalID ||
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
