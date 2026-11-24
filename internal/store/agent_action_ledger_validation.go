package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

type agentExecutionSnapshot struct {
	ProgramStatus   string
	ScopeHash       string
	Scope           assessment.Scope
	AuthorizationID string
	ExpiresAt       time.Time
	PendingReview   bool
	Policy          contract.ProgramAgentPolicy
}

type serializedAgentActionGrant struct {
	ProgramID      string                `json:"program_id"`
	ScopeHash      string                `json:"scope_hash"`
	PolicyRevision int64                 `json:"policy_revision"`
	Stage          string                `json:"stage"`
	Tool           string                `json:"tool,omitempty"`
	Class          contract.ActionClass  `json:"class"`
	Impact         contract.ActionImpact `json:"impact,omitempty"`
	Targets        []string              `json:"targets"`
	RequestBudget  int                   `json:"request_budget"`
	ApprovalID     string                `json:"approval_id,omitempty"`
	Limits         recon.StageLimits     `json:"limits"`
	ValidUntil     time.Time             `json:"valid_until"`
	Proposal       struct {
		Stage          string   `json:"stage"`
		Tool           string   `json:"tool,omitempty"`
		ScopeHash      string   `json:"scope_hash"`
		Targets        []string `json:"targets"`
		EstimatedCalls int      `json:"estimated_calls"`
		Rationale      string   `json:"rationale,omitempty"`
	} `json:"proposal"`
}

func loadAgentExecutionSnapshot(ctx context.Context, queryer agentPolicyQueryRower, programID string) (agentExecutionSnapshot, error) {
	var snapshot agentExecutionSnapshot
	var expiresAtNS int64
	var pending int
	var scopeJSON string
	var stagesJSON, classesJSON, approvalClassesJSON string
	var policy contract.ProgramAgentPolicy
	err := queryer.QueryRowContext(ctx, `SELECT p.status, p.scope_hash, p.scope_json, a.id, a.expires_at_ns,
		EXISTS(SELECT 1 FROM program_source_snapshots ps WHERE ps.program_id = p.id AND ps.status = 'pending'),
		ap.revision, ap.allowed_stages_json, ap.allowed_classes_json, ap.approval_required_classes_json,
		ap.max_actions_per_run, ap.max_requests_per_run, ap.max_requests_per_action, ap.max_targets_per_action
		FROM programs p JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
		JOIN program_agent_policies ap ON ap.program_id = p.id WHERE p.id = ?`, programID).
		Scan(&snapshot.ProgramStatus, &snapshot.ScopeHash, &scopeJSON, &snapshot.AuthorizationID, &expiresAtNS, &pending,
			&policy.Revision, &stagesJSON, &classesJSON, &approvalClassesJSON, &policy.MaxActionsPerRun,
			&policy.MaxRequestsPerRun, &policy.MaxRequestsPerAction, &policy.MaxTargetsPerAction)
	if errors.Is(err, sql.ErrNoRows) {
		return agentExecutionSnapshot{}, fmt.Errorf("program %q has no current authorization or agent policy", programID)
	}
	if err != nil {
		return agentExecutionSnapshot{}, fmt.Errorf("load current agent execution snapshot: %w", err)
	}
	if err := json.Unmarshal([]byte(scopeJSON), &snapshot.Scope); err != nil {
		return agentExecutionSnapshot{}, fmt.Errorf("decode current program scope: %w", err)
	}
	fingerprint, err := assessment.ScopeFingerprint(snapshot.Scope)
	if err != nil || fingerprint != snapshot.ScopeHash {
		return agentExecutionSnapshot{}, errors.New("current program scope is invalid or its fingerprint is stale")
	}
	snapshot.ExpiresAt = time.Unix(0, expiresAtNS).UTC()
	snapshot.PendingReview = pending != 0
	if err := json.Unmarshal([]byte(stagesJSON), &policy.AllowedStages); err != nil {
		return agentExecutionSnapshot{}, fmt.Errorf("decode current allowed agent stages: %w", err)
	}
	if err := json.Unmarshal([]byte(classesJSON), &policy.AllowedClasses); err != nil {
		return agentExecutionSnapshot{}, fmt.Errorf("decode current allowed agent classes: %w", err)
	}
	if err := json.Unmarshal([]byte(approvalClassesJSON), &policy.ApprovalRequiredClasses); err != nil {
		return agentExecutionSnapshot{}, fmt.Errorf("decode current approval-required agent classes: %w", err)
	}
	normalized, err := contract.NormalizeProgramAgentPolicy(policy)
	if err != nil {
		return agentExecutionSnapshot{}, fmt.Errorf("normalize current agent policy: %w", err)
	}
	snapshot.Policy = normalized
	return snapshot, nil
}

func validateAgentExecutionSnapshot(snapshot agentExecutionSnapshot, now time.Time) error {
	if snapshot.ProgramStatus != "active" {
		return fmt.Errorf("program is %s", snapshot.ProgramStatus)
	}
	if !snapshot.ExpiresAt.After(now.UTC()) {
		return errors.New("program authorization has expired")
	}
	if snapshot.PendingReview {
		return errors.New("program has a pending source review")
	}
	return nil
}

func validateLiveAgentActionRun(ctx context.Context, queryer agentPolicyQueryRower, run AgentActionRun, snapshot agentExecutionSnapshot, now time.Time) error {
	if run.Status != "active" {
		return fmt.Errorf("agent action run is %s", run.Status)
	}
	if err := validateAgentExecutionSnapshot(snapshot, now); err != nil {
		return err
	}
	policy := snapshot.Policy
	if run.ProgramID == "" || run.AuthorizationID != snapshot.AuthorizationID || run.ScopeHash != snapshot.ScopeHash ||
		run.PolicyRevision != policy.Revision || run.MaxActions != policy.MaxActionsPerRun ||
		run.MaxTargetsPerAction != policy.MaxTargetsPerAction {
		return errors.New("program authorization, scope, or agent policy changed after the action run was created")
	}
	if run.AutomationRevision == 0 && (run.MaxRequests != policy.MaxRequestsPerRun || run.MaxRequestsPerAction != policy.MaxRequestsPerAction) {
		return errors.New("program request policy changed after the action run was created")
	}
	if run.AutomationRevision > 0 && (run.MaxRequests <= 0 || run.MaxRequests > policy.MaxRequestsPerRun ||
		run.MaxRequestsPerAction <= 0 || run.MaxRequestsPerAction > policy.MaxRequestsPerAction || run.MaxRequestsPerAction > run.MaxRequests) {
		return errors.New("automated action request cap no longer fits the current per-run policy")
	}
	if run.AutomationRevision > 0 {
		automation, err := loadProgramAgentAutomation(ctx, queryer, run.ProgramID)
		if err != nil {
			return err
		}
		if err := validateAutomationForAgentActionRun(automation, run.AutomationRevision, snapshot, now); err != nil {
			return err
		}
		if run.MaxRequests > automation.MaxRequestsPerDay {
			return errors.New("automated action request cap exceeds the program daily consent limit")
		}
		if (run.PlannerCalls > 0 && (automation.PlannerProvider != run.PlannerProvider || automation.PlannerModel != run.PlannerModel)) ||
			(run.MemoryItemsSent > 0 && !automation.IncludeMemory) {
			return errors.New("program automation egress consent changed during the action run")
		}
	}
	return nil
}

func validateAutomationForAgentActionRun(automation ProgramAgentAutomation, expectedRevision int64, snapshot agentExecutionSnapshot, now time.Time) error {
	if !automation.Enabled || automation.Revision != expectedRevision || !automation.AllowModelContextEgress ||
		!automation.AllowActiveRequests || strings.TrimSpace(automation.PlannerProvider) == "" ||
		automation.PolicyRevision != snapshot.Policy.Revision ||
		strings.TrimSpace(automation.PlannerModel) == "" || automation.ContextEgressExpiresAt == nil ||
		!automation.ContextEgressExpiresAt.After(now.UTC()) || automation.ContextEgressExpiresAt.After(snapshot.ExpiresAt) {
		return errors.New("program automation consent is disabled, stale, or expired")
	}
	if automation.MaxStepsPerCycle < 1 || automation.MaxStepsPerCycle > 20 ||
		automation.MaxStepsPerCycle > snapshot.Policy.MaxActionsPerRun ||
		automation.MaxCyclesPerDay < 1 || automation.MaxCyclesPerDay > 50 ||
		automation.MaxRequestsPerDay < 1 || automation.MaxRequestsPerDay > 10000 ||
		!containsPolicyStage(snapshot.Policy.AllowedStages, recon.StageWeb) ||
		!containsPolicyClass(snapshot.Policy.AllowedClasses, contract.ActionSafeActive) {
		return errors.New("program automation consent no longer fits the current web action policy")
	}
	return nil
}

func validateAgentActionStage(ctx context.Context, tx *sql.Tx, programID string, policy contract.ProgramAgentPolicy, stage string, class contract.ActionClass) (recon.StageLimits, error) {
	registeredClass, ok := contract.ActionClassForStage(stage)
	if !ok || registeredClass != class || !containsPolicyStage(policy.AllowedStages, stage) || !containsPolicyClass(policy.AllowedClasses, class) {
		return recon.StageLimits{}, fmt.Errorf("stage %q / action class %q is not currently allowlisted", stage, class)
	}
	var limits recon.StageLimits
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT enabled, rate_limit_per_second, max_concurrency, max_targets, timeout_seconds
		FROM stage_schedules WHERE program_id = ? AND stage = ?`, programID, stage).
		Scan(&enabled, &limits.RateLimitPerSecond, &limits.MaxConcurrency, &limits.MaxTargets, &limits.TimeoutSeconds); err != nil {
		return recon.StageLimits{}, fmt.Errorf("stage %q is not scheduled for this program: %w", stage, err)
	}
	if enabled != 1 {
		return recon.StageLimits{}, fmt.Errorf("stage %q is disabled for this program", stage)
	}
	if err := limits.Validate(); err != nil {
		return recon.StageLimits{}, fmt.Errorf("stage %q schedule limits are invalid: %w", stage, err)
	}
	return limits, nil
}

func agentReservationMatchesGrant(input ReserveAgentActionParams, grant serializedAgentActionGrant) bool {
	return grant.ProgramID == input.ProgramID && grant.ScopeHash == input.ScopeHash &&
		grant.PolicyRevision == input.PolicyRevision && grant.Stage == input.Stage && grant.Class == input.ActionClass &&
		len(grant.Targets) == input.TargetCount && grant.RequestBudget == input.RequestBudget &&
		grant.ValidUntil.Equal(input.GrantValidUntil) && grant.Limits == input.Limits &&
		grant.Proposal.Stage == input.Stage && grant.Proposal.ScopeHash == input.ScopeHash &&
		grant.Proposal.EstimatedCalls == input.RequestBudget
}

func agentReservationMatchesSnapshot(run AgentActionRun, snapshot agentExecutionSnapshot,
	input ReserveAgentActionParams, limits recon.StageLimits, now time.Time) bool {
	return input.ScopeHash == run.ScopeHash && input.PolicyRevision == run.PolicyRevision &&
		input.Limits == limits && input.RequestBudget <= run.MaxRequestsPerAction &&
		input.RequestBudget <= snapshot.Policy.MaxRequestsPerAction && input.TargetCount <= run.MaxTargetsPerAction &&
		input.TargetCount <= snapshot.Policy.MaxTargetsPerAction && input.TargetCount <= limits.MaxTargets &&
		input.GrantValidUntil.After(now) && !input.GrantValidUntil.After(snapshot.ExpiresAt)
}

func validateSerializedAgentActionGrant(scope assessment.Scope, run AgentActionRun, policy contract.ProgramAgentPolicy, limits recon.StageLimits, grant serializedAgentActionGrant) error {
	if err := validateGrantIdentity(run, policy, limits, grant); err != nil {
		return err
	}
	if err := validateGrantToolAndImpact(policy, grant); err != nil {
		return err
	}
	return validateGrantTargets(scope, run, policy, limits, grant)
}

func validateGrantIdentity(run AgentActionRun, policy contract.ProgramAgentPolicy, limits recon.StageLimits, grant serializedAgentActionGrant) error {
	registeredClass, registered := contract.ActionClassForStage(grant.Stage)
	if !registered || grant.Class != registeredClass {
		return errors.New("serialized action grant no longer matches the run authorization snapshot")
	}
	if !grantMatchesRun(run, grant) || !grantWithinBudgets(run, policy, limits, grant) {
		return errors.New("serialized action grant no longer matches the run authorization snapshot")
	}
	return nil
}

func grantMatchesRun(run AgentActionRun, grant serializedAgentActionGrant) bool {
	return grant.ProgramID == run.ProgramID && grant.ScopeHash == run.ScopeHash &&
		grant.PolicyRevision == run.PolicyRevision && grant.Proposal.ScopeHash == run.ScopeHash &&
		grant.Proposal.Stage == grant.Stage && grant.Stage != "" &&
		grant.Proposal.EstimatedCalls == grant.RequestBudget
}

func grantWithinBudgets(run AgentActionRun, policy contract.ProgramAgentPolicy, limits recon.StageLimits, grant serializedAgentActionGrant) bool {
	return grant.RequestBudget >= 1 && grant.Limits == limits && len(grant.Targets) > 0 &&
		containsPolicyStage(policy.AllowedStages, grant.Stage) && containsPolicyClass(policy.AllowedClasses, grant.Class) &&
		grant.RequestBudget <= run.MaxRequestsPerAction && grant.RequestBudget <= policy.MaxRequestsPerAction
}

func validateGrantToolAndImpact(policy contract.ProgramAgentPolicy, grant serializedAgentActionGrant) error {
	if grant.Tool != "" && grant.Proposal.Tool != "" && grant.Tool != grant.Proposal.Tool {
		return errors.New("serialized action grant tool fields disagree")
	}
	if grant.Impact != "" {
		expectedImpact, ok := contract.ActionImpactForClass(grant.Class)
		if !ok || grant.Impact != expectedImpact {
			return errors.New("serialized action grant impact does not match its action class")
		}
	}
	if containsPolicyClass(policy.ApprovalRequiredClasses, grant.Class) && grant.ApprovalID == "" {
		return errors.New("serialized action grant is missing the approval required by policy")
	}
	if grant.ApprovalID != "" && !containsPolicyClass(policy.ApprovalRequiredClasses, grant.Class) {
		return errors.New("serialized action grant uses an approval for a class that no longer requires one")
	}
	return nil
}

func validateGrantTargets(scope assessment.Scope, run AgentActionRun, policy contract.ProgramAgentPolicy, limits recon.StageLimits, grant serializedAgentActionGrant) error {
	maxTargets := policy.MaxTargetsPerAction
	if limits.MaxTargets < maxTargets {
		maxTargets = limits.MaxTargets
	}
	if len(grant.Targets) > maxTargets || len(grant.Targets) > run.MaxTargetsPerAction {
		return errors.New("serialized action grant exceeds the current target budget")
	}
	targets, err := contract.AuthorizeTargets(scope, grant.Stage, grant.Proposal.Targets, maxTargets)
	if err != nil {
		return err
	}
	if !sameActionTargets(targets, grant.Targets) {
		return errors.New("serialized action grant targets do not match current program scope")
	}
	return nil
}

func consumeAgentApprovalForGrant(ctx context.Context, tx *sql.Tx, grant serializedAgentActionGrant, now time.Time) error {
	if grant.ApprovalID == "" {
		return nil
	}
	approval, err := loadAgentApproval(ctx, tx, grant.ProgramID, grant.ApprovalID)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("authorized action names an approval that does not exist")
	}
	if err != nil {
		return fmt.Errorf("load action approval: %w", err)
	}
	if status := approval.EffectiveStatus(now); status != contract.ApprovalApproved {
		return fmt.Errorf("action approval %q is %s", grant.ApprovalID, status)
	}
	tool := grant.Tool
	if tool == "" {
		tool = grant.Proposal.Tool
	}
	if !approval.MatchesGrant(grant.ProgramID, grant.ScopeHash, grant.PolicyRevision, grant.Stage, tool,
		grant.Class, grant.Targets, grant.RequestBudget) {
		return errors.New("action approval does not match the authorized grant")
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_approvals SET status = 'consumed', consumed_at = ?, updated_at = ?
		WHERE program_id = ? AND id = ? AND status = 'approved' AND expires_at > ?`,
		now.Unix(), now.Unix(), grant.ProgramID, grant.ApprovalID, now.Unix())
	if err != nil {
		return fmt.Errorf("consume action approval: %w", err)
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return fmt.Errorf("verify action approval consumption: %w", err)
		}
		return errors.New("action approval was already consumed or expired")
	}
	return nil
}

func sameActionTargets(left, right []string) bool {
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

func containsPolicyStage(stages []string, stage string) bool {
	for _, candidate := range stages {
		if strings.EqualFold(strings.TrimSpace(candidate), stage) {
			return true
		}
	}
	return false
}

func containsPolicyClass(classes []contract.ActionClass, class contract.ActionClass) bool {
	for _, candidate := range classes {
		if candidate == class {
			return true
		}
	}
	return false
}
