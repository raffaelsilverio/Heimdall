package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

const maxAgentActionProposalBytes = 64 << 10

type AgentActionRun struct {
	ID                   string     `json:"id"`
	ProgramID            string     `json:"program_id"`
	AuthorizationID      string     `json:"authorization_id"`
	ScopeHash            string     `json:"scope_hash"`
	PolicyRevision       int64      `json:"policy_revision"`
	MaxActions           int        `json:"max_actions"`
	MaxRequests          int        `json:"max_requests"`
	MaxRequestsPerAction int        `json:"max_requests_per_action"`
	MaxTargetsPerAction  int        `json:"max_targets_per_action"`
	ActionsReserved      int        `json:"actions_reserved"`
	RequestsReserved     int        `json:"requests_reserved"`
	RequestsConsumed     int        `json:"requests_consumed"`
	PlannerProvider      string     `json:"planner_provider,omitempty"`
	PlannerModel         string     `json:"planner_model,omitempty"`
	PlannerCalls         int        `json:"planner_calls"`
	MemoryItemsSent      int        `json:"memory_items_sent"`
	MemoryIDsSent        []string   `json:"memory_ids_sent"`
	AutomationRevision   int64      `json:"automation_revision"`
	Status               string     `json:"status"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	ClosedAt             *time.Time `json:"closed_at,omitempty"`
}

func (s *Store) RecordAgentActionPlannerCall(ctx context.Context, programID, runID, provider, model string, memoryIDs []string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	provider = strings.TrimSpace(provider)
	model = strings.TrimSpace(model)
	if programID == "" || runID == "" || provider == "" || model == "" {
		return errors.New("program, action run, planner provider, and model are required for planner audit")
	}
	if len(provider) > 128 || len(model) > 256 || len(memoryIDs) > 8 {
		return errors.New("planner audit provider/model or memory item list is out of bounds")
	}
	for index := range memoryIDs {
		memoryIDs[index] = strings.TrimSpace(memoryIDs[index])
		if memoryIDs[index] == "" || len(memoryIDs[index]) > 128 {
			return errors.New("planner audit memory ids must contain 1-128 bytes")
		}
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin planner call audit: %w", err)
	}
	defer tx.Rollback()
	run, err := loadAgentActionRun(ctx, tx, programID, runID)
	if err != nil {
		return fmt.Errorf("load action run for planner audit: %w", err)
	}
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, programID)
	if err != nil {
		return err
	}
	if err := validateLiveAgentActionRun(ctx, tx, run, snapshot, now); err != nil {
		return err
	}
	if run.AutomationRevision > 0 {
		automation, err := loadProgramAgentAutomation(ctx, tx, programID)
		if err != nil {
			return err
		}
		if provider != automation.PlannerProvider || model != automation.PlannerModel ||
			(len(memoryIDs) > 0 && !automation.IncludeMemory) {
			return errors.New("planner call exceeds the provider/model or memory egress consent for this program")
		}
	}
	if (run.PlannerProvider != "" && run.PlannerProvider != provider) ||
		(run.PlannerModel != "" && run.PlannerModel != model) {
		return errors.New("planner provider or model changed during the action run")
	}
	run.MemoryIDsSent = append(run.MemoryIDsSent, memoryIDs...)
	if len(run.MemoryIDsSent) > 256 {
		return errors.New("planner memory egress audit exceeds 256 note references")
	}
	memoryIDsJSON, err := json.Marshal(run.MemoryIDsSent)
	if err != nil {
		return fmt.Errorf("encode planner memory egress audit: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET
		planner_provider = ?, planner_model = ?, planner_calls = planner_calls + 1,
		memory_items_sent = memory_items_sent + ?, memory_ids_sent_json = ?, updated_at = ?
		WHERE id = ? AND program_id = ? AND status = 'active'`,
		provider, model, len(memoryIDs), string(memoryIDsJSON), now.Unix(), runID, programID)
	if err != nil {
		return fmt.Errorf("record agent planner call: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify agent planner audit: %w", err)
		}
		return errors.New("active agent action run not found for planner audit")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit planner call audit: %w", err)
	}
	return nil
}

type AgentActionReservation struct {
	ID               string               `json:"id"`
	ActionRunID      string               `json:"action_run_id"`
	ProgramID        string               `json:"program_id"`
	Sequence         int                  `json:"sequence"`
	Stage            string               `json:"stage"`
	ActionClass      contract.ActionClass `json:"action_class"`
	ProposalJSON     string               `json:"authorization_grant_json"`
	ProposalSHA256   string               `json:"authorization_grant_sha256"`
	ResultJSON       string               `json:"result_json"`
	ScopeHash        string               `json:"scope_hash"`
	PolicyRevision   int64                `json:"policy_revision"`
	RequestBudget    int                  `json:"request_budget"`
	RequestsConsumed int                  `json:"requests_consumed"`
	TargetCount      int                  `json:"target_count"`
	Limits           recon.StageLimits    `json:"limits"`
	GrantValidUntil  time.Time            `json:"grant_valid_until"`
	Status           string               `json:"status"`
	LeaseUntil       *time.Time           `json:"lease_until,omitempty"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
	StartedAt        *time.Time           `json:"started_at,omitempty"`
	FinishedAt       *time.Time           `json:"finished_at,omitempty"`
	ReviewDecision   string               `json:"review_decision,omitempty"`
	ReviewedBy       string               `json:"reviewed_by,omitempty"`
	ReviewNote       string               `json:"review_note,omitempty"`
	ReviewedAt       *time.Time           `json:"reviewed_at,omitempty"`
}

type ReserveAgentActionParams struct {
	ID              string
	ActionRunID     string
	ProgramID       string
	Sequence        int
	Stage           string
	ActionClass     contract.ActionClass
	ProposalJSON    []byte
	ScopeHash       string
	PolicyRevision  int64
	RequestBudget   int
	TargetCount     int
	Limits          recon.StageLimits
	GrantValidUntil time.Time
}

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
	ProgramID      string               `json:"program_id"`
	ScopeHash      string               `json:"scope_hash"`
	PolicyRevision int64                `json:"policy_revision"`
	Stage          string               `json:"stage"`
	Class          contract.ActionClass `json:"class"`
	Targets        []string             `json:"targets"`
	RequestBudget  int                  `json:"request_budget"`
	Limits         recon.StageLimits    `json:"limits"`
	ValidUntil     time.Time            `json:"valid_until"`
	Proposal       struct {
		Stage          string   `json:"stage"`
		ScopeHash      string   `json:"scope_hash"`
		Targets        []string `json:"targets"`
		EstimatedCalls int      `json:"estimated_calls"`
		Rationale      string   `json:"rationale,omitempty"`
	} `json:"proposal"`
}

// CreateAgentActionRun snapshots one program's current authorization and
// budgets. Calling it again with the same ID and program is idempotent.
func (s *Store) CreateAgentActionRun(ctx context.Context, runID, programID string, now time.Time) (AgentActionRun, error) {
	return s.createAgentActionRun(ctx, runID, programID, 0, 0, now)
}

func (s *Store) CreateAgentActionRunForAutomation(ctx context.Context, runID, programID string, automationRevision int64, requestBudget int, now time.Time) (AgentActionRun, error) {
	if automationRevision <= 0 || requestBudget <= 0 {
		return AgentActionRun{}, errors.New("positive automation consent revision and request budget are required")
	}
	return s.createAgentActionRun(ctx, runID, programID, automationRevision, requestBudget, now)
}

func (s *Store) createAgentActionRun(ctx context.Context, runID, programID string, automationRevision int64, requestBudget int, now time.Time) (AgentActionRun, error) {
	runID = strings.TrimSpace(runID)
	programID = strings.TrimSpace(programID)
	if _, err := uuid.Parse(runID); err != nil {
		return AgentActionRun{}, errors.New("agent action run id must be a UUID")
	}
	if programID == "" {
		return AgentActionRun{}, errors.New("program id is required for an agent action run")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentActionRun{}, fmt.Errorf("begin agent action run: %w", err)
	}
	defer tx.Rollback()

	if existing, err := loadAgentActionRun(ctx, tx, programID, runID); err == nil {
		if existing.AutomationRevision != automationRevision || (automationRevision > 0 && existing.MaxRequests != requestBudget) {
			return AgentActionRun{}, errors.New("action run id was already used with a different automation mode or request budget")
		}
		if err := tx.Commit(); err != nil {
			return AgentActionRun{}, fmt.Errorf("commit idempotent agent action run lookup: %w", err)
		}
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return AgentActionRun{}, fmt.Errorf("load existing agent action run: %w", err)
	}

	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, programID)
	if err != nil {
		return AgentActionRun{}, err
	}
	if err := validateAgentExecutionSnapshot(snapshot, now); err != nil {
		return AgentActionRun{}, err
	}
	if automationRevision > 0 {
		automation, err := loadProgramAgentAutomation(ctx, tx, programID)
		if err != nil {
			return AgentActionRun{}, err
		}
		if err := validateAutomationForAgentActionRun(automation, automationRevision, snapshot, now); err != nil {
			return AgentActionRun{}, err
		}
		if requestBudget > automation.MaxRequestsPerDay || requestBudget > snapshot.Policy.MaxRequestsPerRun {
			return AgentActionRun{}, errors.New("automated cycle request budget exceeds current daily or per-run limit")
		}
	}
	policy := snapshot.Policy
	if policy.MaxActionsPerRun <= 0 || policy.MaxRequestsPerRun <= 0 || policy.MaxRequestsPerAction <= 0 || policy.MaxTargetsPerAction <= 0 {
		return AgentActionRun{}, errors.New("deny-all agent policy cannot create an action run")
	}
	run := AgentActionRun{
		ID: runID, ProgramID: programID, AuthorizationID: snapshot.AuthorizationID, ScopeHash: snapshot.ScopeHash,
		PolicyRevision: policy.Revision, MaxActions: policy.MaxActionsPerRun, MaxRequests: policy.MaxRequestsPerRun,
		MaxRequestsPerAction: policy.MaxRequestsPerAction, MaxTargetsPerAction: policy.MaxTargetsPerAction,
		AutomationRevision: automationRevision, Status: "active", CreatedAt: now, UpdatedAt: now,
	}
	if automationRevision > 0 {
		run.MaxRequests = requestBudget
		if run.MaxRequestsPerAction > requestBudget {
			run.MaxRequestsPerAction = requestBudget
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_action_runs(
		id, program_id, authorization_id, scope_hash, policy_revision, max_actions, max_requests,
		max_requests_per_action, max_targets_per_action, automation_revision, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`, run.ID, run.ProgramID, run.AuthorizationID,
		run.ScopeHash, run.PolicyRevision, run.MaxActions, run.MaxRequests, run.MaxRequestsPerAction,
		run.MaxTargetsPerAction, run.AutomationRevision, now.Unix(), now.Unix()); err != nil {
		return AgentActionRun{}, fmt.Errorf("store agent action run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AgentActionRun{}, fmt.Errorf("commit agent action run: %w", err)
	}
	return run, nil
}

// ReserveAgentAction atomically validates the current program policy/schedule
// snapshot and consumes the action/request budgets before a tool can start.
func (s *Store) ReserveAgentAction(ctx context.Context, input ReserveAgentActionParams, now time.Time) (AgentActionReservation, bool, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.ActionRunID = strings.TrimSpace(input.ActionRunID)
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.Stage = strings.ToLower(strings.TrimSpace(input.Stage))
	if _, err := uuid.Parse(input.ID); err != nil {
		return AgentActionReservation{}, false, errors.New("agent action reservation id must be a UUID")
	}
	if _, err := uuid.Parse(input.ActionRunID); err != nil {
		return AgentActionReservation{}, false, errors.New("agent action run id must be a UUID")
	}
	if input.ProgramID == "" || input.Sequence < 1 || input.Stage == "" || len(input.ProposalJSON) == 0 || len(input.ProposalJSON) > maxAgentActionProposalBytes || !json.Valid(input.ProposalJSON) {
		return AgentActionReservation{}, false, errors.New("agent action reservation has invalid sequence, stage, or proposal JSON")
	}
	if input.RequestBudget < 1 || input.TargetCount < 1 || input.PolicyRevision <= 0 || input.ScopeHash == "" || input.GrantValidUntil.IsZero() {
		return AgentActionReservation{}, false, errors.New("agent action reservation is missing authorization or budget fields")
	}
	class, ok := contract.ActionClassForStage(input.Stage)
	if !ok || class != input.ActionClass {
		return AgentActionReservation{}, false, errors.New("agent action stage is unregistered or its action class does not match")
	}
	var grant serializedAgentActionGrant
	if err := json.Unmarshal(input.ProposalJSON, &grant); err != nil || grant.ProgramID != input.ProgramID ||
		grant.ScopeHash != input.ScopeHash || grant.PolicyRevision != input.PolicyRevision || grant.Stage != input.Stage ||
		grant.Class != input.ActionClass || len(grant.Targets) != input.TargetCount ||
		grant.RequestBudget != input.RequestBudget || !grant.ValidUntil.Equal(input.GrantValidUntil) || grant.Limits != input.Limits ||
		grant.Proposal.Stage != input.Stage || grant.Proposal.ScopeHash != input.ScopeHash ||
		grant.Proposal.EstimatedCalls != input.RequestBudget {
		return AgentActionReservation{}, false, errors.New("serialized authorization grant does not match reservation fields")
	}
	now = now.UTC().Truncate(time.Second)
	input.GrantValidUntil = input.GrantValidUntil.UTC()
	input.GrantValidUntil = time.Unix(input.GrantValidUntil.Unix(), 0).UTC()
	proposalHash := sha256.Sum256(input.ProposalJSON)
	proposalHashText := hex.EncodeToString(proposalHash[:])

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentActionReservation{}, false, fmt.Errorf("begin agent action reservation: %w", err)
	}
	defer tx.Rollback()
	run, err := loadAgentActionRun(ctx, tx, input.ProgramID, input.ActionRunID)
	if err != nil {
		return AgentActionReservation{}, false, fmt.Errorf("load agent action run for reservation: %w", err)
	}
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, run.ProgramID)
	if err != nil {
		return AgentActionReservation{}, false, err
	}
	if err := validateLiveAgentActionRun(ctx, tx, run, snapshot, now); err != nil {
		return AgentActionReservation{}, false, err
	}
	limits, err := validateAgentActionStage(ctx, tx, input.ProgramID, snapshot.Policy, input.Stage, input.ActionClass)
	if err != nil {
		return AgentActionReservation{}, false, err
	}
	if input.ScopeHash != run.ScopeHash || input.PolicyRevision != run.PolicyRevision ||
		input.Limits != limits || input.RequestBudget > run.MaxRequestsPerAction ||
		input.RequestBudget > snapshot.Policy.MaxRequestsPerAction || input.TargetCount > run.MaxTargetsPerAction ||
		input.TargetCount > snapshot.Policy.MaxTargetsPerAction || input.TargetCount > limits.MaxTargets ||
		!input.GrantValidUntil.After(now) || input.GrantValidUntil.After(snapshot.ExpiresAt) {
		return AgentActionReservation{}, false, errors.New("authorized action no longer matches the run scope, policy, limits, or budgets")
	}
	if err := validateSerializedAgentActionGrant(snapshot.Scope, run, snapshot.Policy, limits, grant); err != nil {
		return AgentActionReservation{}, false, err
	}

	if existing, err := loadAgentActionReservation(ctx, tx, run.ProgramID, input.ActionRunID, input.ID); err == nil {
		if !sameAgentActionReservationInput(existing, input, proposalHashText) {
			return AgentActionReservation{}, false, errors.New("idempotency key was already used for a different action reservation")
		}
		if err := tx.Commit(); err != nil {
			return AgentActionReservation{}, false, fmt.Errorf("commit idempotent action reservation: %w", err)
		}
		return existing, false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return AgentActionReservation{}, false, fmt.Errorf("load idempotent action reservation: %w", err)
	}

	update, err := tx.ExecContext(ctx, `UPDATE agent_action_runs
		SET actions_reserved = actions_reserved + 1, requests_reserved = requests_reserved + ?, updated_at = ?
		WHERE id = ? AND status = 'active' AND actions_reserved < max_actions
		AND requests_reserved + ? <= max_requests`, input.RequestBudget, now.Unix(), run.ID, input.RequestBudget)
	if err != nil {
		return AgentActionReservation{}, false, fmt.Errorf("reserve agent action budgets: %w", err)
	}
	if rows, err := update.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return AgentActionReservation{}, false, fmt.Errorf("verify agent action budget reservation: %w", err)
		}
		return AgentActionReservation{}, false, errors.New("agent action run budget is exhausted or closed")
	}

	reservation := AgentActionReservation{
		ID: input.ID, ActionRunID: run.ID, ProgramID: run.ProgramID, Sequence: input.Sequence,
		Stage: input.Stage, ActionClass: input.ActionClass, ProposalJSON: string(input.ProposalJSON),
		ProposalSHA256: proposalHashText, ScopeHash: input.ScopeHash, PolicyRevision: input.PolicyRevision,
		RequestBudget: input.RequestBudget, TargetCount: input.TargetCount, Limits: input.Limits,
		GrantValidUntil: input.GrantValidUntil, Status: "reserved", CreatedAt: now, UpdatedAt: now,
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_action_reservations(
		id, action_run_id, program_id, sequence, stage, action_class, proposal_json, proposal_sha256,
		scope_hash, policy_revision, request_budget, target_count, rate_limit_per_second, max_concurrency,
		max_targets, timeout_seconds, grant_valid_until, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)`,
		reservation.ID, reservation.ActionRunID, reservation.ProgramID, reservation.Sequence, reservation.Stage,
		string(reservation.ActionClass), reservation.ProposalJSON, reservation.ProposalSHA256, reservation.ScopeHash,
		reservation.PolicyRevision, reservation.RequestBudget, reservation.TargetCount,
		reservation.Limits.RateLimitPerSecond, reservation.Limits.MaxConcurrency, reservation.Limits.MaxTargets,
		reservation.Limits.TimeoutSeconds, reservation.GrantValidUntil.Unix(), reservation.CreatedAt.Unix(), reservation.UpdatedAt.Unix()); err != nil {
		return AgentActionReservation{}, false, fmt.Errorf("store agent action reservation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AgentActionReservation{}, false, fmt.Errorf("commit agent action reservation: %w", err)
	}
	return reservation, true, nil
}

// StartAgentAction performs a just-in-time authorization snapshot check and
// makes a reservation non-replayable before a future executor invokes tools.
func (s *Store) StartAgentAction(ctx context.Context, programID, runID, actionID string, leaseDuration time.Duration, now time.Time) (AgentActionReservation, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return AgentActionReservation{}, errors.New("program id is required to start an agent action")
	}
	if leaseDuration < time.Second || leaseDuration > time.Hour {
		return AgentActionReservation{}, errors.New("agent action lease must be between 1 second and 1 hour")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentActionReservation{}, fmt.Errorf("begin agent action start: %w", err)
	}
	defer tx.Rollback()
	run, err := loadAgentActionRun(ctx, tx, programID, runID)
	if err != nil {
		return AgentActionReservation{}, err
	}
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, run.ProgramID)
	if err != nil {
		return AgentActionReservation{}, err
	}
	if err := validateLiveAgentActionRun(ctx, tx, run, snapshot, now); err != nil {
		return AgentActionReservation{}, err
	}
	action, err := loadAgentActionReservation(ctx, tx, run.ProgramID, runID, actionID)
	if err != nil {
		return AgentActionReservation{}, err
	}
	if action.Status != "reserved" {
		return AgentActionReservation{}, fmt.Errorf("agent action %q is %s and cannot be started or replayed", actionID, action.Status)
	}
	if !action.GrantValidUntil.After(now) {
		return AgentActionReservation{}, errors.New("authorized action grant expired before execution")
	}
	limits, err := validateAgentActionStage(ctx, tx, programID, snapshot.Policy, action.Stage, action.ActionClass)
	if err != nil {
		return AgentActionReservation{}, err
	}
	if limits != action.Limits || action.ScopeHash != run.ScopeHash || action.PolicyRevision != run.PolicyRevision {
		return AgentActionReservation{}, errors.New("action schedule, scope, or policy changed before execution")
	}
	var grant serializedAgentActionGrant
	if err := json.Unmarshal([]byte(action.ProposalJSON), &grant); err != nil {
		return AgentActionReservation{}, errors.New("stored action authorization grant is invalid")
	}
	proposalDigest := sha256.Sum256([]byte(action.ProposalJSON))
	if hex.EncodeToString(proposalDigest[:]) != action.ProposalSHA256 || grant.Stage != action.Stage || grant.Class != action.ActionClass ||
		grant.RequestBudget != action.RequestBudget || len(grant.Targets) != action.TargetCount {
		return AgentActionReservation{}, errors.New("stored action authorization grant failed integrity validation")
	}
	if grant.ValidUntil.Unix() != action.GrantValidUntil.Unix() || !grant.ValidUntil.After(now) || grant.ValidUntil.After(snapshot.ExpiresAt) {
		return AgentActionReservation{}, errors.New("stored action authorization grant expired or changed")
	}
	if err := validateSerializedAgentActionGrant(snapshot.Scope, run, snapshot.Policy, limits, grant); err != nil {
		return AgentActionReservation{}, err
	}
	leaseUntil := now.Add(leaseDuration)
	if leaseUntil.After(now.Add(time.Duration(limits.TimeoutSeconds) * time.Second)) {
		return AgentActionReservation{}, errors.New("agent action lease cannot exceed its stage timeout")
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_reservations SET status = 'running', started_at = ?,
		lease_until = ?, updated_at = ? WHERE id = ? AND action_run_id = ? AND program_id = ? AND status = 'reserved'`,
		now.Unix(), leaseUntil.Unix(), now.Unix(), actionID, runID, run.ProgramID)
	if err != nil {
		return AgentActionReservation{}, fmt.Errorf("mark agent action running: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return AgentActionReservation{}, fmt.Errorf("verify agent action start: %w", err)
		}
		return AgentActionReservation{}, errors.New("agent action was started by another worker")
	}
	if err := tx.Commit(); err != nil {
		return AgentActionReservation{}, fmt.Errorf("commit agent action start: %w", err)
	}
	action.Status = "running"
	action.StartedAt = &now
	action.LeaseUntil = &leaseUntil
	action.UpdatedAt = now
	return action, nil
}

func (s *Store) FinishAgentAction(ctx context.Context, programID, runID, actionID, outcome string, now time.Time) error {
	return s.FinishAgentActionWithResult(ctx, programID, runID, actionID, outcome, []byte(`{}`), now)
}

func (s *Store) FinishAgentActionWithResult(ctx context.Context, programID, runID, actionID, outcome string, resultJSON []byte, now time.Time) error {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return errors.New("program id is required to finish an agent action")
	}
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if outcome != "completed" && outcome != "failed" && outcome != "cancelled" {
		return errors.New("agent action outcome must be completed, failed, or cancelled")
	}
	if len(resultJSON) == 0 {
		resultJSON = []byte(`{}`)
	}
	if len(resultJSON) > 64<<10 || !json.Valid(resultJSON) {
		return errors.New("agent action result must be valid JSON no larger than 64 KiB")
	}
	now = now.UTC().Truncate(time.Second)
	result, err := s.db.ExecContext(ctx, `UPDATE agent_action_reservations SET status = ?, result_json = ?, lease_until = NULL,
		finished_at = ?, updated_at = ? WHERE id = ? AND action_run_id = ? AND program_id = ? AND status = 'running' AND lease_until > ?`,
		outcome, string(resultJSON), now.Unix(), now.Unix(), actionID, runID, programID, now.Unix())
	if err != nil {
		return fmt.Errorf("finish agent action: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify finished agent action: %w", err)
		}
		return errors.New("running agent action not found, lease expired, or action already finished")
	}
	return nil
}

// ConsumeAgentActionRequest must be called immediately before each outbound
// network attempt. A request that fails after consumption remains charged.
// Retries must consume again. Subprocess tools cannot use this meter unless
// their own request layer is instrumented, so they are not safe to dispatch via
// this interface yet.
func (s *Store) ConsumeAgentActionRequest(ctx context.Context, programID, runID, actionID string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	actionID = strings.TrimSpace(actionID)
	if programID == "" || runID == "" || actionID == "" {
		return errors.New("program id, agent action run id, and action id are required")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin outbound request accounting: %w", err)
	}
	defer tx.Rollback()
	run, err := loadAgentActionRun(ctx, tx, programID, runID)
	if err != nil {
		return fmt.Errorf("load action run for request accounting: %w", err)
	}
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, programID)
	if err != nil {
		return err
	}
	if err := validateLiveAgentActionRun(ctx, tx, run, snapshot, now); err != nil {
		return err
	}
	action, err := loadAgentActionReservation(ctx, tx, programID, runID, actionID)
	if err != nil {
		return fmt.Errorf("load action for request accounting: %w", err)
	}
	if action.Status != "running" || action.LeaseUntil == nil || !action.LeaseUntil.After(now) {
		return errors.New("outbound request denied because the action is not running under a live lease")
	}
	if !action.GrantValidUntil.After(now) {
		return errors.New("outbound request denied because the action authorization expired")
	}
	limits, err := validateAgentActionStage(ctx, tx, programID, snapshot.Policy, action.Stage, action.ActionClass)
	if err != nil {
		return err
	}
	if limits != action.Limits || action.ScopeHash != run.ScopeHash || action.PolicyRevision != run.PolicyRevision {
		return errors.New("outbound request denied because scope, policy, or stage schedule changed")
	}
	var grant serializedAgentActionGrant
	if err := json.Unmarshal([]byte(action.ProposalJSON), &grant); err != nil {
		return errors.New("stored action authorization grant is invalid")
	}
	proposalDigest := sha256.Sum256([]byte(action.ProposalJSON))
	if hex.EncodeToString(proposalDigest[:]) != action.ProposalSHA256 || grant.ValidUntil.Unix() != action.GrantValidUntil.Unix() ||
		!grant.ValidUntil.After(now) || grant.ValidUntil.After(snapshot.ExpiresAt) {
		return errors.New("outbound request denied because the stored authorization grant failed integrity or expiry checks")
	}
	if err := validateSerializedAgentActionGrant(snapshot.Scope, run, snapshot.Policy, limits, grant); err != nil {
		return err
	}
	if action.RequestsConsumed >= action.RequestBudget || run.RequestsConsumed >= run.MaxRequests {
		return errors.New("outbound request budget exhausted")
	}
	updateAction, err := tx.ExecContext(ctx, `UPDATE agent_action_reservations
		SET requests_consumed = requests_consumed + 1, updated_at = ?
		WHERE id = ? AND action_run_id = ? AND program_id = ? AND status = 'running' AND lease_until > ?
		AND requests_consumed < request_budget`, now.Unix(), actionID, runID, programID, now.Unix())
	if err != nil {
		return fmt.Errorf("consume action request unit: %w", err)
	}
	if count, err := updateAction.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify action request consumption: %w", err)
		}
		return errors.New("action request budget exhausted or action lease expired")
	}
	updateRun, err := tx.ExecContext(ctx, `UPDATE agent_action_runs
		SET requests_consumed = requests_consumed + 1, updated_at = ?
		WHERE id = ? AND program_id = ? AND status = 'active'
		AND requests_consumed < max_requests AND requests_consumed < requests_reserved`,
		now.Unix(), runID, programID)
	if err != nil {
		return fmt.Errorf("consume run request unit: %w", err)
	}
	if count, err := updateRun.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify run request consumption: %w", err)
		}
		return errors.New("agent action run request budget exhausted")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit outbound request accounting: %w", err)
	}
	return nil
}

func (s *Store) CancelReservedAgentAction(ctx context.Context, programID, runID, actionID string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	if programID == "" || strings.TrimSpace(runID) == "" || strings.TrimSpace(actionID) == "" {
		return errors.New("program id, action run id, and action id are required")
	}
	now = now.UTC().Truncate(time.Second)
	result, err := s.db.ExecContext(ctx, `UPDATE agent_action_reservations SET status = 'cancelled', finished_at = ?, updated_at = ?
		WHERE program_id = ? AND action_run_id = ? AND id = ? AND status = 'reserved'`,
		now.Unix(), now.Unix(), programID, runID, actionID)
	if err != nil {
		return fmt.Errorf("cancel reserved agent action: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify cancelled agent action: %w", err)
		}
		return errors.New("reserved agent action not found or no longer cancellable")
	}
	return nil
}

// ResolveUncertainAgentAction records an operator assessment without changing
// the action's uncertain status or returning any budget. It never replays work.
func (s *Store) ResolveUncertainAgentAction(ctx context.Context, programID, runID, actionID, decision, reviewer, note string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	actionID = strings.TrimSpace(actionID)
	decision = strings.TrimSpace(strings.ToLower(decision))
	reviewer = strings.TrimSpace(reviewer)
	note = strings.TrimSpace(note)
	if programID == "" || runID == "" || actionID == "" {
		return errors.New("program id, action run id, and action id are required")
	}
	if decision != "assessed_completed" && decision != "assessed_not_executed" {
		return errors.New("review decision must be assessed_completed or assessed_not_executed")
	}
	if reviewer == "" || len(reviewer) > 128 || note == "" || len(note) > 2048 ||
		!utf8.ValidString(reviewer) || !utf8.ValidString(note) {
		return errors.New("reviewer must be valid UTF-8 (1-128 bytes) and review note valid UTF-8 (1-2048 bytes)")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin uncertain action review: %w", err)
	}
	defer tx.Rollback()
	run, err := loadAgentActionRun(ctx, tx, programID, runID)
	if err != nil {
		return fmt.Errorf("load action run for review: %w", err)
	}
	if run.Status != "needs_review" {
		return fmt.Errorf("agent action run is %s, not awaiting uncertain-action review", run.Status)
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_reservations SET review_decision = ?, reviewed_by = ?,
		review_note = ?, reviewed_at = ?, updated_at = ?
		WHERE id = ? AND action_run_id = ? AND program_id = ? AND status = 'uncertain' AND review_decision IS NULL`,
		decision, reviewer, note, now.Unix(), now.Unix(), actionID, runID, programID)
	if err != nil {
		return fmt.Errorf("record uncertain action review: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify uncertain action review: %w", err)
		}
		return errors.New("unreviewed uncertain action not found in this program and action run")
	}
	var remaining int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_action_reservations
		WHERE action_run_id = ? AND program_id = ? AND status = 'uncertain' AND review_decision IS NULL`, runID, programID).Scan(&remaining); err != nil {
		return fmt.Errorf("count remaining uncertain action reviews: %w", err)
	}
	if remaining == 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET status = 'failed', closed_at = ?, updated_at = ?
			WHERE id = ? AND program_id = ? AND status = 'needs_review'`, now.Unix(), now.Unix(), runID, programID); err != nil {
			return fmt.Errorf("close reviewed uncertain action run: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit uncertain action review: %w", err)
	}
	return nil
}

// RecoverExpiredAgentActions marks possibly-executed actions uncertain rather
// than retrying them automatically. Their budgets remain consumed.
func (s *Store) RecoverExpiredAgentActions(ctx context.Context, now time.Time) (int64, error) {
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin expired action recovery: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_reservations SET status = 'uncertain', lease_until = NULL,
		finished_at = ?, updated_at = ? WHERE status = 'running' AND COALESCE(lease_until, 0) <= ?`,
		now.Unix(), now.Unix(), now.Unix())
	if err != nil {
		return 0, fmt.Errorf("mark expired agent actions uncertain: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count recovered agent actions: %w", err)
	}
	if count > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET status = 'needs_review', updated_at = ?
			WHERE status = 'active' AND id IN (SELECT action_run_id FROM agent_action_reservations WHERE status = 'uncertain')`, now.Unix()); err != nil {
			return 0, fmt.Errorf("mark uncertain agent action runs for review: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit expired agent action recovery: %w", err)
	}
	return count, nil
}

func (s *Store) CloseAgentActionRun(ctx context.Context, programID, runID, outcome string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if programID == "" || runID == "" {
		return errors.New("program id and agent action run id are required")
	}
	if outcome != "completed" && outcome != "failed" && outcome != "cancelled" {
		return errors.New("agent action run outcome must be completed, failed, or cancelled")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin agent action run close: %w", err)
	}
	defer tx.Rollback()
	var activeActions, uncertainActions int
	if err := tx.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(CASE WHEN status IN ('reserved', 'running') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'uncertain' THEN 1 ELSE 0 END), 0)
		FROM agent_action_reservations WHERE action_run_id = ? AND program_id = ?`, runID, programID).
		Scan(&activeActions, &uncertainActions); err != nil {
		return fmt.Errorf("check unfinished agent actions: %w", err)
	}
	if uncertainActions > 0 {
		return errors.New("agent action run has uncertain actions and requires review")
	}
	if activeActions > 0 {
		return errors.New("agent action run has reserved or running actions")
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET status = ?, closed_at = ?, updated_at = ?
		WHERE id = ? AND program_id = ? AND status = 'active'`, outcome, now.Unix(), now.Unix(), runID, programID)
	if err != nil {
		return fmt.Errorf("close agent action run: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify closed agent action run: %w", err)
		}
		return fmt.Errorf("active agent action run %q not found in program %q", runID, programID)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit agent action run close: %w", err)
	}
	return nil
}

func (s *Store) GetAgentActionRun(ctx context.Context, programID, runID string) (AgentActionRun, error) {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	if programID == "" || runID == "" {
		return AgentActionRun{}, errors.New("program id and agent action run id are required")
	}
	run, err := loadAgentActionRun(ctx, s.db, programID, runID)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentActionRun{}, fmt.Errorf("agent action run %q not found in program %q", runID, programID)
	}
	if err != nil {
		return AgentActionRun{}, fmt.Errorf("get agent action run: %w", err)
	}
	return run, nil
}

func (s *Store) ListAgentActionRuns(ctx context.Context, programID string, limit int) ([]AgentActionRun, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return nil, errors.New("program id is required; agent action runs are always program-scoped")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, program_id, authorization_id, scope_hash,
		policy_revision, max_actions, max_requests, max_requests_per_action, max_targets_per_action,
		actions_reserved, requests_reserved, requests_consumed, planner_provider, planner_model, planner_calls,
		memory_items_sent, memory_ids_sent_json, automation_revision, status, created_at, updated_at, closed_at
		FROM agent_action_runs WHERE program_id = ? ORDER BY created_at DESC, id LIMIT ?`, programID, limit)
	if err != nil {
		return nil, fmt.Errorf("list program agent action runs: %w", err)
	}
	defer rows.Close()
	runs := make([]AgentActionRun, 0)
	for rows.Next() {
		run, err := scanAgentActionRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan program agent action run: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate program agent action runs: %w", err)
	}
	return runs, nil
}

func (s *Store) ListAgentActionReservations(ctx context.Context, programID, runID string) ([]AgentActionReservation, error) {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	if programID == "" || runID == "" {
		return nil, errors.New("program id and agent action run id are required")
	}
	rows, err := s.db.QueryContext(ctx, agentActionReservationSelect+` WHERE program_id = ? AND action_run_id = ? ORDER BY sequence`, programID, runID)
	if err != nil {
		return nil, fmt.Errorf("list program agent action reservations: %w", err)
	}
	defer rows.Close()
	items := make([]AgentActionReservation, 0)
	for rows.Next() {
		item, err := scanAgentActionReservation(rows)
		if err != nil {
			return nil, fmt.Errorf("scan program agent action reservation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate program agent action reservations: %w", err)
	}
	return items, nil
}

func loadAgentExecutionSnapshot(ctx context.Context, queryer agentPolicyQueryRower, programID string) (agentExecutionSnapshot, error) {
	var snapshot agentExecutionSnapshot
	var expiresAtNS int64
	var pending int
	var scopeJSON string
	var stagesJSON, classesJSON string
	var policy contract.ProgramAgentPolicy
	err := queryer.QueryRowContext(ctx, `SELECT p.status, p.scope_hash, p.scope_json, a.id, a.expires_at_ns,
		EXISTS(SELECT 1 FROM program_source_snapshots ps WHERE ps.program_id = p.id AND ps.status = 'pending'),
		ap.revision, ap.allowed_stages_json, ap.allowed_classes_json, ap.max_actions_per_run,
		ap.max_requests_per_run, ap.max_requests_per_action, ap.max_targets_per_action
		FROM programs p JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
		JOIN program_agent_policies ap ON ap.program_id = p.id WHERE p.id = ?`, programID).
		Scan(&snapshot.ProgramStatus, &snapshot.ScopeHash, &scopeJSON, &snapshot.AuthorizationID, &expiresAtNS, &pending,
			&policy.Revision, &stagesJSON, &classesJSON, &policy.MaxActionsPerRun, &policy.MaxRequestsPerRun,
			&policy.MaxRequestsPerAction, &policy.MaxTargetsPerAction)
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

func validateSerializedAgentActionGrant(scope assessment.Scope, run AgentActionRun, policy contract.ProgramAgentPolicy, limits recon.StageLimits, grant serializedAgentActionGrant) error {
	registeredClass, registered := contract.ActionClassForStage(grant.Stage)
	if grant.ProgramID != run.ProgramID || grant.ScopeHash != run.ScopeHash || grant.PolicyRevision != run.PolicyRevision ||
		grant.Proposal.ScopeHash != run.ScopeHash || grant.Proposal.Stage != grant.Stage || grant.Stage == "" ||
		grant.RequestBudget < 1 || grant.Proposal.EstimatedCalls != grant.RequestBudget || grant.Limits != limits ||
		!registered || grant.Class != registeredClass || !containsPolicyStage(policy.AllowedStages, grant.Stage) ||
		!containsPolicyClass(policy.AllowedClasses, grant.Class) || grant.RequestBudget > run.MaxRequestsPerAction ||
		grant.RequestBudget > policy.MaxRequestsPerAction || len(grant.Targets) == 0 {
		return errors.New("serialized action grant no longer matches the run authorization snapshot")
	}
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

func loadAgentActionRun(ctx context.Context, queryer agentPolicyQueryRower, programID, runID string) (AgentActionRun, error) {
	return scanAgentActionRun(queryer.QueryRowContext(ctx, `SELECT id, program_id, authorization_id, scope_hash,
		policy_revision, max_actions, max_requests, max_requests_per_action, max_targets_per_action,
		actions_reserved, requests_reserved, requests_consumed, planner_provider, planner_model, planner_calls,
		memory_items_sent, memory_ids_sent_json, automation_revision, status, created_at, updated_at, closed_at
		FROM agent_action_runs WHERE program_id = ? AND id = ?`, programID, runID))
}

func scanAgentActionRun(row interface{ Scan(...any) error }) (AgentActionRun, error) {
	var run AgentActionRun
	var createdAt, updatedAt int64
	var closedAt sql.NullInt64
	var memoryIDsJSON string
	err := row.Scan(&run.ID, &run.ProgramID, &run.AuthorizationID, &run.ScopeHash, &run.PolicyRevision,
		&run.MaxActions, &run.MaxRequests, &run.MaxRequestsPerAction, &run.MaxTargetsPerAction,
		&run.ActionsReserved, &run.RequestsReserved, &run.RequestsConsumed, &run.PlannerProvider, &run.PlannerModel,
		&run.PlannerCalls, &run.MemoryItemsSent, &memoryIDsJSON, &run.AutomationRevision, &run.Status, &createdAt, &updatedAt, &closedAt)
	if err != nil {
		return AgentActionRun{}, err
	}
	if err := json.Unmarshal([]byte(memoryIDsJSON), &run.MemoryIDsSent); err != nil {
		return AgentActionRun{}, fmt.Errorf("decode planner memory egress audit: %w", err)
	}
	run.CreatedAt = time.Unix(createdAt, 0).UTC()
	run.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if closedAt.Valid {
		value := time.Unix(closedAt.Int64, 0).UTC()
		run.ClosedAt = &value
	}
	return run, nil
}

type agentActionRowScanner interface {
	Scan(...any) error
}

const agentActionReservationSelect = `SELECT id, action_run_id, program_id, sequence, stage, action_class,
	proposal_json, proposal_sha256, result_json, scope_hash, policy_revision, request_budget, requests_consumed, target_count,
	rate_limit_per_second, max_concurrency, max_targets, timeout_seconds, grant_valid_until, status,
	lease_until, created_at, updated_at, started_at, finished_at, COALESCE(review_decision, ''),
	COALESCE(reviewed_by, ''), COALESCE(review_note, ''), reviewed_at FROM agent_action_reservations`

func loadAgentActionReservation(ctx context.Context, queryer agentPolicyQueryRower, programID, runID, actionID string) (AgentActionReservation, error) {
	return scanAgentActionReservation(queryer.QueryRowContext(ctx, agentActionReservationSelect+
		` WHERE program_id = ? AND action_run_id = ? AND id = ?`, programID, runID, actionID))
}

func scanAgentActionReservation(row agentActionRowScanner) (AgentActionReservation, error) {
	var item AgentActionReservation
	var class string
	var validUntil, createdAt, updatedAt int64
	var leaseUntil, startedAt, finishedAt, reviewedAt sql.NullInt64
	err := row.Scan(&item.ID, &item.ActionRunID, &item.ProgramID, &item.Sequence, &item.Stage, &class,
		&item.ProposalJSON, &item.ProposalSHA256, &item.ResultJSON, &item.ScopeHash, &item.PolicyRevision, &item.RequestBudget,
		&item.RequestsConsumed, &item.TargetCount, &item.Limits.RateLimitPerSecond, &item.Limits.MaxConcurrency, &item.Limits.MaxTargets,
		&item.Limits.TimeoutSeconds, &validUntil, &item.Status, &leaseUntil, &createdAt, &updatedAt, &startedAt, &finishedAt,
		&item.ReviewDecision, &item.ReviewedBy, &item.ReviewNote, &reviewedAt)
	if err != nil {
		return AgentActionReservation{}, err
	}
	item.ActionClass = contract.ActionClass(class)
	item.GrantValidUntil = time.Unix(validUntil, 0).UTC()
	item.CreatedAt = time.Unix(createdAt, 0).UTC()
	item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if leaseUntil.Valid {
		value := time.Unix(leaseUntil.Int64, 0).UTC()
		item.LeaseUntil = &value
	}
	if startedAt.Valid {
		value := time.Unix(startedAt.Int64, 0).UTC()
		item.StartedAt = &value
	}
	if finishedAt.Valid {
		value := time.Unix(finishedAt.Int64, 0).UTC()
		item.FinishedAt = &value
	}
	if reviewedAt.Valid {
		value := time.Unix(reviewedAt.Int64, 0).UTC()
		item.ReviewedAt = &value
	}
	return item, nil
}

func sameAgentActionReservationInput(existing AgentActionReservation, input ReserveAgentActionParams, proposalHash string) bool {
	return existing.ActionRunID == input.ActionRunID && existing.Sequence == input.Sequence && existing.Stage == input.Stage &&
		existing.ActionClass == input.ActionClass && existing.ProposalSHA256 == proposalHash && existing.ScopeHash == input.ScopeHash &&
		existing.PolicyRevision == input.PolicyRevision && existing.RequestBudget == input.RequestBudget &&
		existing.TargetCount == input.TargetCount && existing.Limits == input.Limits &&
		existing.GrantValidUntil.Equal(input.GrantValidUntil)
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
