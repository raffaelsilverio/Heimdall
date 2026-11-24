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

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

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
	if err := json.Unmarshal(input.ProposalJSON, &grant); err != nil || !agentReservationMatchesGrant(input, grant) {
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
	if !agentReservationMatchesSnapshot(run, snapshot, input, limits, now) {
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

	if err := consumeAgentApprovalForGrant(ctx, tx, grant, now); err != nil {
		return AgentActionReservation{}, false, err
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
