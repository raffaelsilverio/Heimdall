package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
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
