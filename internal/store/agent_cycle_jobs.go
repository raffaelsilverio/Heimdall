package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

const maxAgentCycleJobErrorBytes = 2048

type AgentCycleLease struct {
	TaskID             string
	ProgramID          string
	EventID            string
	EventScopeHash     string
	ActionRunID        string
	RequestBudget      int
	PolicyRequestLimit int
	Attempt            int
	AutomationRevision int64
	LeaseUntil         time.Time
	Stage              string
	Category           string
	Target             string
	ChangeType         string
	ObservedAt         time.Time
	Automation         ProgramAgentAutomation
}

type AgentCycleJob struct {
	TaskID             string     `json:"task_id"`
	ProgramID          string     `json:"program_id"`
	EventID            string     `json:"event_id"`
	EventScopeHash     string     `json:"event_scope_hash"`
	AutomationRevision int64      `json:"automation_revision"`
	ActionRunID        string     `json:"action_run_id,omitempty"`
	RequestBudget      int        `json:"request_budget"`
	Status             string     `json:"status"`
	Attempts           int        `json:"attempts"`
	LeaseUntil         *time.Time `json:"lease_until,omitempty"`
	Error              string     `json:"error,omitempty"`
	ResultJSON         string     `json:"result_json"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	FinishedAt         *time.Time `json:"finished_at,omitempty"`
	ReviewDecision     string     `json:"review_decision,omitempty"`
	ReviewedBy         string     `json:"reviewed_by,omitempty"`
	ReviewNote         string     `json:"review_note,omitempty"`
	ReviewedAt         *time.Time `json:"reviewed_at,omitempty"`
}

// ClaimAgentCycleJobs only leases jobs created while persistent per-program
// consent was enabled. It atomically charges the UTC daily-cycle allowance.
// Expired leases become needs_review and are never automatically replayed.
func (s *Store) ClaimAgentCycleJobs(ctx context.Context, now time.Time, leaseDuration time.Duration, limit int) ([]AgentCycleLease, error) {
	now = now.UTC().Truncate(time.Second)
	if _, err := s.RecoverExpiredAgentActions(ctx, now); err != nil {
		return nil, fmt.Errorf("recover expired agent actions before cycle claim: %w", err)
	}
	if leaseDuration <= 0 {
		leaseDuration = 2 * time.Minute
	}
	if leaseDuration > 10*time.Minute {
		return nil, errors.New("agent cycle lease cannot exceed 10 minutes")
	}
	if limit <= 0 || limit > 10 {
		limit = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin agent cycle claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE agent_cycle_jobs SET status = 'needs_review', lease_until = NULL,
		error = COALESCE(error, 'agent cycle lease expired; automatic replay is disabled'), finished_at = ?, updated_at = ?
		WHERE status = 'running' AND COALESCE(lease_until, 0) <= ?`, now.Unix(), now.Unix(), now.Unix()); err != nil {
		return nil, fmt.Errorf("mark expired agent cycle jobs for review: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_cycle_jobs AS j SET status = 'cancelled', lease_until = NULL,
		error = 'persistent automation consent, authorization, scope, or web policy is no longer valid',
		finished_at = ?, updated_at = ?
		WHERE j.status = 'pending' AND NOT EXISTS (
			SELECT 1 FROM programs p
			JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
			JOIN program_agent_automation aa ON aa.program_id = p.id
			JOIN program_agent_policies ap ON ap.program_id = p.id
			JOIN change_events e ON e.id = j.event_id
			JOIN stage_schedules ss ON ss.program_id = p.id AND ss.stage = 'web'
			WHERE p.id = j.program_id AND p.status = 'active' AND e.scope_hash = p.scope_hash
			AND j.event_scope_hash = p.scope_hash AND a.expires_at_ns > ?
			AND aa.enabled = 1 AND aa.revision = j.automation_revision
			AND aa.policy_revision = ap.revision
			AND aa.allow_model_context_egress = 1 AND aa.allow_active_requests = 1
			AND aa.context_egress_expires_at > ? AND aa.context_egress_expires_at <= a.expires_at_ns / 1000000000
			AND aa.max_cycles_per_day BETWEEN 1 AND 50 AND aa.max_requests_per_day BETWEEN 1 AND 10000
			AND aa.max_steps_per_cycle BETWEEN 1 AND 20
			AND aa.max_steps_per_cycle <= ap.max_actions_per_run
			AND EXISTS (SELECT 1 FROM json_each(ap.allowed_stages_json) WHERE value = 'web')
			AND EXISTS (SELECT 1 FROM json_each(ap.allowed_classes_json) WHERE value = 'safe_active')
			AND ss.enabled = 1 AND ss.rate_limit_per_second BETWEEN 1 AND 1000
			AND ss.max_concurrency BETWEEN 1 AND 100 AND ss.max_targets BETWEEN 1 AND 50000
			AND ss.timeout_seconds BETWEEN 1 AND 3600
			AND NOT EXISTS (SELECT 1 FROM program_source_snapshots ps WHERE ps.program_id = p.id AND ps.status = 'pending')
		)`, now.Unix(), now.Unix(), now.UnixNano(), now.Unix()); err != nil {
		return nil, fmt.Errorf("cancel queued cycles with stale consent or authorization: %w", err)
	}
	utcDay := now.Format("2006-01-02")
	rows, err := tx.QueryContext(ctx, `SELECT j.task_id FROM agent_cycle_jobs j
		JOIN program_agent_automation aa ON aa.program_id = j.program_id
		LEFT JOIN agent_cycle_daily_usage du ON du.program_id = j.program_id AND du.utc_day = ?
		WHERE j.status = 'pending' AND aa.enabled = 1 AND aa.context_egress_expires_at > ?
		AND COALESCE(du.cycles_started, 0) < aa.max_cycles_per_day
		AND COALESCE(du.requests_reserved, 0) < aa.max_requests_per_day
		ORDER BY j.created_at, j.task_id LIMIT 100`, utcDay, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("select pending agent cycle jobs: %w", err)
	}
	taskIDs := make([]string, 0, 100)
	for rows.Next() {
		var taskID string
		if err := rows.Scan(&taskID); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan pending agent cycle job: %w", err)
		}
		taskIDs = append(taskIDs, taskID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate pending agent cycle jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close pending agent cycle jobs: %w", err)
	}
	leases := make([]AgentCycleLease, 0, limit)
	for _, taskID := range taskIDs {
		if len(leases) >= limit {
			break
		}
		lease, eligible, err := loadAgentCycleCandidate(ctx, tx, taskID, now)
		if err != nil {
			return nil, err
		}
		if !eligible {
			if _, err := tx.ExecContext(ctx, `UPDATE agent_cycle_jobs SET status = 'cancelled',
				error = 'automation consent, authorization, scope, or web policy is no longer valid', finished_at = ?, updated_at = ?
				WHERE task_id = ? AND status = 'pending'`, now.Unix(), now.Unix(), taskID); err != nil {
				return nil, fmt.Errorf("cancel ineligible agent cycle job: %w", err)
			}
			continue
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO agent_cycle_daily_usage(program_id, utc_day, cycles_started, requests_reserved, updated_at)
			VALUES (?, ?, 0, 0, ?) ON CONFLICT(program_id, utc_day) DO NOTHING`, lease.ProgramID, utcDay, now.Unix()); err != nil {
			return nil, fmt.Errorf("initialize daily agent cycle budget: %w", err)
		}
		var cyclesStarted, requestsReserved int
		if err := tx.QueryRowContext(ctx, `SELECT cycles_started, requests_reserved FROM agent_cycle_daily_usage
			WHERE program_id = ? AND utc_day = ?`, lease.ProgramID, utcDay).Scan(&cyclesStarted, &requestsReserved); err != nil {
			return nil, fmt.Errorf("read daily agent cycle budget: %w", err)
		}
		requestBudget := lease.Automation.MaxRequestsPerDay - requestsReserved
		if requestBudget > lease.PolicyRequestLimit {
			requestBudget = lease.PolicyRequestLimit
		}
		if cyclesStarted >= lease.Automation.MaxCyclesPerDay || requestBudget <= 0 {
			continue
		}
		lease.RequestBudget = requestBudget
		usage, err := tx.ExecContext(ctx, `UPDATE agent_cycle_daily_usage
			SET cycles_started = cycles_started + 1, requests_reserved = requests_reserved + ?, updated_at = ?
			WHERE program_id = ? AND utc_day = ? AND cycles_started < ?
			AND requests_reserved + ? <= ?`, requestBudget, now.Unix(), lease.ProgramID, utcDay,
			lease.Automation.MaxCyclesPerDay, requestBudget, lease.Automation.MaxRequestsPerDay)
		if err != nil {
			return nil, fmt.Errorf("reserve daily agent cycle budget: %w", err)
		}
		if count, err := usage.RowsAffected(); err != nil || count != 1 {
			if err != nil {
				return nil, fmt.Errorf("verify daily agent cycle budget: %w", err)
			}
			continue
		}
		lease.ActionRunID = uuid.NewString()
		lease.Attempt = 1
		lease.LeaseUntil = now.Add(leaseDuration)
		update, err := tx.ExecContext(ctx, `UPDATE agent_cycle_jobs SET status = 'running', attempts = 1,
			action_run_id = ?, request_budget = ?, lease_until = ?, error = NULL, updated_at = ?
			WHERE task_id = ? AND status = 'pending' AND automation_revision = ?`,
			lease.ActionRunID, lease.RequestBudget, lease.LeaseUntil.Unix(), now.Unix(), taskID, lease.AutomationRevision)
		if err != nil {
			return nil, fmt.Errorf("lease agent cycle job: %w", err)
		}
		if count, err := update.RowsAffected(); err != nil || count != 1 {
			if err != nil {
				return nil, fmt.Errorf("verify agent cycle job lease: %w", err)
			}
			// The daily budget update is in the same transaction; a failed claim
			// rolls back below rather than consuming quota for an unleased job.
			return nil, errors.New("agent cycle job changed while being leased")
		}
		leases = append(leases, lease)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit agent cycle leases: %w", err)
	}
	return leases, nil
}

func loadAgentCycleCandidate(ctx context.Context, tx *sql.Tx, taskID string, now time.Time) (AgentCycleLease, bool, error) {
	var lease AgentCycleLease
	var eventCreatedAt int64
	if err := tx.QueryRowContext(ctx, `SELECT j.task_id, j.program_id, j.event_id, j.event_scope_hash, j.automation_revision,
		e.stage, e.category, e.stable_key, e.change_type, e.created_at
		FROM agent_cycle_jobs j JOIN change_events e ON e.id = j.event_id
		WHERE j.task_id = ? AND j.status = 'pending'`, taskID).Scan(
		&lease.TaskID, &lease.ProgramID, &lease.EventID, &lease.EventScopeHash,
		&lease.AutomationRevision, &lease.Stage, &lease.Category, &lease.Target, &lease.ChangeType, &eventCreatedAt); err != nil {
		return AgentCycleLease{}, false, fmt.Errorf("load agent cycle candidate %s: %w", taskID, err)
	}
	lease.Target = sanitizeCycleEventTarget(lease.Target)
	lease.Category = boundedCycleText(lease.Category, 128)
	lease.ChangeType = boundedCycleText(lease.ChangeType, 32)
	lease.ObservedAt = time.Unix(eventCreatedAt, 0).UTC()
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, lease.ProgramID)
	if err != nil {
		return lease, false, nil
	}
	if err := validateAgentExecutionSnapshot(snapshot, now); err != nil {
		return lease, false, nil
	}
	automation, err := loadProgramAgentAutomation(ctx, tx, lease.ProgramID)
	if err != nil {
		return lease, false, fmt.Errorf("load automation consent for queued cycle: %w", err)
	}
	if !automation.Enabled || automation.Revision != lease.AutomationRevision || automation.PolicyRevision != snapshot.Policy.Revision ||
		!automation.AllowModelContextEgress ||
		!automation.AllowActiveRequests || automation.ContextEgressExpiresAt == nil ||
		!automation.ContextEgressExpiresAt.After(now) || automation.ContextEgressExpiresAt.After(snapshot.ExpiresAt) ||
		automation.MaxCyclesPerDay < 1 || automation.MaxCyclesPerDay > 50 || automation.MaxRequestsPerDay < 1 ||
		automation.MaxRequestsPerDay > 10000 || automation.MaxStepsPerCycle < 1 ||
		automation.MaxStepsPerCycle > 20 ||
		automation.MaxStepsPerCycle > snapshot.Policy.MaxActionsPerRun ||
		!containsPolicyStage(snapshot.Policy.AllowedStages, recon.StageWeb) ||
		!containsPolicyClass(snapshot.Policy.AllowedClasses, contract.ActionSafeActive) {
		return lease, false, nil
	}
	if automation.ContextEgressExpiresAt.After(snapshot.ExpiresAt) {
		return lease, false, nil
	}
	var currentScopeHash string
	var scheduleEnabled int
	var limits recon.StageLimits
	if err := tx.QueryRowContext(ctx, `SELECT p.scope_hash, ss.enabled, ss.rate_limit_per_second, ss.max_concurrency,
		ss.max_targets, ss.timeout_seconds FROM programs p JOIN stage_schedules ss ON ss.program_id = p.id
		WHERE p.id = ? AND ss.stage = ?`, lease.ProgramID, recon.StageWeb).
		Scan(&currentScopeHash, &scheduleEnabled, &limits.RateLimitPerSecond, &limits.MaxConcurrency, &limits.MaxTargets, &limits.TimeoutSeconds); err != nil {
		return lease, false, nil
	}
	if currentScopeHash != lease.EventScopeHash || scheduleEnabled != 1 || limits.Validate() != nil {
		return lease, false, nil
	}
	lease.Automation = automation
	lease.PolicyRequestLimit = snapshot.Policy.MaxRequestsPerRun
	return lease, true, nil
}

func (s *Store) RenewAgentCycleJobLease(ctx context.Context, lease AgentCycleLease, now time.Time, leaseDuration time.Duration) (bool, error) {
	now = now.UTC().Truncate(time.Second)
	if lease.TaskID == "" || lease.ProgramID == "" || lease.Attempt < 1 || leaseDuration <= 0 || leaseDuration > 10*time.Minute {
		return false, errors.New("valid agent cycle lease and duration up to 10 minutes are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin agent cycle lease renewal: %w", err)
	}
	defer tx.Rollback()
	var status string
	var attempts int
	var automationRevision int64
	var leaseUntil sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT status, attempts, automation_revision, lease_until FROM agent_cycle_jobs
		WHERE task_id = ? AND program_id = ?`, lease.TaskID, lease.ProgramID).
		Scan(&status, &attempts, &automationRevision, &leaseUntil); err != nil {
		return false, fmt.Errorf("load agent cycle lease: %w", err)
	}
	if status != "running" || attempts != lease.Attempt || automationRevision != lease.AutomationRevision ||
		!leaseUntil.Valid || leaseUntil.Int64 <= now.Unix() {
		return false, nil
	}
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, lease.ProgramID)
	if err != nil {
		return false, nil
	}
	automation, err := loadProgramAgentAutomation(ctx, tx, lease.ProgramID)
	if err != nil || !automation.Enabled || automation.Revision != lease.AutomationRevision || automation.PolicyRevision != snapshot.Policy.Revision ||
		!automation.AllowModelContextEgress || !automation.AllowActiveRequests || automation.ContextEgressExpiresAt == nil ||
		!automation.ContextEgressExpiresAt.After(now) || automation.ContextEgressExpiresAt.After(snapshot.ExpiresAt) ||
		automation.MaxCyclesPerDay < 1 || automation.MaxCyclesPerDay > 50 || automation.MaxRequestsPerDay < 1 ||
		automation.MaxRequestsPerDay > 10000 || automation.MaxStepsPerCycle < 1 ||
		automation.MaxStepsPerCycle > 20 || automation.MaxStepsPerCycle > snapshot.Policy.MaxActionsPerRun ||
		validateAgentExecutionSnapshot(snapshot, now) != nil || !containsPolicyStage(snapshot.Policy.AllowedStages, recon.StageWeb) ||
		!containsPolicyClass(snapshot.Policy.AllowedClasses, contract.ActionSafeActive) {
		return false, nil
	}
	var eventScopeHash string
	if err := tx.QueryRowContext(ctx, `SELECT e.scope_hash FROM agent_cycle_jobs j JOIN change_events e ON e.id = j.event_id
		WHERE j.task_id = ? AND j.program_id = ? AND j.status = 'running'`, lease.TaskID, lease.ProgramID).Scan(&eventScopeHash); err != nil ||
		eventScopeHash != snapshot.ScopeHash {
		return false, nil
	}
	var enabled int
	var limits recon.StageLimits
	if err := tx.QueryRowContext(ctx, `SELECT enabled, rate_limit_per_second, max_concurrency, max_targets, timeout_seconds
		FROM stage_schedules WHERE program_id = ? AND stage = ?`, lease.ProgramID, recon.StageWeb).
		Scan(&enabled, &limits.RateLimitPerSecond, &limits.MaxConcurrency, &limits.MaxTargets, &limits.TimeoutSeconds); err != nil ||
		enabled != 1 || limits.Validate() != nil {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_cycle_jobs SET lease_until = ?, updated_at = ?
		WHERE task_id = ? AND program_id = ? AND status = 'running' AND attempts = ? AND lease_until > ?`,
		now.Add(leaseDuration).Unix(), now.Unix(), lease.TaskID, lease.ProgramID, lease.Attempt, now.Unix())
	if err != nil {
		return false, fmt.Errorf("renew agent cycle lease: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return false, fmt.Errorf("verify renewed agent cycle lease: %w", err)
		}
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit agent cycle lease renewal: %w", err)
	}
	return true, nil
}

func (s *Store) CompleteAgentCycleJob(ctx context.Context, lease AgentCycleLease, outcome string, resultJSON []byte, cause error, now time.Time) error {
	if lease.TaskID == "" || lease.ProgramID == "" || lease.Attempt < 1 {
		return errors.New("valid agent cycle job lease is required")
	}
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if outcome != "completed" && outcome != "failed" && outcome != "needs_review" && outcome != "cancelled" {
		return errors.New("agent cycle outcome must be completed, failed, needs_review, or cancelled")
	}
	if len(resultJSON) == 0 {
		resultJSON = []byte(`{}`)
	}
	if len(resultJSON) > 64<<10 || !json.Valid(resultJSON) {
		return errors.New("agent cycle result must be valid JSON no larger than 64 KiB")
	}
	errorText := ""
	if cause != nil {
		errorText = strings.ToValidUTF8(cause.Error(), "�")
		if len(errorText) > maxAgentCycleJobErrorBytes {
			errorText = boundedCycleText(errorText, maxAgentCycleJobErrorBytes)
		}
	}
	now = now.UTC().Truncate(time.Second)
	result, err := s.db.ExecContext(ctx, `UPDATE agent_cycle_jobs SET status = ?, lease_until = NULL,
		error = NULLIF(?, ''), result_json = ?, finished_at = ?, updated_at = ?
		WHERE task_id = ? AND program_id = ? AND status = 'running' AND attempts = ? AND lease_until > ?`,
		outcome, errorText, string(resultJSON), now.Unix(), now.Unix(), lease.TaskID, lease.ProgramID, lease.Attempt, now.Unix())
	if err != nil {
		return fmt.Errorf("complete agent cycle job: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify completed agent cycle job: %w", err)
		}
		return errors.New("agent cycle lease was lost or expired before completion")
	}
	return nil
}

func (s *Store) ResolveAgentCycleJobReview(ctx context.Context, programID, taskID, decision, reviewer, note string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	taskID = strings.TrimSpace(taskID)
	decision = strings.TrimSpace(strings.ToLower(decision))
	reviewer = strings.TrimSpace(reviewer)
	note = strings.TrimSpace(note)
	if programID == "" || taskID == "" || reviewer == "" || len(reviewer) > 128 || note == "" || len(note) > 2048 ||
		!utf8.ValidString(reviewer) || !utf8.ValidString(note) {
		return errors.New("program id, task id, operator, and a valid review note are required")
	}
	if decision != "assessed_completed" && decision != "assessed_failed" && decision != "assessed_no_action" {
		return errors.New("cycle review decision must be assessed_completed, assessed_failed, or assessed_no_action")
	}
	if _, err := s.RecoverExpiredAgentActions(ctx, now.UTC()); err != nil {
		return fmt.Errorf("recover action leases before cycle review: %w", err)
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cycle job review: %w", err)
	}
	defer tx.Rollback()
	var actionRunID, jobStatus string
	var attempts int
	var reviewDecision sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(action_run_id, ''), status, attempts, review_decision
		FROM agent_cycle_jobs WHERE task_id = ? AND program_id = ?`, taskID, programID).
		Scan(&actionRunID, &jobStatus, &attempts, &reviewDecision); err != nil {
		return fmt.Errorf("load cycle job for review: %w", err)
	}
	if jobStatus != "needs_review" || attempts < 1 || reviewDecision.Valid {
		return errors.New("cycle job is not awaiting an operator review or has already been reviewed")
	}
	if actionRunID != "" {
		run, err := loadAgentActionRun(ctx, tx, programID, actionRunID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("load cycle action run for review: %w", err)
		}
		if err == nil {
			if run.Status == "needs_review" {
				return errors.New("cycle action run has uncertain actions; resolve each with agent action-review first")
			}
			if run.Status == "active" {
				rows, err := tx.QueryContext(ctx, `SELECT id, status, COALESCE(review_decision, '') FROM agent_action_reservations
					WHERE program_id = ? AND action_run_id = ?`, programID, actionRunID)
				if err != nil {
					return fmt.Errorf("inspect cycle actions before review: %w", err)
				}
				type actionState struct{ id, status, decision string }
				var states []actionState
				for rows.Next() {
					var state actionState
					if err := rows.Scan(&state.id, &state.status, &state.decision); err != nil {
						_ = rows.Close()
						return fmt.Errorf("scan cycle action review state: %w", err)
					}
					states = append(states, state)
				}
				if err := rows.Err(); err != nil {
					_ = rows.Close()
					return fmt.Errorf("iterate cycle action review states: %w", err)
				}
				if err := rows.Close(); err != nil {
					return fmt.Errorf("close cycle action review states: %w", err)
				}
				for _, state := range states {
					switch state.status {
					case "running":
						return errors.New("cycle has an action with a live execution lease; wait for it to expire and review it first")
					case "reserved":
						if _, err := tx.ExecContext(ctx, `UPDATE agent_action_reservations SET status = 'cancelled',
							finished_at = ?, updated_at = ? WHERE id = ? AND program_id = ? AND status = 'reserved'`,
							now.Unix(), now.Unix(), state.id, programID); err != nil {
							return fmt.Errorf("cancel unstarted cycle action during review: %w", err)
						}
					case "uncertain":
						if state.decision == "" {
							return errors.New("cycle contains an uncertain action; review it with agent action-review first")
						}
					}
				}
				if _, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET status = 'failed', closed_at = ?, updated_at = ?
					WHERE id = ? AND program_id = ? AND status = 'active'`, now.Unix(), now.Unix(), actionRunID, programID); err != nil {
					return fmt.Errorf("close action run under operator cycle review: %w", err)
				}
			}
		}
	}
	status := "failed"
	if decision == "assessed_completed" {
		status = "completed"
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_cycle_jobs SET status = ?, review_decision = ?, reviewed_by = ?,
		review_note = ?, reviewed_at = ?, finished_at = ?, lease_until = NULL, updated_at = ?
		WHERE task_id = ? AND program_id = ? AND status = 'needs_review' AND review_decision IS NULL`,
		status, decision, reviewer, note, now.Unix(), now.Unix(), now.Unix(), taskID, programID)
	if err != nil {
		return fmt.Errorf("record operator cycle job review: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify cycle job review: %w", err)
		}
		return errors.New("cycle job review was already recorded or job is not awaiting review")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cycle job review: %w", err)
	}
	return nil
}

func (s *Store) ListAgentCycleJobs(ctx context.Context, programID string, limit int) ([]AgentCycleJob, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return nil, errors.New("program id is required for cycle-job listing")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT task_id, program_id, event_id, event_scope_hash, automation_revision,
		COALESCE(action_run_id, ''), request_budget, status, attempts, lease_until, COALESCE(error, ''), result_json, created_at, updated_at, finished_at,
		COALESCE(review_decision, ''), COALESCE(reviewed_by, ''), COALESCE(review_note, ''), reviewed_at
		FROM agent_cycle_jobs WHERE program_id = ? ORDER BY created_at DESC, task_id LIMIT ?`, programID, limit)
	if err != nil {
		return nil, fmt.Errorf("list program agent cycle jobs: %w", err)
	}
	defer rows.Close()
	jobs := make([]AgentCycleJob, 0)
	for rows.Next() {
		var job AgentCycleJob
		var leaseUntil, finishedAt, reviewedAt sql.NullInt64
		var createdAt, updatedAt int64
		if err := rows.Scan(&job.TaskID, &job.ProgramID, &job.EventID, &job.EventScopeHash, &job.AutomationRevision,
			&job.ActionRunID, &job.RequestBudget, &job.Status, &job.Attempts, &leaseUntil, &job.Error, &job.ResultJSON,
			&createdAt, &updatedAt, &finishedAt, &job.ReviewDecision, &job.ReviewedBy, &job.ReviewNote, &reviewedAt); err != nil {
			return nil, fmt.Errorf("scan agent cycle job: %w", err)
		}
		job.CreatedAt = time.Unix(createdAt, 0).UTC()
		job.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		if leaseUntil.Valid {
			value := time.Unix(leaseUntil.Int64, 0).UTC()
			job.LeaseUntil = &value
		}
		if finishedAt.Valid {
			value := time.Unix(finishedAt.Int64, 0).UTC()
			job.FinishedAt = &value
		}
		if reviewedAt.Valid {
			value := time.Unix(reviewedAt.Int64, 0).UTC()
			job.ReviewedAt = &value
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent cycle jobs: %w", err)
	}
	return jobs, nil
}

func sanitizeCycleEventTarget(value string) string {
	value = boundedCycleText(value, 2048)
	parsed, err := url.Parse(value)
	if err == nil && parsed.Hostname() != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		return boundedCycleText(parsed.String(), 2048)
	}
	return value
}

func boundedCycleText(value string, maximum int) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "�")
	if len(value) <= maximum {
		return value
	}
	const suffix = " [truncated]"
	maximum -= len(suffix)
	for maximum > 0 && !utf8.RuneStart(value[maximum]) {
		maximum--
	}
	if maximum <= 0 {
		return ""
	}
	return value[:maximum] + suffix
}
