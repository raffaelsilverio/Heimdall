package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

type ProgramAgentAutomation struct {
	ProgramID               string     `json:"program_id"`
	Revision                int64      `json:"revision"`
	PolicyRevision          int64      `json:"policy_revision"`
	Enabled                 bool       `json:"enabled"`
	PlannerProvider         string     `json:"planner_provider,omitempty"`
	PlannerModel            string     `json:"planner_model,omitempty"`
	ContextEgressExpiresAt  *time.Time `json:"context_egress_expires_at,omitempty"`
	AllowModelContextEgress bool       `json:"allow_model_context_egress"`
	AllowActiveRequests     bool       `json:"allow_active_requests"`
	IncludeMemory           bool       `json:"include_memory"`
	MaxCyclesPerDay         int        `json:"max_cycles_per_day"`
	MaxRequestsPerDay       int        `json:"max_requests_per_day"`
	CyclesStartedToday      int        `json:"cycles_started_today"`
	RequestsReservedToday   int        `json:"requests_reserved_today"`
	MaxStepsPerCycle        int        `json:"max_steps_per_cycle"`
	ReviewedBy              string     `json:"reviewed_by,omitempty"`
	ReviewReason            string     `json:"review_reason,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

const maxAgentAutomationConsentDuration = 90 * 24 * time.Hour

// SetProgramAgentAutomation persists time-bounded, per-program consent. It
// does not launch a planner or enqueue work.
func (s *Store) SetProgramAgentAutomation(ctx context.Context, programID string, input ProgramAgentAutomation, now time.Time) (ProgramAgentAutomation, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return ProgramAgentAutomation{}, errors.New("program id is required for agent automation consent")
	}
	input.PlannerProvider = strings.TrimSpace(strings.ToLower(input.PlannerProvider))
	input.PlannerModel = strings.TrimSpace(input.PlannerModel)
	input.ReviewedBy = strings.TrimSpace(input.ReviewedBy)
	input.ReviewReason = strings.TrimSpace(input.ReviewReason)
	if !input.Enabled {
		return ProgramAgentAutomation{}, errors.New("use DisableProgramAgentAutomation to revoke automation consent")
	}
	if input.PlannerProvider == "" || len(input.PlannerProvider) > 128 || input.PlannerModel == "" || len(input.PlannerModel) > 256 {
		return ProgramAgentAutomation{}, errors.New("planner provider/model are required and must fit their limits")
	}
	if !input.AllowModelContextEgress || !input.AllowActiveRequests {
		return ProgramAgentAutomation{}, errors.New("automation requires separate explicit consent for model context egress and active requests")
	}
	if input.MaxCyclesPerDay < 1 || input.MaxCyclesPerDay > 50 || input.MaxRequestsPerDay < 1 || input.MaxRequestsPerDay > 10000 ||
		input.MaxStepsPerCycle < 1 || input.MaxStepsPerCycle > 20 {
		return ProgramAgentAutomation{}, errors.New("automation limits must be 1-50 cycles/day, 1-10000 requests/day, and 1-20 steps/cycle")
	}
	if input.ReviewedBy == "" || len(input.ReviewedBy) > 128 || input.ReviewReason == "" || len(input.ReviewReason) > 2048 ||
		!utf8.ValidString(input.ReviewedBy) || !utf8.ValidString(input.ReviewReason) {
		return ProgramAgentAutomation{}, errors.New("reviewed-by and review reason are required valid UTF-8 audit fields")
	}
	if input.ContextEgressExpiresAt == nil {
		return ProgramAgentAutomation{}, errors.New("model-context consent expiry is required")
	}
	now = now.UTC().Truncate(time.Second)
	expires := input.ContextEgressExpiresAt.UTC().Truncate(time.Second)
	if !expires.After(now) {
		return ProgramAgentAutomation{}, errors.New("model-context consent is expired")
	}
	if expires.After(now.Add(maxAgentAutomationConsentDuration)) {
		return ProgramAgentAutomation{}, fmt.Errorf("model-context consent cannot exceed %d days", int(maxAgentAutomationConsentDuration/(24*time.Hour)))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("begin program agent automation update: %w", err)
	}
	defer tx.Rollback()
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, programID)
	if err != nil {
		return ProgramAgentAutomation{}, err
	}
	if err := validateAgentExecutionSnapshot(snapshot, now); err != nil {
		return ProgramAgentAutomation{}, err
	}
	if expires.After(snapshot.ExpiresAt) {
		return ProgramAgentAutomation{}, errors.New("model-context consent cannot outlive current program authorization")
	}
	if !containsPolicyStage(snapshot.Policy.AllowedStages, "web") || !containsPolicyClass(snapshot.Policy.AllowedClasses, contract.ActionSafeActive) ||
		snapshot.Policy.MaxActionsPerRun < input.MaxStepsPerCycle {
		return ProgramAgentAutomation{}, errors.New("automation requires an allowlisted web/safe_active policy whose action budget covers max steps")
	}
	var enabled, rate, concurrency, targets, timeout int
	if err := tx.QueryRowContext(ctx, `SELECT enabled, rate_limit_per_second, max_concurrency, max_targets, timeout_seconds
		FROM stage_schedules WHERE program_id = ? AND stage = 'web'`, programID).
		Scan(&enabled, &rate, &concurrency, &targets, &timeout); err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("load web schedule for automation consent: %w", err)
	}
	limits := recon.StageLimits{RateLimitPerSecond: rate, MaxConcurrency: concurrency, MaxTargets: targets, TimeoutSeconds: timeout}
	if enabled != 1 {
		return ProgramAgentAutomation{}, errors.New("agent automation requires an enabled web schedule")
	}
	if err := limits.Validate(); err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("web schedule for automation is invalid: %w", err)
	}
	current, err := loadProgramAgentAutomation(ctx, tx, programID)
	if err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("load existing automation consent: %w", err)
	}
	input.ProgramID = programID
	input.PolicyRevision = snapshot.Policy.Revision
	input.ContextEgressExpiresAt = &expires
	if sameProgramAgentAutomation(current, input) {
		if err := tx.Commit(); err != nil {
			return ProgramAgentAutomation{}, fmt.Errorf("commit unchanged automation consent: %w", err)
		}
		return current, nil
	}
	input.Revision = current.Revision + 1
	input.CreatedAt = current.CreatedAt
	input.UpdatedAt = now
	result, err := tx.ExecContext(ctx, `UPDATE program_agent_automation SET revision = ?, policy_revision = ?, enabled = 1,
		planner_provider = ?, planner_model = ?, context_egress_expires_at = ?, allow_model_context_egress = 1,
		allow_active_requests = 1, include_memory = ?, max_cycles_per_day = ?, max_requests_per_day = ?, max_steps_per_cycle = ?,
		reviewed_by = ?, review_reason = ?, updated_at = ? WHERE program_id = ?`,
		input.Revision, input.PolicyRevision, input.PlannerProvider, input.PlannerModel, expires.Unix(), boolToInt(input.IncludeMemory),
		input.MaxCyclesPerDay, input.MaxRequestsPerDay, input.MaxStepsPerCycle, input.ReviewedBy, input.ReviewReason, now.Unix(), programID)
	if err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("save program agent automation consent: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return ProgramAgentAutomation{}, fmt.Errorf("verify saved automation consent: %w", err)
		}
		return ProgramAgentAutomation{}, fmt.Errorf("program %q not found", programID)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_cycle_jobs SET status = 'cancelled', lease_until = NULL,
		error = 'automation consent revision changed', finished_at = ?, updated_at = ?
		WHERE program_id = ? AND status = 'pending' AND automation_revision <> ?`,
		now.Unix(), now.Unix(), programID, input.Revision); err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("cancel pending cycles for stale consent revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("commit program agent automation consent: %w", err)
	}
	return input, nil
}

func (s *Store) DisableProgramAgentAutomation(ctx context.Context, programID, reviewedBy, reason string, now time.Time) (ProgramAgentAutomation, error) {
	programID = strings.TrimSpace(programID)
	reviewedBy = strings.TrimSpace(reviewedBy)
	reason = strings.TrimSpace(reason)
	if programID == "" || reviewedBy == "" || len(reviewedBy) > 128 || reason == "" || len(reason) > 2048 ||
		!utf8.ValidString(reviewedBy) || !utf8.ValidString(reason) {
		return ProgramAgentAutomation{}, errors.New("program id, reviewed-by, and a valid review reason are required")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("begin agent automation revocation: %w", err)
	}
	defer tx.Rollback()
	current, err := loadProgramAgentAutomation(ctx, tx, programID)
	if err != nil {
		return ProgramAgentAutomation{}, err
	}
	if !current.Enabled {
		if err := tx.Commit(); err != nil {
			return ProgramAgentAutomation{}, fmt.Errorf("commit unchanged disabled automation: %w", err)
		}
		return current, nil
	}
	current.Revision++
	current.Enabled = false
	current.ReviewedBy = reviewedBy
	current.ReviewReason = reason
	current.UpdatedAt = now
	if _, err := tx.ExecContext(ctx, `UPDATE program_agent_automation SET revision = ?, enabled = 0,
		reviewed_by = ?, review_reason = ?, updated_at = ? WHERE program_id = ? AND enabled = 1`,
		current.Revision, reviewedBy, reason, now.Unix(), programID); err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("disable program agent automation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_cycle_jobs SET status = 'cancelled', lease_until = NULL,
		error = 'automation consent revoked', finished_at = ?, updated_at = ?
		WHERE program_id = ? AND status = 'pending'`, now.Unix(), now.Unix(), programID); err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("cancel pending cycles after consent revocation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("commit agent automation revocation: %w", err)
	}
	return current, nil
}

func (s *Store) GetProgramAgentAutomation(ctx context.Context, programID string) (ProgramAgentAutomation, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return ProgramAgentAutomation{}, errors.New("program id is required")
	}
	automation, err := loadProgramAgentAutomation(ctx, s.db, programID)
	if errors.Is(err, sql.ErrNoRows) {
		return ProgramAgentAutomation{}, fmt.Errorf("program %q not found", programID)
	}
	if err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("get program agent automation: %w", err)
	}
	day := time.Now().UTC().Format("2006-01-02")
	if err := s.db.QueryRowContext(ctx, `SELECT
		COALESCE((SELECT cycles_started FROM agent_cycle_daily_usage WHERE program_id = ? AND utc_day = ?), 0),
		COALESCE((SELECT requests_reserved FROM agent_cycle_daily_usage WHERE program_id = ? AND utc_day = ?), 0)`,
		programID, day, programID, day).Scan(&automation.CyclesStartedToday, &automation.RequestsReservedToday); err != nil {
		return ProgramAgentAutomation{}, fmt.Errorf("read daily adaptive cycle usage: %w", err)
	}
	return automation, nil
}

func loadProgramAgentAutomation(ctx context.Context, queryer agentPolicyQueryRower, programID string) (ProgramAgentAutomation, error) {
	var automation ProgramAgentAutomation
	var enabled, egress, activeRequests, includeMemory int
	var egressExpiry sql.NullInt64
	var createdAt, updatedAt int64
	err := queryer.QueryRowContext(ctx, `SELECT program_id, revision, policy_revision, enabled, planner_provider, planner_model,
		context_egress_expires_at, allow_model_context_egress, allow_active_requests, include_memory,
		max_cycles_per_day, max_requests_per_day, max_steps_per_cycle, reviewed_by, review_reason, created_at, updated_at
		FROM program_agent_automation WHERE program_id = ?`, programID).Scan(
		&automation.ProgramID, &automation.Revision, &automation.PolicyRevision, &enabled, &automation.PlannerProvider, &automation.PlannerModel,
		&egressExpiry, &egress, &activeRequests, &includeMemory, &automation.MaxCyclesPerDay,
		&automation.MaxRequestsPerDay, &automation.MaxStepsPerCycle, &automation.ReviewedBy, &automation.ReviewReason, &createdAt, &updatedAt)
	if err != nil {
		return ProgramAgentAutomation{}, err
	}
	automation.Enabled = enabled != 0
	automation.AllowModelContextEgress = egress != 0
	automation.AllowActiveRequests = activeRequests != 0
	automation.IncludeMemory = includeMemory != 0
	automation.CreatedAt = time.Unix(createdAt, 0).UTC()
	automation.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if egressExpiry.Valid {
		value := time.Unix(egressExpiry.Int64, 0).UTC()
		automation.ContextEgressExpiresAt = &value
	}
	return automation, nil
}

func sameProgramAgentAutomation(left, right ProgramAgentAutomation) bool {
	return left.Enabled == right.Enabled && left.PolicyRevision == right.PolicyRevision && left.PlannerProvider == right.PlannerProvider &&
		left.PlannerModel == right.PlannerModel && sameOptionalTime(left.ContextEgressExpiresAt, right.ContextEgressExpiresAt) &&
		left.AllowModelContextEgress == right.AllowModelContextEgress && left.AllowActiveRequests == right.AllowActiveRequests &&
		left.IncludeMemory == right.IncludeMemory && left.MaxCyclesPerDay == right.MaxCyclesPerDay &&
		left.MaxRequestsPerDay == right.MaxRequestsPerDay && left.MaxStepsPerCycle == right.MaxStepsPerCycle &&
		left.ReviewedBy == right.ReviewedBy && left.ReviewReason == right.ReviewReason
}
