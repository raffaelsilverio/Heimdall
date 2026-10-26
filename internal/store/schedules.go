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
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/schedule"
)

type DueJob struct {
	RunID           string
	AuthorizationID string
	Program         assessment.Program
	Stage           string
	CronExpression  string
	Timezone        string
	ScheduledFor    time.Time
	Limits          recon.StageLimits
}

type StageSchedule struct {
	ProgramID      string
	Stage          string
	CronExpression string
	Timezone       string
	Enabled        bool
	NextRun        time.Time
	Limits         recon.StageLimits
}

type dueSchedule struct {
	programID string
	stage     string
	cron      string
	timezone  string
	nextRun   int64
	limits    recon.StageLimits
}

func (s *Store) SetStageSchedule(ctx context.Context, programID, stage, expression, timezone string, enabled bool, now time.Time, configuredLimits ...recon.StageLimits) error {
	stage = strings.ToLower(strings.TrimSpace(stage))
	if stage != recon.StageOSINT && stage != recon.StageDNS && stage != recon.StageWeb && stage != recon.StageNmap && stage != recon.StageCrawl && stage != recon.StageFFUF && stage != recon.StageNuclei {
		return fmt.Errorf("unsupported stage %q", stage)
	}
	if err := schedule.Validate(expression, timezone); err != nil {
		return err
	}
	limits := recon.DefaultStageLimits(stage)
	var existing recon.StageLimits
	err := s.db.QueryRowContext(ctx, `SELECT rate_limit_per_second, max_concurrency, max_targets, timeout_seconds
		FROM stage_schedules WHERE program_id = ? AND stage = ?`, programID, stage).Scan(
		&existing.RateLimitPerSecond, &existing.MaxConcurrency, &existing.MaxTargets, &existing.TimeoutSeconds)
	if err == nil {
		limits = existing
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load existing stage limits: %w", err)
	}
	limits = mergeConfiguredStageLimits(limits, configuredLimits)
	if err := limits.Validate(); err != nil {
		return err
	}
	nextRun, err := schedule.Next(expression, timezone, now)
	if err != nil {
		return err
	}
	var enabledValue int
	if enabled {
		enabledValue = 1
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO stage_schedules(program_id, stage, cron_expression, timezone, enabled, next_run_at,
		rate_limit_per_second, max_concurrency, max_targets, timeout_seconds)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(program_id, stage) DO UPDATE SET cron_expression = excluded.cron_expression,
			timezone = excluded.timezone, enabled = excluded.enabled, next_run_at = excluded.next_run_at, lease_until = NULL,
			rate_limit_per_second = excluded.rate_limit_per_second, max_concurrency = excluded.max_concurrency,
			max_targets = excluded.max_targets, timeout_seconds = excluded.timeout_seconds`,
		programID, stage, expression, timezone, enabledValue, nextRun.Unix(), limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds)
	if err != nil {
		return fmt.Errorf("save stage schedule: %w", err)
	}
	return nil
}

func mergeConfiguredStageLimits(limits recon.StageLimits, configured []recon.StageLimits) recon.StageLimits {
	if len(configured) == 0 {
		return limits
	}
	provided := configured[0]
	if provided.RateLimitPerSecond != 0 {
		limits.RateLimitPerSecond = provided.RateLimitPerSecond
	}
	if provided.MaxConcurrency != 0 {
		limits.MaxConcurrency = provided.MaxConcurrency
	}
	if provided.MaxTargets != 0 {
		limits.MaxTargets = provided.MaxTargets
	}
	if provided.TimeoutSeconds != 0 {
		limits.TimeoutSeconds = provided.TimeoutSeconds
	}
	return limits
}

func (s *Store) InScopeHostSeeds(ctx context.Context, programID, scopeHash string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT bo.stable_key FROM baseline_observations bo
		WHERE bo.program_id = ? AND bo.scope_hash = ? AND bo.category = ? AND bo.missing_count = 0 AND bo.stage IN (?, ?)
		AND bo.profile_version = (SELECT r.profile_version FROM runs r
			WHERE r.program_id = bo.program_id AND r.stage = bo.stage AND r.scope_hash = bo.scope_hash AND r.status = 'complete'
			ORDER BY r.started_at DESC LIMIT 1)
		ORDER BY stable_key`, programID, scopeHash, recon.CategoryHostname, recon.StageOSINT, recon.StageDNS)
	if err != nil {
		return nil, fmt.Errorf("load in-scope host seeds: %w", err)
	}
	defer rows.Close()
	hosts := make([]string, 0)
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, fmt.Errorf("scan host seed: %w", err)
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host seeds: %w", err)
	}
	return hosts, nil
}

func (s *Store) InScopeEndpointSeeds(ctx context.Context, programID, scopeHash string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT bo.stable_key FROM baseline_observations bo
		WHERE bo.program_id = ? AND bo.scope_hash = ? AND bo.category = ? AND bo.missing_count = 0 AND bo.stage = ?
		AND bo.profile_version = (SELECT r.profile_version FROM runs r
			WHERE r.program_id = bo.program_id AND r.stage = bo.stage AND r.scope_hash = bo.scope_hash AND r.status = 'complete'
			ORDER BY r.started_at DESC LIMIT 1)
		ORDER BY bo.stable_key`, programID, scopeHash, recon.CategoryHTTPEndpoint, recon.StageWeb)
	if err != nil {
		return nil, fmt.Errorf("load in-scope endpoint seeds: %w", err)
	}
	defer rows.Close()
	endpoints := make([]string, 0)
	for rows.Next() {
		var endpoint string
		if err := rows.Scan(&endpoint); err != nil {
			return nil, fmt.Errorf("scan endpoint seed: %w", err)
		}
		endpoints = append(endpoints, endpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate endpoint seeds: %w", err)
	}
	return endpoints, nil
}

func (s *Store) ListStageSchedules(ctx context.Context, programID string) ([]StageSchedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT program_id, stage, cron_expression, timezone, enabled, next_run_at,
		rate_limit_per_second, max_concurrency, max_targets, timeout_seconds
		FROM stage_schedules WHERE program_id = ? ORDER BY stage`, programID)
	if err != nil {
		return nil, fmt.Errorf("list stage schedules: %w", err)
	}
	defer rows.Close()
	schedules := make([]StageSchedule, 0)
	for rows.Next() {
		var item StageSchedule
		var enabled int
		var nextRun int64
		if err := rows.Scan(&item.ProgramID, &item.Stage, &item.CronExpression, &item.Timezone, &enabled, &nextRun,
			&item.Limits.RateLimitPerSecond, &item.Limits.MaxConcurrency, &item.Limits.MaxTargets, &item.Limits.TimeoutSeconds); err != nil {
			return nil, fmt.Errorf("scan stage schedule: %w", err)
		}
		item.Enabled = enabled != 0
		item.NextRun = time.Unix(nextRun, 0).UTC()
		schedules = append(schedules, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stage schedules: %w", err)
	}
	return schedules, nil
}

func (s *Store) ClaimDueSchedules(ctx context.Context, now time.Time, leaseDuration time.Duration) ([]DueJob, error) {
	now = now.UTC()
	if leaseDuration <= 0 {
		leaseDuration = 2 * time.Hour
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin schedule claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE programs SET status = ?, updated_at = ?
		WHERE status = ? AND EXISTS (SELECT 1 FROM authorizations a WHERE a.program_id = programs.id AND a.replaced_at IS NULL AND a.expires_at_ns <= ?)`,
		assessment.ProgramPaused, now.Unix(), assessment.ProgramActive, now.UnixNano()); err != nil {
		return nil, fmt.Errorf("pause expired programs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET enabled = 0, lease_until = NULL
		WHERE program_id IN (SELECT program_id FROM authorizations WHERE replaced_at IS NULL AND expires_at_ns <= ?)`, now.UnixNano()); err != nil {
		return nil, fmt.Errorf("disable expired schedules: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT program_id, stage, cron_expression, timezone, next_run_at,
		rate_limit_per_second, max_concurrency, max_targets, timeout_seconds
		FROM stage_schedules
		WHERE enabled = 1 AND next_run_at <= ? AND (lease_until IS NULL OR lease_until <= ?)
		ORDER BY next_run_at LIMIT 1`, now.Unix(), now.Unix())
	if err != nil {
		return nil, fmt.Errorf("find due schedules: %w", err)
	}
	due := make([]dueSchedule, 0)
	for rows.Next() {
		var item dueSchedule
		if err := rows.Scan(&item.programID, &item.stage, &item.cron, &item.timezone, &item.nextRun,
			&item.limits.RateLimitPerSecond, &item.limits.MaxConcurrency, &item.limits.MaxTargets, &item.limits.TimeoutSeconds); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read due schedule: %w", err)
		}
		due = append(due, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate due schedules: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close due schedules: %w", err)
	}

	jobs := make([]DueJob, 0, len(due))
	for _, item := range due {
		program, authorizationID, err := getProgramAndAuthorization(ctx, tx, item.programID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, fmt.Errorf("load scheduled program: %w", err)
		}

		if !program.ExpiresAt.After(now) {
			if _, err := tx.ExecContext(ctx, `UPDATE programs SET status = ?, updated_at = ? WHERE id = ?`, assessment.ProgramPaused, now.Unix(), item.programID); err != nil {
				return nil, fmt.Errorf("pause expired program: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET enabled = 0, lease_until = NULL WHERE program_id = ?`, item.programID); err != nil {
				return nil, fmt.Errorf("disable expired program schedules: %w", err)
			}
			continue
		}

		nextRun, err := schedule.Next(item.cron, item.timezone, now)
		if err != nil {
			return nil, fmt.Errorf("calculate next run for program %q: %w", item.programID, err)
		}
		if program.Status != assessment.ProgramActive {
			if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET next_run_at = ?, lease_until = NULL WHERE program_id = ? AND stage = ?`, nextRun.Unix(), item.programID, item.stage); err != nil {
				return nil, fmt.Errorf("advance inactive schedule: %w", err)
			}
			continue
		}

		runID := uuid.NewString()
		insert, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO runs(
			id, program_id, authorization_id, stage, trigger, scheduled_for, scope_hash,
			profile_version, normalizer_version, status, started_at)
			VALUES (?, ?, ?, ?, 'schedule', ?, ?, ?, ?, 'running', ?)`, runID, item.programID, authorizationID,
			item.stage, item.nextRun, program.ScopeHash, recon.DefaultProfileVersion(item.stage), recon.NormalizerVersion, now.Unix())
		if err != nil {
			return nil, fmt.Errorf("create scheduled run: %w", err)
		}
		inserted, err := insert.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("check scheduled run: %w", err)
		}
		if inserted == 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET next_run_at = ?, lease_until = NULL WHERE program_id = ? AND stage = ?`, nextRun.Unix(), item.programID, item.stage); err != nil {
				return nil, fmt.Errorf("advance duplicate schedule: %w", err)
			}
			continue
		}

		if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET next_run_at = ?, last_scheduled_for = ?, lease_until = ?
			WHERE program_id = ? AND stage = ?`, nextRun.Unix(), item.nextRun, now.Add(leaseDuration).Unix(), item.programID, item.stage); err != nil {
			return nil, fmt.Errorf("lease stage schedule: %w", err)
		}
		jobs = append(jobs, DueJob{
			RunID:           runID,
			AuthorizationID: authorizationID,
			Program:         program,
			Stage:           item.stage,
			CronExpression:  item.cron,
			Timezone:        item.timezone,
			ScheduledFor:    time.Unix(item.nextRun, 0).UTC(),
			Limits:          item.limits,
		})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit schedule claim: %w", err)
	}
	return jobs, nil
}

func getProgramAndAuthorization(ctx context.Context, tx *sql.Tx, id string) (assessment.Program, string, error) {
	var program assessment.Program
	var status, scopeJSON string
	var expiresAtNS, createdAt, updatedAt int64
	var authorizationID string
	err := tx.QueryRowContext(ctx, `SELECT p.id, p.name, p.status, p.scope_json, p.scope_hash, p.source_platform, COALESCE(p.source_url, ''),
		a.id, a.reference, a.expires_at_ns, p.created_at, p.updated_at
		FROM programs p JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL WHERE p.id = ?`, id).
		Scan(&program.ID, &program.Name, &status, &scopeJSON, &program.ScopeHash, &program.SourcePlatform, &program.SourceURL, &authorizationID,
			&program.AuthorizationReference, &expiresAtNS, &createdAt, &updatedAt)
	if err != nil {
		return assessment.Program{}, "", err
	}
	if err := json.Unmarshal([]byte(scopeJSON), &program.Scope); err != nil {
		return assessment.Program{}, "", fmt.Errorf("decode program scope: %w", err)
	}
	program.Status = assessment.ProgramStatus(status)
	program.ExpiresAt = time.Unix(0, expiresAtNS).UTC()
	program.CreatedAt = time.Unix(createdAt, 0).UTC()
	program.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return program, authorizationID, nil
}
