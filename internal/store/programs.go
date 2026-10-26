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

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/schedule"
)

type CreateProgramParams struct {
	Name                   string
	SourcePlatform         string
	SourceURL              string
	AuthorizationReference string
	ExpiresAt              time.Time
	Scope                  assessment.Scope
	Timezone               string
}

func normalizeProgramSource(platform, rawURL string) (string, string, error) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		if platform == "" || platform == "manual" {
			return "manual", "", nil
		}
		return "", "", fmt.Errorf("platform %q requires --program-url", platform)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.User != nil {
		return "", "", errors.New("program URL must be an absolute HTTPS URL without credentials")
	}
	if parsed.RawQuery != "" {
		return "", "", errors.New("program URL must not contain query parameters")
	}
	parsed.Scheme = "https"
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if platform == "" || platform == "auto" {
		switch {
		case host == "hackerone.com" || strings.HasSuffix(host, ".hackerone.com"):
			platform = "hackerone"
		case host == "bugcrowd.com" || strings.HasSuffix(host, ".bugcrowd.com"):
			platform = "bugcrowd"
		case host == "intigriti.com" || strings.HasSuffix(host, ".intigriti.com"):
			platform = "intigriti"
		default:
			platform = "custom"
		}
	}
	switch platform {
	case "hackerone":
		if host != "hackerone.com" && !strings.HasSuffix(host, ".hackerone.com") {
			return "", "", errors.New("HackerOne program URL must use hackerone.com")
		}
		if parsed.Port() != "" && parsed.Port() != "443" {
			return "", "", errors.New("HackerOne program URL must use the standard HTTPS port")
		}
	case "bugcrowd":
		if host != "bugcrowd.com" && !strings.HasSuffix(host, ".bugcrowd.com") {
			return "", "", errors.New("program URL must use bugcrowd.com")
		}
	case "intigriti":
		if host != "intigriti.com" && !strings.HasSuffix(host, ".intigriti.com") {
			return "", "", errors.New("program URL must use intigriti.com")
		}
	case "custom":
	case "manual":
		return "", "", errors.New("use --platform custom when attaching a non-platform HTTPS source URL")
	default:
		return "", "", fmt.Errorf("unsupported source platform %q", platform)
	}
	return platform, parsed.String(), nil
}

func (s *Store) CreateProgram(ctx context.Context, params CreateProgramParams, now time.Time) (assessment.Program, error) {
	name := strings.TrimSpace(params.Name)
	if name == "" {
		return assessment.Program{}, errors.New("program name is required")
	}
	if strings.TrimSpace(params.AuthorizationReference) == "" {
		return assessment.Program{}, errors.New("authorization reference is required")
	}
	if !params.ExpiresAt.After(now) {
		return assessment.Program{}, errors.New("authorization expiry must be in the future")
	}
	sourcePlatform, sourceURL, err := normalizeProgramSource(params.SourcePlatform, params.SourceURL)
	if err != nil {
		return assessment.Program{}, err
	}
	scope, err := assessment.NormalizeScope(params.Scope)
	if err != nil {
		return assessment.Program{}, err
	}
	scopeHash, err := assessment.ScopeFingerprint(scope)
	if err != nil {
		return assessment.Program{}, err
	}
	if params.Timezone == "" {
		params.Timezone = schedule.DefaultOSINTTimezone
	}
	if err := schedule.Validate(schedule.DefaultOSINTCron, params.Timezone); err != nil {
		return assessment.Program{}, err
	}
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return assessment.Program{}, fmt.Errorf("encode scope: %w", err)
	}
	programID := uuid.NewString()
	authorizationID := uuid.NewString()
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return assessment.Program{}, fmt.Errorf("begin program creation: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO programs(id, name, status, scope_json, scope_hash, scope_revision, created_at, updated_at, source_platform, source_url)
		VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, NULLIF(?, ''))`, programID, name, assessment.ProgramDraft, string(scopeJSON), scopeHash, now.Unix(), now.Unix(), sourcePlatform, sourceURL); err != nil {
		return assessment.Program{}, fmt.Errorf("create program: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authorizations(id, program_id, reference, expires_at, expires_at_ns, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, authorizationID, programID, strings.TrimSpace(params.AuthorizationReference),
		params.ExpiresAt.UTC().Unix(), params.ExpiresAt.UTC().UnixNano(), now.Unix()); err != nil {
		return assessment.Program{}, fmt.Errorf("create authorization: %w", err)
	}
	// The initial OSINT run is due immediately after explicit activation; later
	// runs follow the daily cron expression.
	limits := recon.DefaultStageLimits(recon.StageOSINT)
	if _, err := tx.ExecContext(ctx, `INSERT INTO stage_schedules(program_id, stage, cron_expression, timezone, enabled, next_run_at,
		rate_limit_per_second, max_concurrency, max_targets, timeout_seconds)
		VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`, programID, recon.StageOSINT, schedule.DefaultOSINTCron,
		params.Timezone, now.Unix(), limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds); err != nil {
		return assessment.Program{}, fmt.Errorf("create default OSINT schedule: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return assessment.Program{}, fmt.Errorf("commit program creation: %w", err)
	}

	return assessment.Program{
		ID:                     programID,
		Name:                   name,
		SourcePlatform:         sourcePlatform,
		SourceURL:              sourceURL,
		Status:                 assessment.ProgramDraft,
		AuthorizationReference: strings.TrimSpace(params.AuthorizationReference),
		ExpiresAt:              params.ExpiresAt.UTC(),
		Scope:                  scope,
		ScopeHash:              scopeHash,
		CreatedAt:              now,
		UpdatedAt:              now,
	}, nil
}

func (s *Store) GetProgram(ctx context.Context, id string) (assessment.Program, error) {
	program, err := scanProgram(s.db.QueryRowContext(ctx, `SELECT p.id, p.name, p.status, p.scope_json, p.scope_hash, p.source_platform, COALESCE(p.source_url, ''),
		a.reference, a.expires_at_ns, p.created_at, p.updated_at
		FROM programs p JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
		WHERE p.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return assessment.Program{}, fmt.Errorf("program %q not found", id)
	}
	if err != nil {
		return assessment.Program{}, fmt.Errorf("get program: %w", err)
	}
	return program, nil
}

func (s *Store) ListPrograms(ctx context.Context) ([]assessment.Program, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id, p.name, p.status, p.scope_json, p.scope_hash, p.source_platform, COALESCE(p.source_url, ''),
		a.reference, a.expires_at_ns, p.created_at, p.updated_at
		FROM programs p JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
		ORDER BY p.created_at, p.name`)
	if err != nil {
		return nil, fmt.Errorf("list programs: %w", err)
	}
	defer rows.Close()

	programs := make([]assessment.Program, 0)
	for rows.Next() {
		program, err := scanProgram(rows)
		if err != nil {
			return nil, fmt.Errorf("scan program: %w", err)
		}
		programs = append(programs, program)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate programs: %w", err)
	}
	return programs, nil
}

func (s *Store) ActivateProgram(ctx context.Context, id string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin activation: %w", err)
	}
	defer tx.Rollback()

	var status string
	var expiresAtNS int64
	var scopeJSON string
	if err := tx.QueryRowContext(ctx, `SELECT p.status, a.expires_at_ns, p.scope_json
		FROM programs p JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
		WHERE p.id = ?`, id).Scan(&status, &expiresAtNS, &scopeJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("program %q not found", id)
		}
		return fmt.Errorf("load program for activation: %w", err)
	}
	if !time.Unix(0, expiresAtNS).UTC().After(now.UTC()) {
		return errors.New("authorization is expired")
	}
	var pendingSourceReview int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM program_source_snapshots
		WHERE program_id = ? AND status = 'pending'`, id).Scan(&pendingSourceReview); err != nil {
		return fmt.Errorf("check pending source review: %w", err)
	}
	if pendingSourceReview > 0 {
		return errors.New("program has a pending source review; inspect and approve it before activation")
	}
	var scope assessment.Scope
	if err := json.Unmarshal([]byte(scopeJSON), &scope); err != nil {
		return fmt.Errorf("decode stored scope: %w", err)
	}
	if _, err := assessment.NormalizeScope(scope); err != nil {
		return fmt.Errorf("program scope is invalid: %w", err)
	}
	if status == string(assessment.ProgramActive) {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE programs SET status = ?, updated_at = ? WHERE id = ?`, assessment.ProgramActive, now.UTC().Unix(), id); err != nil {
		return fmt.Errorf("activate program: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET next_run_at = ?, lease_until = NULL WHERE program_id = ? AND enabled = 1`, now.UTC().Unix(), id); err != nil {
		return fmt.Errorf("enable program schedules: %w", err)
	}
	return tx.Commit()
}

func (s *Store) PauseProgram(ctx context.Context, id string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin pause: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE programs SET status = ?, updated_at = ? WHERE id = ?`, assessment.ProgramPaused, now.UTC().Unix(), id)
	if err != nil {
		return fmt.Errorf("pause program: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check paused program: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("program %q not found", id)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET lease_until = NULL WHERE program_id = ?`, id); err != nil {
		return fmt.Errorf("clear program schedule leases: %w", err)
	}
	return tx.Commit()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanProgram(row rowScanner) (assessment.Program, error) {
	var program assessment.Program
	var status string
	var scopeJSON string
	var expiresAtNS, createdAt, updatedAt int64
	if err := row.Scan(&program.ID, &program.Name, &status, &scopeJSON, &program.ScopeHash, &program.SourcePlatform, &program.SourceURL,
		&program.AuthorizationReference, &expiresAtNS, &createdAt, &updatedAt); err != nil {
		return assessment.Program{}, err
	}
	if err := json.Unmarshal([]byte(scopeJSON), &program.Scope); err != nil {
		return assessment.Program{}, fmt.Errorf("decode program scope: %w", err)
	}
	program.Status = assessment.ProgramStatus(status)
	program.ExpiresAt = time.Unix(0, expiresAtNS).UTC()
	program.CreatedAt = time.Unix(createdAt, 0).UTC()
	program.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return program, nil
}
