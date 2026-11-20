package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

// GetProgramRequestProfile returns the mandatory request profile for one
// program. The profile row is created with the program and defaults to the
// built-in User-Agent with no extra headers.
func (s *Store) GetProgramRequestProfile(ctx context.Context, programID string) (assessment.RequestProfile, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return assessment.RequestProfile{}, errors.New("program id is required")
	}
	profile, err := loadProgramRequestProfile(ctx, s.db, programID)
	if errors.Is(err, sql.ErrNoRows) {
		return assessment.RequestProfile{}, fmt.Errorf("program %q not found or has no request profile", programID)
	}
	if err != nil {
		return assessment.RequestProfile{}, fmt.Errorf("get program request profile: %w", err)
	}
	return profile, nil
}

// SetProgramRequestProfile replaces one program's request profile and bumps
// its revision only when the normalized profile actually changes.
func (s *Store) SetProgramRequestProfile(ctx context.Context, programID string, input assessment.RequestProfile, now time.Time) (assessment.RequestProfile, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return assessment.RequestProfile{}, errors.New("program id is required")
	}
	input.Revision = 0
	normalized, err := assessment.NormalizeRequestProfile(input)
	if err != nil {
		return assessment.RequestProfile{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return assessment.RequestProfile{}, fmt.Errorf("begin request profile update: %w", err)
	}
	defer tx.Rollback()

	current, err := loadProgramRequestProfile(ctx, tx, programID)
	if errors.Is(err, sql.ErrNoRows) {
		return assessment.RequestProfile{}, fmt.Errorf("program %q not found", programID)
	}
	if err != nil {
		return assessment.RequestProfile{}, fmt.Errorf("load current request profile: %w", err)
	}
	if sameRequestProfile(current, normalized) {
		if err := tx.Commit(); err != nil {
			return assessment.RequestProfile{}, fmt.Errorf("commit unchanged request profile: %w", err)
		}
		return current, nil
	}

	normalized.Revision = current.Revision + 1
	headersJSON, err := json.Marshal(normalized.Headers)
	if err != nil {
		return assessment.RequestProfile{}, fmt.Errorf("encode request headers: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE program_request_profiles SET user_agent = ?, headers_json = ?,
		revision = ?, updated_at = ? WHERE program_id = ?`, normalized.UserAgent, string(headersJSON),
		normalized.Revision, now.UTC().Unix(), programID)
	if err != nil {
		return assessment.RequestProfile{}, fmt.Errorf("save request profile: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return assessment.RequestProfile{}, fmt.Errorf("verify saved request profile: %w", err)
		}
		return assessment.RequestProfile{}, fmt.Errorf("program %q not found", programID)
	}
	if err := tx.Commit(); err != nil {
		return assessment.RequestProfile{}, fmt.Errorf("commit request profile: %w", err)
	}
	return normalized, nil
}

type requestProfileQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadProgramRequestProfile(ctx context.Context, queryer requestProfileQueryRower, programID string) (assessment.RequestProfile, error) {
	var profile assessment.RequestProfile
	var headersJSON string
	if err := queryer.QueryRowContext(ctx, `SELECT user_agent, headers_json, revision
		FROM program_request_profiles WHERE program_id = ?`, programID).Scan(
		&profile.UserAgent, &headersJSON, &profile.Revision); err != nil {
		return assessment.RequestProfile{}, err
	}
	if err := json.Unmarshal([]byte(headersJSON), &profile.Headers); err != nil {
		return assessment.RequestProfile{}, fmt.Errorf("decode request headers: %w", err)
	}
	normalized, err := assessment.NormalizeRequestProfile(assessment.RequestProfile{
		UserAgent: profile.UserAgent, Headers: profile.Headers, Revision: profile.Revision,
	})
	if err != nil {
		return assessment.RequestProfile{}, fmt.Errorf("stored request profile is invalid: %w", err)
	}
	return normalized, nil
}

func sameRequestProfile(left, right assessment.RequestProfile) bool {
	left.Revision = 0
	right.Revision = 0
	return left.Equal(right)
}
