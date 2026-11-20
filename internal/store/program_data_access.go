package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

// GetProgramDataAccess returns the user-data policy for one program. Every
// program receives the restrictive default when it is created.
func (s *Store) GetProgramDataAccess(ctx context.Context, programID string) (assessment.DataAccessPolicy, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return assessment.DataAccessPolicy{}, errors.New("program id is required")
	}
	policy, err := loadProgramDataAccess(ctx, s.db, programID)
	if errors.Is(err, sql.ErrNoRows) {
		return assessment.DataAccessPolicy{}, fmt.Errorf("program %q not found or has no data access policy", programID)
	}
	if err != nil {
		return assessment.DataAccessPolicy{}, fmt.Errorf("get program data access policy: %w", err)
	}
	return policy, nil
}

// SetProgramDataAccess replaces one program's user-data policy and bumps its
// revision only when the normalized policy actually changes.
func (s *Store) SetProgramDataAccess(ctx context.Context, programID string, input assessment.DataAccessPolicy, now time.Time) (assessment.DataAccessPolicy, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return assessment.DataAccessPolicy{}, errors.New("program id is required")
	}
	input.Revision = 0
	normalized, err := assessment.NormalizeDataAccessPolicy(input)
	if err != nil {
		return assessment.DataAccessPolicy{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return assessment.DataAccessPolicy{}, fmt.Errorf("begin data access update: %w", err)
	}
	defer tx.Rollback()

	current, err := loadProgramDataAccess(ctx, tx, programID)
	if errors.Is(err, sql.ErrNoRows) {
		return assessment.DataAccessPolicy{}, fmt.Errorf("program %q not found", programID)
	}
	if err != nil {
		return assessment.DataAccessPolicy{}, fmt.Errorf("load current data access policy: %w", err)
	}
	if current.Equal(normalized) {
		if err := tx.Commit(); err != nil {
			return assessment.DataAccessPolicy{}, fmt.Errorf("commit unchanged data access policy: %w", err)
		}
		return current, nil
	}

	normalized.Revision = current.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE program_data_access SET mode = ?,
		allow_owned_test_accounts = ?, allow_explicitly_authorized_accounts = ?,
		allow_other_users_data = 0, revision = ?, updated_at = ? WHERE program_id = ?`,
		normalized.Mode, boolToInt(normalized.AllowOwnedTestAccounts),
		boolToInt(normalized.AllowExplicitlyAuthorizedAccounts), normalized.Revision, now.UTC().Unix(), programID)
	if err != nil {
		return assessment.DataAccessPolicy{}, fmt.Errorf("save data access policy: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return assessment.DataAccessPolicy{}, fmt.Errorf("verify saved data access policy: %w", err)
		}
		return assessment.DataAccessPolicy{}, fmt.Errorf("program %q not found", programID)
	}
	if err := tx.Commit(); err != nil {
		return assessment.DataAccessPolicy{}, fmt.Errorf("commit data access policy: %w", err)
	}
	return normalized, nil
}

type dataAccessQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadProgramDataAccess(ctx context.Context, queryer dataAccessQueryRower, programID string) (assessment.DataAccessPolicy, error) {
	var policy assessment.DataAccessPolicy
	var allowOwned, allowExplicitlyAuthorized, allowOtherUsersData int
	if err := queryer.QueryRowContext(ctx, `SELECT mode, allow_owned_test_accounts,
		allow_explicitly_authorized_accounts, allow_other_users_data, revision
		FROM program_data_access WHERE program_id = ?`, programID).Scan(
		&policy.Mode, &allowOwned, &allowExplicitlyAuthorized, &allowOtherUsersData, &policy.Revision); err != nil {
		return assessment.DataAccessPolicy{}, err
	}
	policy.AllowOwnedTestAccounts = allowOwned == 1
	policy.AllowExplicitlyAuthorizedAccounts = allowExplicitlyAuthorized == 1
	policy.AllowOtherUsersData = allowOtherUsersData == 1
	normalized, err := assessment.NormalizeDataAccessPolicy(policy)
	if err != nil {
		return assessment.DataAccessPolicy{}, fmt.Errorf("stored data access policy is invalid: %w", err)
	}
	return normalized, nil
}
