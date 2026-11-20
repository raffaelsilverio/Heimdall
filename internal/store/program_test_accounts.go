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

// ListProgramTestAccounts returns the registered test accounts for one
// program, ordered by stable id. It never resolves credential references.
func (s *Store) ListProgramTestAccounts(ctx context.Context, programID string) ([]assessment.TestAccount, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return nil, errors.New("program id is required")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT account_id, identity, role, status, source,
		credential_ref, created_at, updated_at FROM program_test_accounts
		WHERE program_id = ? ORDER BY account_id`, programID)
	if err != nil {
		return nil, fmt.Errorf("list program test accounts: %w", err)
	}
	defer rows.Close()
	accounts := make([]assessment.TestAccount, 0)
	for rows.Next() {
		account, err := scanTestAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("decode test account: %w", err)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list program test accounts: %w", err)
	}
	return accounts, nil
}

// AddProgramTestAccount registers one authorized test account. The record
// stores metadata and an optional credential reference only.
func (s *Store) AddProgramTestAccount(ctx context.Context, programID string, input assessment.TestAccount, now time.Time) (assessment.TestAccount, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return assessment.TestAccount{}, errors.New("program id is required")
	}
	normalized, err := assessment.NormalizeTestAccount(input)
	if err != nil {
		return assessment.TestAccount{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return assessment.TestAccount{}, fmt.Errorf("begin test account registration: %w", err)
	}
	defer tx.Rollback()

	var programExists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM program_data_access WHERE program_id = ?`, programID).Scan(&programExists); err != nil {
		return assessment.TestAccount{}, fmt.Errorf("check program: %w", err)
	}
	if programExists == 0 {
		return assessment.TestAccount{}, fmt.Errorf("program %q not found", programID)
	}
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM program_test_accounts WHERE program_id = ?`, programID).Scan(&total); err != nil {
		return assessment.TestAccount{}, fmt.Errorf("count test accounts: %w", err)
	}
	if total >= assessment.MaxProgramTestAccounts {
		return assessment.TestAccount{}, fmt.Errorf("program already has the maximum of %d test accounts", assessment.MaxProgramTestAccounts)
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM program_test_accounts WHERE program_id = ? AND account_id = ?`,
		programID, normalized.ID).Scan(&existing); err != nil {
		return assessment.TestAccount{}, fmt.Errorf("check test account id: %w", err)
	}
	if existing != 0 {
		return assessment.TestAccount{}, fmt.Errorf("test account %q already exists for program %q", normalized.ID, programID)
	}
	timestamp := now.UTC().Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO program_test_accounts(program_id, account_id, identity,
		role, status, source, credential_ref, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		programID, normalized.ID, normalized.Identity, normalized.Role, normalized.Status,
		normalized.Source, normalized.CredentialRef, timestamp, timestamp); err != nil {
		return assessment.TestAccount{}, fmt.Errorf("save test account: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return assessment.TestAccount{}, fmt.Errorf("commit test account registration: %w", err)
	}
	normalized.CreatedAt = time.Unix(timestamp, 0).UTC()
	normalized.UpdatedAt = normalized.CreatedAt
	return normalized, nil
}

// RevokeProgramTestAccount marks one account as revoked. Revocation is
// idempotent and never deletes the audit record.
func (s *Store) RevokeProgramTestAccount(ctx context.Context, programID, accountID string, now time.Time) (assessment.TestAccount, error) {
	programID = strings.TrimSpace(programID)
	accountID = strings.TrimSpace(accountID)
	if programID == "" || accountID == "" {
		return assessment.TestAccount{}, errors.New("program id and account id are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return assessment.TestAccount{}, fmt.Errorf("begin test account revocation: %w", err)
	}
	defer tx.Rollback()
	account, err := loadProgramTestAccount(ctx, tx, programID, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return assessment.TestAccount{}, fmt.Errorf("test account %q not found for program %q", accountID, programID)
	}
	if err != nil {
		return assessment.TestAccount{}, fmt.Errorf("load test account: %w", err)
	}
	if account.Status == assessment.TestAccountStatusRevoked {
		if err := tx.Commit(); err != nil {
			return assessment.TestAccount{}, fmt.Errorf("commit unchanged test account revocation: %w", err)
		}
		return account, nil
	}
	timestamp := now.UTC().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE program_test_accounts SET status = ?, updated_at = ?
		WHERE program_id = ? AND account_id = ?`, assessment.TestAccountStatusRevoked, timestamp, programID, accountID); err != nil {
		return assessment.TestAccount{}, fmt.Errorf("revoke test account: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return assessment.TestAccount{}, fmt.Errorf("commit test account revocation: %w", err)
	}
	account.Status = assessment.TestAccountStatusRevoked
	account.UpdatedAt = time.Unix(timestamp, 0).UTC()
	return account, nil
}

type testAccountQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadProgramTestAccount(ctx context.Context, queryer testAccountQueryer, programID, accountID string) (assessment.TestAccount, error) {
	return scanTestAccount(queryer.QueryRowContext(ctx, `SELECT account_id, identity, role, status, source,
		credential_ref, created_at, updated_at FROM program_test_accounts
		WHERE program_id = ? AND account_id = ?`, programID, accountID))
}

type testAccountScanner interface {
	Scan(...any) error
}

func scanTestAccount(scanner testAccountScanner) (assessment.TestAccount, error) {
	var account assessment.TestAccount
	var createdAt, updatedAt int64
	if err := scanner.Scan(&account.ID, &account.Identity, &account.Role, &account.Status,
		&account.Source, &account.CredentialRef, &createdAt, &updatedAt); err != nil {
		return assessment.TestAccount{}, err
	}
	account.CreatedAt = time.Unix(createdAt, 0).UTC()
	account.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	normalized, err := assessment.NormalizeTestAccount(account)
	if err != nil {
		return assessment.TestAccount{}, fmt.Errorf("stored test account is invalid: %w", err)
	}
	return normalized, nil
}
