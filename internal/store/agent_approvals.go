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

const (
	maxAgentApprovalsListed = 200
)

// CreateAgentApprovalRequest records one pending approval for an exact
// operation. It revalidates the current program, scope, policy revision,
// schedule-independent allowlists, and the approval-required class.
func (s *Store) CreateAgentApprovalRequest(ctx context.Context, programID string, subject contract.ApprovalSubject, requestedBy string, expiresAt, now time.Time) (contract.ActionApproval, error) {
	canonical, expiresAt, err := normalizeAgentApprovalRequest(programID, subject, requestedBy, expiresAt, now)
	if err != nil {
		return contract.ActionApproval{}, err
	}
	now = now.UTC().Truncate(time.Second)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contract.ActionApproval{}, fmt.Errorf("begin approval request: %w", err)
	}
	defer tx.Rollback()

	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, canonical.ProgramID)
	if err != nil {
		return contract.ActionApproval{}, err
	}
	if err := validateAgentApprovalRequestSnapshot(snapshot, canonical, expiresAt, now); err != nil {
		return contract.ActionApproval{}, err
	}
	fingerprint := canonical.Fingerprint()
	approval := contract.ActionApproval{
		ID: uuid.NewString(), Subject: canonical, Fingerprint: fingerprint, Status: contract.ApprovalPending,
		RequestedBy: strings.TrimSpace(requestedBy), CreatedAt: now, ExpiresAt: expiresAt,
	}
	if err := insertAgentApproval(ctx, tx, approval, now); err != nil {
		return contract.ActionApproval{}, err
	}
	if err := tx.Commit(); err != nil {
		return contract.ActionApproval{}, fmt.Errorf("commit approval request: %w", err)
	}
	return approval, nil
}

func normalizeAgentApprovalRequest(programID string, subject contract.ApprovalSubject, requestedBy string,
	expiresAt, now time.Time) (contract.ApprovalSubject, time.Time, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" || subject.ProgramID != programID {
		return contract.ApprovalSubject{}, time.Time{}, errors.New("approval request requires one matching program id")
	}
	if err := contract.ValidateApprovalActor(requestedBy, "requester"); err != nil {
		return contract.ApprovalSubject{}, time.Time{}, err
	}
	canonical, err := contract.NewApprovalSubject(subject.ProgramID, subject.ScopeHash, subject.PolicyRevision,
		subject.Stage, subject.Tool, subject.Class, subject.Targets, subject.RequestBudget)
	if err != nil {
		return contract.ApprovalSubject{}, time.Time{}, err
	}
	now = now.UTC().Truncate(time.Second)
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) {
		return contract.ApprovalSubject{}, time.Time{}, errors.New("approval expiry must be in the future")
	}
	return canonical, expiresAt, nil
}

func validateAgentApprovalRequestSnapshot(snapshot agentExecutionSnapshot, canonical contract.ApprovalSubject,
	expiresAt, now time.Time) error {
	if err := validateAgentExecutionSnapshot(snapshot, now); err != nil {
		return err
	}
	if canonical.ScopeHash != snapshot.ScopeHash || canonical.PolicyRevision != snapshot.Policy.Revision {
		return errors.New("approval request no longer matches the current scope or policy revision")
	}
	if !containsPolicyStage(snapshot.Policy.AllowedStages, canonical.Stage) || !containsPolicyClass(snapshot.Policy.AllowedClasses, canonical.Class) {
		return errors.New("approval request is for a stage or class the program does not allow")
	}
	if !containsPolicyClass(snapshot.Policy.ApprovalRequiredClasses, canonical.Class) {
		return fmt.Errorf("action class %q does not require approval under the current policy", canonical.Class)
	}
	targets, err := contract.AuthorizeTargets(snapshot.Scope, canonical.Stage, canonical.Targets, snapshot.Policy.MaxTargetsPerAction)
	if err != nil {
		return fmt.Errorf("approval targets are outside the program scope: %w", err)
	}
	if !sameActionTargets(targets, canonical.Targets) {
		return errors.New("approval targets are not canonical for the current program scope")
	}
	if expiresAt.After(snapshot.ExpiresAt) {
		return errors.New("approval expiry cannot exceed the current program authorization")
	}
	return nil
}

func insertAgentApproval(ctx context.Context, tx *sql.Tx, approval contract.ActionApproval, now time.Time) error {
	targetsJSON, err := json.Marshal(approval.Subject.Targets)
	if err != nil {
		return fmt.Errorf("encode approval targets: %w", err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO agent_action_approvals(
		id, program_id, scope_hash, policy_revision, stage, tool, action_class, impact, targets_json,
		target_count, request_budget, fingerprint, status, requested_by, created_at, expires_at, updated_at)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?
		WHERE NOT EXISTS (SELECT 1 FROM agent_action_approvals
			WHERE program_id = ? AND fingerprint = ? AND status IN ('pending', 'approved') AND expires_at > ?)`,
		approval.ID, approval.Subject.ProgramID, approval.Subject.ScopeHash, approval.Subject.PolicyRevision,
		approval.Subject.Stage, approval.Subject.Tool, string(approval.Subject.Class), string(approval.Subject.Impact),
		string(targetsJSON), len(approval.Subject.Targets), approval.Subject.RequestBudget, approval.Fingerprint,
		approval.RequestedBy, approval.CreatedAt.Unix(), approval.ExpiresAt.Unix(), now.Unix(),
		approval.Subject.ProgramID, approval.Fingerprint, now.Unix())
	if err != nil {
		return fmt.Errorf("store approval request: %w", err)
	}
	if rows, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("verify stored approval request: %w", err)
	} else if rows != 1 {
		return errors.New("an unexpired pending or approved request already exists for this exact action")
	}
	return nil
}

// DecideAgentApproval approves or denies one pending request. Approval
// revalidates the program and policy so a stale request cannot be approved.
func (s *Store) DecideAgentApproval(ctx context.Context, programID, approvalID string, approve bool, reviewer, note string, now time.Time) (contract.ActionApproval, error) {
	programID = strings.TrimSpace(programID)
	approvalID = strings.TrimSpace(approvalID)
	if programID == "" || approvalID == "" {
		return contract.ActionApproval{}, errors.New("program id and approval id are required")
	}
	reviewer, note, err := normalizeApprovalReviewer(reviewer, note)
	if err != nil {
		return contract.ActionApproval{}, err
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contract.ActionApproval{}, fmt.Errorf("begin approval decision: %w", err)
	}
	defer tx.Rollback()
	approval, err := loadAgentApproval(ctx, tx, programID, approvalID)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.ActionApproval{}, fmt.Errorf("approval %q not found for program %q", approvalID, programID)
	}
	if err != nil {
		return contract.ActionApproval{}, fmt.Errorf("load approval: %w", err)
	}
	if status := approval.EffectiveStatus(now); status != contract.ApprovalPending {
		return contract.ActionApproval{}, fmt.Errorf("approval %q is %s and cannot be decided", approvalID, status)
	}
	if approve {
		if err := validateAgentApprovalStillCurrent(ctx, tx, programID, approval, now); err != nil {
			return contract.ActionApproval{}, err
		}
	}
	nextStatus := contract.ApprovalDenied
	if approve {
		nextStatus = contract.ApprovalApproved
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_approvals SET status = ?, reviewed_by = ?,
		review_note = ?, decided_at = ?, updated_at = ? WHERE program_id = ? AND id = ? AND status = 'pending'`,
		string(nextStatus), reviewer, note, now.Unix(), now.Unix(), programID, approvalID)
	if err != nil {
		return contract.ActionApproval{}, fmt.Errorf("save approval decision: %w", err)
	}
	if rows, err := result.RowsAffected(); err != nil {
		return contract.ActionApproval{}, fmt.Errorf("verify approval decision: %w", err)
	} else if rows != 1 {
		return contract.ActionApproval{}, fmt.Errorf("approval %q is no longer pending", approvalID)
	}
	if err := tx.Commit(); err != nil {
		return contract.ActionApproval{}, fmt.Errorf("commit approval decision: %w", err)
	}
	approval.Status = nextStatus
	approval.ReviewedBy = reviewer
	approval.ReviewNote = note
	approval.DecidedAt = &now
	return approval, nil
}

func normalizeApprovalReviewer(reviewer, note string) (string, string, error) {
	reviewer = strings.TrimSpace(reviewer)
	if err := contract.ValidateApprovalActor(reviewer, "reviewer"); err != nil {
		return "", "", err
	}
	note = strings.TrimSpace(note)
	if len(note) > contract.MaxApprovalNoteBytes {
		return "", "", fmt.Errorf("approval review note must not exceed %d bytes", contract.MaxApprovalNoteBytes)
	}
	return reviewer, note, nil
}

func validateAgentApprovalStillCurrent(ctx context.Context, tx *sql.Tx, programID string,
	approval contract.ActionApproval, now time.Time) error {
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, programID)
	if err != nil {
		return err
	}
	if err := validateAgentExecutionSnapshot(snapshot, now); err != nil {
		return err
	}
	if approval.Subject.ScopeHash != snapshot.ScopeHash || approval.Subject.PolicyRevision != snapshot.Policy.Revision ||
		!containsPolicyStage(snapshot.Policy.AllowedStages, approval.Subject.Stage) ||
		!containsPolicyClass(snapshot.Policy.AllowedClasses, approval.Subject.Class) ||
		!containsPolicyClass(snapshot.Policy.ApprovalRequiredClasses, approval.Subject.Class) {
		return errors.New("approval request is stale: scope, policy revision, or allowlists changed")
	}
	return nil
}

// GetAgentApproval returns one approval record for a program.
func (s *Store) GetAgentApproval(ctx context.Context, programID, approvalID string) (contract.ActionApproval, error) {
	programID = strings.TrimSpace(programID)
	approvalID = strings.TrimSpace(approvalID)
	if programID == "" || approvalID == "" {
		return contract.ActionApproval{}, errors.New("program id and approval id are required")
	}
	approval, err := loadAgentApproval(ctx, s.db, programID, approvalID)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.ActionApproval{}, fmt.Errorf("approval %q not found for program %q", approvalID, programID)
	}
	if err != nil {
		return contract.ActionApproval{}, fmt.Errorf("get approval: %w", err)
	}
	return approval, nil
}

// ListAgentApprovals returns the most recent approvals for one program.
func (s *Store) ListAgentApprovals(ctx context.Context, programID string, limit int) ([]contract.ActionApproval, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return nil, errors.New("program id is required")
	}
	if limit < 1 || limit > maxAgentApprovalsListed {
		limit = maxAgentApprovalsListed
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, program_id, scope_hash, policy_revision, stage, tool,
		action_class, impact, targets_json, request_budget, fingerprint, status, requested_by, reviewed_by,
		review_note, created_at, expires_at, decided_at, consumed_at
		FROM agent_action_approvals WHERE program_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`, programID, limit)
	if err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	defer rows.Close()
	approvals := make([]contract.ActionApproval, 0)
	for rows.Next() {
		approval, err := scanAgentApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("decode approval: %w", err)
		}
		approvals = append(approvals, approval)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	return approvals, nil
}

// ListUsableAgentApprovals returns every approved, unexpired approval for one
// program. The policy engine selects the one whose fingerprint matches the
// candidate action; it never broadens authorization by itself.
func (s *Store) ListUsableAgentApprovals(ctx context.Context, programID string, now time.Time) ([]contract.ActionApproval, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return nil, errors.New("program id is required")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, program_id, scope_hash, policy_revision, stage, tool,
		action_class, impact, targets_json, request_budget, fingerprint, status, requested_by, reviewed_by,
		review_note, created_at, expires_at, decided_at, consumed_at
		FROM agent_action_approvals WHERE program_id = ? AND status = 'approved' AND expires_at > ?
		ORDER BY created_at, id LIMIT ?`, programID, now.UTC().Unix(), maxAgentApprovalsListed)
	if err != nil {
		return nil, fmt.Errorf("list usable approvals: %w", err)
	}
	defer rows.Close()
	approvals := make([]contract.ActionApproval, 0)
	for rows.Next() {
		approval, err := scanAgentApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("decode usable approval: %w", err)
		}
		approvals = append(approvals, approval)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list usable approvals: %w", err)
	}
	return approvals, nil
}

func loadAgentApproval(ctx context.Context, queryer agentPolicyQueryRower, programID, approvalID string) (contract.ActionApproval, error) {
	return scanAgentApproval(queryer.QueryRowContext(ctx, `SELECT id, program_id, scope_hash, policy_revision, stage, tool,
		action_class, impact, targets_json, request_budget, fingerprint, status, requested_by, reviewed_by,
		review_note, created_at, expires_at, decided_at, consumed_at
		FROM agent_action_approvals WHERE program_id = ? AND id = ?`, programID, approvalID))
}

type agentApprovalScanner interface {
	Scan(...any) error
}

func scanAgentApproval(scanner agentApprovalScanner) (contract.ActionApproval, error) {
	var approval contract.ActionApproval
	var actionClass, impact, targetsJSON string
	var createdAt, expiresAt int64
	var decidedAt, consumedAt sql.NullInt64
	if err := scanner.Scan(&approval.ID, &approval.Subject.ProgramID, &approval.Subject.ScopeHash,
		&approval.Subject.PolicyRevision, &approval.Subject.Stage, &approval.Subject.Tool, &actionClass, &impact,
		&targetsJSON, &approval.Subject.RequestBudget, &approval.Fingerprint, &approval.Status, &approval.RequestedBy,
		&approval.ReviewedBy, &approval.ReviewNote, &createdAt, &expiresAt, &decidedAt, &consumedAt); err != nil {
		return contract.ActionApproval{}, err
	}
	approval.Subject.Class = contract.ActionClass(actionClass)
	approval.Subject.Impact = contract.ActionImpact(impact)
	if err := json.Unmarshal([]byte(targetsJSON), &approval.Subject.Targets); err != nil {
		return contract.ActionApproval{}, fmt.Errorf("decode approval targets: %w", err)
	}
	approval.CreatedAt = time.Unix(createdAt, 0).UTC()
	approval.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	if decidedAt.Valid {
		value := time.Unix(decidedAt.Int64, 0).UTC()
		approval.DecidedAt = &value
	}
	if consumedAt.Valid {
		value := time.Unix(consumedAt.Int64, 0).UTC()
		approval.ConsumedAt = &value
	}
	if err := approval.Validate(); err != nil {
		return contract.ActionApproval{}, fmt.Errorf("stored approval is invalid: %w", err)
	}
	return approval, nil
}
