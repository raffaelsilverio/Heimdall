package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

func (s *Store) CancelReservedAgentAction(ctx context.Context, programID, runID, actionID string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	if programID == "" || strings.TrimSpace(runID) == "" || strings.TrimSpace(actionID) == "" {
		return errors.New("program id, action run id, and action id are required")
	}
	now = now.UTC().Truncate(time.Second)
	result, err := s.db.ExecContext(ctx, `UPDATE agent_action_reservations SET status = 'cancelled', finished_at = ?, updated_at = ?
		WHERE program_id = ? AND action_run_id = ? AND id = ? AND status = 'reserved'`,
		now.Unix(), now.Unix(), programID, runID, actionID)
	if err != nil {
		return fmt.Errorf("cancel reserved agent action: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify cancelled agent action: %w", err)
		}
		return errors.New("reserved agent action not found or no longer cancellable")
	}
	return nil
}

// ResolveUncertainAgentAction records an operator assessment without changing
// the action's uncertain status or returning any budget. It never replays work.
func (s *Store) ResolveUncertainAgentAction(ctx context.Context, programID, runID, actionID, decision, reviewer, note string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	actionID = strings.TrimSpace(actionID)
	decision = strings.TrimSpace(strings.ToLower(decision))
	reviewer = strings.TrimSpace(reviewer)
	note = strings.TrimSpace(note)
	if programID == "" || runID == "" || actionID == "" {
		return errors.New("program id, action run id, and action id are required")
	}
	if decision != "assessed_completed" && decision != "assessed_not_executed" {
		return errors.New("review decision must be assessed_completed or assessed_not_executed")
	}
	if reviewer == "" || len(reviewer) > 128 || note == "" || len(note) > 2048 ||
		!utf8.ValidString(reviewer) || !utf8.ValidString(note) {
		return errors.New("reviewer must be valid UTF-8 (1-128 bytes) and review note valid UTF-8 (1-2048 bytes)")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin uncertain action review: %w", err)
	}
	defer tx.Rollback()
	run, err := loadAgentActionRun(ctx, tx, programID, runID)
	if err != nil {
		return fmt.Errorf("load action run for review: %w", err)
	}
	if run.Status != "needs_review" {
		return fmt.Errorf("agent action run is %s, not awaiting uncertain-action review", run.Status)
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_reservations SET review_decision = ?, reviewed_by = ?,
		review_note = ?, reviewed_at = ?, updated_at = ?
		WHERE id = ? AND action_run_id = ? AND program_id = ? AND status = 'uncertain' AND review_decision IS NULL`,
		decision, reviewer, note, now.Unix(), now.Unix(), actionID, runID, programID)
	if err != nil {
		return fmt.Errorf("record uncertain action review: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify uncertain action review: %w", err)
		}
		return errors.New("unreviewed uncertain action not found in this program and action run")
	}
	var remaining int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_action_reservations
		WHERE action_run_id = ? AND program_id = ? AND status = 'uncertain' AND review_decision IS NULL`, runID, programID).Scan(&remaining); err != nil {
		return fmt.Errorf("count remaining uncertain action reviews: %w", err)
	}
	if remaining == 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET status = 'failed', closed_at = ?, updated_at = ?
			WHERE id = ? AND program_id = ? AND status = 'needs_review'`, now.Unix(), now.Unix(), runID, programID); err != nil {
			return fmt.Errorf("close reviewed uncertain action run: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit uncertain action review: %w", err)
	}
	return nil
}

// RecoverExpiredAgentActions marks possibly-executed actions uncertain rather
// than retrying them automatically. Their budgets remain consumed.
func (s *Store) RecoverExpiredAgentActions(ctx context.Context, now time.Time) (int64, error) {
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin expired action recovery: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_reservations SET status = 'uncertain', lease_until = NULL,
		finished_at = ?, updated_at = ? WHERE status = 'running' AND COALESCE(lease_until, 0) <= ?`,
		now.Unix(), now.Unix(), now.Unix())
	if err != nil {
		return 0, fmt.Errorf("mark expired agent actions uncertain: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count recovered agent actions: %w", err)
	}
	if count > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET status = 'needs_review', updated_at = ?
			WHERE status = 'active' AND id IN (SELECT action_run_id FROM agent_action_reservations WHERE status = 'uncertain')`, now.Unix()); err != nil {
			return 0, fmt.Errorf("mark uncertain agent action runs for review: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit expired agent action recovery: %w", err)
	}
	return count, nil
}

func (s *Store) CloseAgentActionRun(ctx context.Context, programID, runID, outcome string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if programID == "" || runID == "" {
		return errors.New("program id and agent action run id are required")
	}
	if outcome != "completed" && outcome != "failed" && outcome != "cancelled" {
		return errors.New("agent action run outcome must be completed, failed, or cancelled")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin agent action run close: %w", err)
	}
	defer tx.Rollback()
	var activeActions, uncertainActions int
	if err := tx.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(CASE WHEN status IN ('reserved', 'running') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'uncertain' THEN 1 ELSE 0 END), 0)
		FROM agent_action_reservations WHERE action_run_id = ? AND program_id = ?`, runID, programID).
		Scan(&activeActions, &uncertainActions); err != nil {
		return fmt.Errorf("check unfinished agent actions: %w", err)
	}
	if uncertainActions > 0 {
		return errors.New("agent action run has uncertain actions and requires review")
	}
	if activeActions > 0 {
		return errors.New("agent action run has reserved or running actions")
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET status = ?, closed_at = ?, updated_at = ?
		WHERE id = ? AND program_id = ? AND status = 'active'`, outcome, now.Unix(), now.Unix(), runID, programID)
	if err != nil {
		return fmt.Errorf("close agent action run: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify closed agent action run: %w", err)
		}
		return fmt.Errorf("active agent action run %q not found in program %q", runID, programID)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit agent action run close: %w", err)
	}
	return nil
}
