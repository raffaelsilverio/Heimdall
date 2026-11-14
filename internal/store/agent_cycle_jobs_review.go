package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

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
