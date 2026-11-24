package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// MaxKillSwitchActorBytes bounds the operator identifier recorded on a
	// kill-switch transition.
	MaxKillSwitchActorBytes = 96
	// MaxKillSwitchReasonBytes bounds the human-readable reason.
	MaxKillSwitchReasonBytes = 512
)

// ErrKillSwitchEngaged is returned whenever execution is refused because the
// global kill switch is engaged.
var ErrKillSwitchEngaged = errors.New("global kill switch is engaged")

// KillSwitchState is the durable, observable global execution halt. It is
// independent of any program, consent, or policy: while engaged, no agent
// action, approval, scheduled run, or cycle may start or send a request.
type KillSwitchState struct {
	Engaged   bool      `json:"engaged"`
	Reason    string    `json:"reason,omitempty"`
	ChangedBy string    `json:"changed_by,omitempty"`
	ChangedAt time.Time `json:"changed_at"`
	Revision  int64     `json:"revision"`
}

// GetKillSwitch returns the current global kill-switch state.
func (s *Store) GetKillSwitch(ctx context.Context) (KillSwitchState, error) {
	state, err := loadKillSwitch(ctx, s.db)
	if err != nil {
		return KillSwitchState{}, fmt.Errorf("load kill switch: %w", err)
	}
	return state, nil
}

// SetKillSwitch engages or releases the global kill switch. Every transition
// requires an operator, a printable reason, and increments the audit revision;
// repeating the current state is idempotent and does not create a new revision.
func (s *Store) SetKillSwitch(ctx context.Context, engaged bool, actor, reason string, now time.Time) (KillSwitchState, error) {
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if err := validateKillSwitchText(actor, "operator", MaxKillSwitchActorBytes); err != nil {
		return KillSwitchState{}, err
	}
	if err := validateKillSwitchText(reason, "reason", MaxKillSwitchReasonBytes); err != nil {
		return KillSwitchState{}, err
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return KillSwitchState{}, fmt.Errorf("begin kill-switch update: %w", err)
	}
	defer tx.Rollback()
	current, err := loadKillSwitch(ctx, tx)
	if err != nil {
		return KillSwitchState{}, fmt.Errorf("load kill switch: %w", err)
	}
	if current.Engaged == engaged {
		return current, nil
	}
	engagedValue := 0
	if engaged {
		engagedValue = 1
	}
	if _, err := tx.ExecContext(ctx, `UPDATE system_kill_switch SET engaged = ?, reason = ?, changed_by = ?,
		changed_at = ?, revision = revision + 1 WHERE id = 1`, engagedValue, reason, actor, now.Unix()); err != nil {
		return KillSwitchState{}, fmt.Errorf("save kill switch: %w", err)
	}
	updated, err := loadKillSwitch(ctx, tx)
	if err != nil {
		return KillSwitchState{}, fmt.Errorf("reload kill switch: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return KillSwitchState{}, fmt.Errorf("commit kill switch: %w", err)
	}
	return updated, nil
}

func loadKillSwitch(ctx context.Context, queryer agentPolicyQueryRower) (KillSwitchState, error) {
	var engaged int
	var changedAt int64
	var state KillSwitchState
	if err := queryer.QueryRowContext(ctx, `SELECT engaged, reason, changed_by, changed_at, revision
		FROM system_kill_switch WHERE id = 1`).Scan(&engaged, &state.Reason, &state.ChangedBy, &changedAt, &state.Revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KillSwitchState{}, errors.New("system kill switch row is missing")
		}
		return KillSwitchState{}, err
	}
	state.Engaged = engaged == 1
	if changedAt > 0 {
		state.ChangedAt = time.Unix(changedAt, 0).UTC()
	}
	return state, nil
}

// killSwitchEngaged reports whether execution is globally halted. A missing or
// unreadable row is an error, never an implicit release.
func killSwitchEngaged(ctx context.Context, queryer agentPolicyQueryRower) (bool, error) {
	state, err := loadKillSwitch(ctx, queryer)
	if err != nil {
		return false, err
	}
	return state.Engaged, nil
}

func validateKillSwitchText(value, field string, maximum int) error {
	if value == "" || len(value) > maximum {
		return fmt.Errorf("kill-switch %s must be between 1 and %d bytes", field, maximum)
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return fmt.Errorf("kill-switch %s must use printable ASCII", field)
		}
	}
	return nil
}
