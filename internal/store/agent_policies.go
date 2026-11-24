package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
)

func (s *Store) GetProgramAgentPolicy(ctx context.Context, programID string) (contract.ProgramAgentPolicy, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return contract.ProgramAgentPolicy{}, errors.New("program id is required")
	}
	policy, err := loadProgramAgentPolicy(ctx, s.db, programID)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("program %q not found or has no agent policy", programID)
	}
	if err != nil {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("get program agent policy: %w", err)
	}
	return policy, nil
}

// SetProgramAgentPolicy replaces one program's policy. Empty stage/class
// allowlists with zero budgets are the explicit deny-all policy.

func (s *Store) SetProgramAgentPolicy(ctx context.Context, programID string, input contract.ProgramAgentPolicy, now time.Time) (contract.ProgramAgentPolicy, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return contract.ProgramAgentPolicy{}, errors.New("program id is required")
	}
	input.Revision = 1
	normalized, err := contract.NormalizeProgramAgentPolicy(input)
	if err != nil {
		return contract.ProgramAgentPolicy{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("begin program agent policy update: %w", err)
	}
	defer tx.Rollback()

	current, err := loadProgramAgentPolicy(ctx, tx, programID)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("program %q not found", programID)
	}
	if err != nil {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("load current program agent policy: %w", err)
	}
	if sameAgentPolicy(current, normalized) {
		if err := tx.Commit(); err != nil {
			return contract.ProgramAgentPolicy{}, fmt.Errorf("commit unchanged agent policy: %w", err)
		}
		return current, nil
	}

	normalized.Revision = current.Revision + 1
	if err := persistProgramAgentPolicy(ctx, tx, programID, normalized, now); err != nil {
		return contract.ProgramAgentPolicy{}, err
	}
	if err := tx.Commit(); err != nil {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("commit program agent policy: %w", err)
	}
	return normalized, nil
}

func persistProgramAgentPolicy(ctx context.Context, tx *sql.Tx, programID string, policy contract.ProgramAgentPolicy, now time.Time) error {
	stagesJSON, err := json.Marshal(policy.AllowedStages)
	if err != nil {
		return fmt.Errorf("encode allowed agent stages: %w", err)
	}
	classesJSON, err := json.Marshal(policy.AllowedClasses)
	if err != nil {
		return fmt.Errorf("encode allowed agent classes: %w", err)
	}
	approvalClassesJSON, err := json.Marshal(policy.ApprovalRequiredClasses)
	if err != nil {
		return fmt.Errorf("encode approval-required agent classes: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE program_agent_policies SET revision = ?, allowed_stages_json = ?,
		allowed_classes_json = ?, approval_required_classes_json = ?, max_actions_per_run = ?, max_requests_per_run = ?,
		max_requests_per_action = ?, max_targets_per_action = ?, updated_at = ? WHERE program_id = ?`, policy.Revision,
		string(stagesJSON), string(classesJSON), string(approvalClassesJSON), policy.MaxActionsPerRun,
		policy.MaxRequestsPerRun, policy.MaxRequestsPerAction, policy.MaxTargetsPerAction,
		now.UTC().Unix(), programID)
	if err != nil {
		return fmt.Errorf("save program agent policy: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("verify saved program agent policy: %w", err)
	} else if count != 1 {
		return fmt.Errorf("program %q not found", programID)
	}
	return nil
}

func (s *Store) HasPendingProgramSourceReview(ctx context.Context, programID string) (bool, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return false, errors.New("program id is required")
	}
	var pending int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM program_source_snapshots WHERE program_id = ? AND status = 'pending')`, programID).Scan(&pending); err != nil {
		return false, fmt.Errorf("check pending program source review: %w", err)
	}
	return pending != 0, nil
}

type agentPolicyQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadProgramAgentPolicy(ctx context.Context, queryer agentPolicyQueryRower, programID string) (contract.ProgramAgentPolicy, error) {
	var policy contract.ProgramAgentPolicy
	var stagesJSON, classesJSON, approvalClassesJSON string
	if err := queryer.QueryRowContext(ctx, `SELECT revision, allowed_stages_json, allowed_classes_json,
		approval_required_classes_json, max_actions_per_run, max_requests_per_run, max_requests_per_action, max_targets_per_action
		FROM program_agent_policies WHERE program_id = ?`, programID).Scan(
		&policy.Revision, &stagesJSON, &classesJSON, &approvalClassesJSON, &policy.MaxActionsPerRun, &policy.MaxRequestsPerRun,
		&policy.MaxRequestsPerAction, &policy.MaxTargetsPerAction); err != nil {
		return contract.ProgramAgentPolicy{}, err
	}
	if err := json.Unmarshal([]byte(stagesJSON), &policy.AllowedStages); err != nil {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("decode allowed stages: %w", err)
	}
	if err := json.Unmarshal([]byte(classesJSON), &policy.AllowedClasses); err != nil {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("decode allowed action classes: %w", err)
	}
	if err := json.Unmarshal([]byte(approvalClassesJSON), &policy.ApprovalRequiredClasses); err != nil {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("decode approval-required action classes: %w", err)
	}
	normalized, err := contract.NormalizeProgramAgentPolicy(policy)
	if err != nil {
		return contract.ProgramAgentPolicy{}, fmt.Errorf("stored agent policy is invalid: %w", err)
	}
	return normalized, nil
}

func sameAgentPolicy(left, right contract.ProgramAgentPolicy) bool {
	if left.MaxActionsPerRun != right.MaxActionsPerRun || left.MaxRequestsPerRun != right.MaxRequestsPerRun ||
		left.MaxRequestsPerAction != right.MaxRequestsPerAction || left.MaxTargetsPerAction != right.MaxTargetsPerAction ||
		len(left.AllowedStages) != len(right.AllowedStages) || len(left.AllowedClasses) != len(right.AllowedClasses) ||
		len(left.ApprovalRequiredClasses) != len(right.ApprovalRequiredClasses) {
		return false
	}
	for index := range left.AllowedStages {
		if left.AllowedStages[index] != right.AllowedStages[index] {
			return false
		}
	}
	for index := range left.AllowedClasses {
		if left.AllowedClasses[index] != right.AllowedClasses[index] {
			return false
		}
	}
	for index := range left.ApprovalRequiredClasses {
		if left.ApprovalRequiredClasses[index] != right.ApprovalRequiredClasses[index] {
			return false
		}
	}
	return true
}
