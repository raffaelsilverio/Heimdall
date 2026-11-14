package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *Store) RecordAgentActionPlannerCall(ctx context.Context, programID, runID, provider, model string, memoryIDs []string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	runID = strings.TrimSpace(runID)
	provider = strings.TrimSpace(provider)
	model = strings.TrimSpace(model)
	if programID == "" || runID == "" || provider == "" || model == "" {
		return errors.New("program, action run, planner provider, and model are required for planner audit")
	}
	if len(provider) > 128 || len(model) > 256 || len(memoryIDs) > 8 {
		return errors.New("planner audit provider/model or memory item list is out of bounds")
	}
	for index := range memoryIDs {
		memoryIDs[index] = strings.TrimSpace(memoryIDs[index])
		if memoryIDs[index] == "" || len(memoryIDs[index]) > 128 {
			return errors.New("planner audit memory ids must contain 1-128 bytes")
		}
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin planner call audit: %w", err)
	}
	defer tx.Rollback()
	run, err := loadAgentActionRun(ctx, tx, programID, runID)
	if err != nil {
		return fmt.Errorf("load action run for planner audit: %w", err)
	}
	snapshot, err := loadAgentExecutionSnapshot(ctx, tx, programID)
	if err != nil {
		return err
	}
	if err := validateLiveAgentActionRun(ctx, tx, run, snapshot, now); err != nil {
		return err
	}
	if run.AutomationRevision > 0 {
		automation, err := loadProgramAgentAutomation(ctx, tx, programID)
		if err != nil {
			return err
		}
		if provider != automation.PlannerProvider || model != automation.PlannerModel ||
			(len(memoryIDs) > 0 && !automation.IncludeMemory) {
			return errors.New("planner call exceeds the provider/model or memory egress consent for this program")
		}
	}
	if (run.PlannerProvider != "" && run.PlannerProvider != provider) ||
		(run.PlannerModel != "" && run.PlannerModel != model) {
		return errors.New("planner provider or model changed during the action run")
	}
	run.MemoryIDsSent = append(run.MemoryIDsSent, memoryIDs...)
	if len(run.MemoryIDsSent) > 256 {
		return errors.New("planner memory egress audit exceeds 256 note references")
	}
	memoryIDsJSON, err := json.Marshal(run.MemoryIDsSent)
	if err != nil {
		return fmt.Errorf("encode planner memory egress audit: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_action_runs SET
		planner_provider = ?, planner_model = ?, planner_calls = planner_calls + 1,
		memory_items_sent = memory_items_sent + ?, memory_ids_sent_json = ?, updated_at = ?
		WHERE id = ? AND program_id = ? AND status = 'active'`,
		provider, model, len(memoryIDs), string(memoryIDsJSON), now.Unix(), runID, programID)
	if err != nil {
		return fmt.Errorf("record agent planner call: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return fmt.Errorf("verify agent planner audit: %w", err)
		}
		return errors.New("active agent action run not found for planner audit")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit planner call audit: %w", err)
	}
	return nil
}
