package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

const (
	maxAutomaticFindingCandidatesPerRun = 20
	automaticFindingRetention           = 30 * 24 * time.Hour
)

type automaticFindingCandidate struct {
	SchemaVersion int             `json:"schema_version"`
	State         string          `json:"state"`
	ProgramID     string          `json:"program_id"`
	RunID         string          `json:"run_id"`
	Stage         string          `json:"stage"`
	ScopeHash     string          `json:"scope_hash"`
	StableKey     string          `json:"stable_key"`
	Observation   json.RawMessage `json:"observation"`
	Notice        string          `json:"notice"`
}

// captureRunFindingCandidates records scanner detections only as unverified,
// expiring candidates. It never promotes a tool result to reproduced/verified.
func captureRunFindingCandidates(ctx context.Context, tx *sql.Tx, programID, runID, stage, scopeHash string, observations []recon.Observation, now time.Time) error {
	captured := 0
	for _, observation := range observations {
		if observation.Category != recon.CategoryVulnFinding || !strings.EqualFold(strings.TrimSpace(observation.Source), "nuclei") {
			continue
		}
		if captured >= maxAutomaticFindingCandidatesPerRun {
			break
		}
		stableKey := boundedMemoryBriefText(observation.StableKey, 2048)
		if stableKey == "" {
			continue
		}
		rawObservation := json.RawMessage(strings.TrimSpace(observation.Value))
		if len(rawObservation) == 0 || len(rawObservation) > 8<<10 || !json.Valid(rawObservation) {
			encoded, err := json.Marshal(boundedMemoryBriefText(observation.Value, 8<<10))
			if err != nil {
				return fmt.Errorf("encode candidate finding observation: %w", err)
			}
			rawObservation = encoded
		}
		content, err := json.Marshal(automaticFindingCandidate{
			SchemaVersion: 1, State: "candidate", ProgramID: programID, RunID: runID,
			Stage: stage, ScopeHash: scopeHash, StableKey: stableKey,
			Observation: rawObservation,
			Notice:      "Unverified scanner candidate. This is not reproduced or validated and does not authorize further testing.",
		})
		if err != nil {
			return fmt.Errorf("encode automatic finding candidate: %w", err)
		}
		if len(content) > maxProgramMemoryContentBytes {
			return fmt.Errorf("automatic finding candidate exceeds the memory content limit")
		}
		keyDigest := sha256.Sum256([]byte(stableKey))
		title := fmt.Sprintf("Candidate finding %s: %s", hex.EncodeToString(keyDigest[:6]), stableKey)
		title = boundedMemoryBriefText(title, maxProgramMemoryTitleBytes)
		var supersedesID string
		err = tx.QueryRowContext(ctx, `SELECT id FROM program_memories
			WHERE program_id = ? AND kind = 'finding_candidate' AND source_kind = 'run'
			AND title = ? AND scope_hash = ? AND status = 'active'
			ORDER BY observed_at DESC, created_at DESC LIMIT 1`, programID, title, scopeHash).Scan(&supersedesID)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("find prior finding candidate: %w", err)
		}
		if err == nil {
			if _, err := tx.ExecContext(ctx, `UPDATE program_memories SET status = 'superseded', updated_at = ?
				WHERE id = ? AND program_id = ? AND status = 'active'`, now.Unix(), supersedesID, programID); err != nil {
				return fmt.Errorf("supersede prior finding candidate: %w", err)
			}
		} else {
			supersedesID = ""
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO program_memories(
			id, program_id, kind, title, content, source_kind, source_id, scope_hash, confidence,
			status, observed_at, expires_at, supersedes_id, created_at, updated_at)
			VALUES (?, ?, 'finding_candidate', ?, ?, 'run', ?, ?, 0.5, 'active', ?, ?, NULLIF(?, ''), ?, ?)`,
			uuid.NewString(), programID, title, string(content), runID, scopeHash, now.Unix(),
			now.Add(automaticFindingRetention).Unix(), supersedesID, now.Unix(), now.Unix()); err != nil {
			return fmt.Errorf("store automatic finding candidate: %w", err)
		}
		captured++
	}
	return nil
}
