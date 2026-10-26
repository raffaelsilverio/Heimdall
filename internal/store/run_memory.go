package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

const (
	quietRunMemoryRetention   = 30 * 24 * time.Hour
	quietRunMemoryMaxSamples  = 12
	quietRunMemoryMaxKeyBytes = 512
)

type quietRunMemorySummary struct {
	SchemaVersion     int               `json:"schema_version"`
	ProgramID         string            `json:"program_id"`
	RunID             string            `json:"run_id"`
	Stage             string            `json:"stage"`
	ScopeHash         string            `json:"scope_hash"`
	CompletedAt       time.Time         `json:"completed_at"`
	ObservationCounts map[string]int    `json:"observation_counts"`
	Samples           []runMemorySample `json:"samples,omitempty"`
	Notice            string            `json:"notice"`
}

type runMemorySample struct {
	Category string `json:"category"`
	Key      string `json:"key"`
}

// captureQuietRunMemory stores a bounded, deterministic summary for a
// successful run that produced no material change event. It is written in the
// run-completion transaction and is linked to that run and scope revision.
func captureQuietRunMemory(ctx context.Context, tx *sql.Tx, programID, runID, stage, scopeHash string, observations []recon.Observation, now time.Time) error {
	if len(observations) == 0 {
		return nil
	}

	counts := make(map[string]int)
	samples := make([]runMemorySample, 0, quietRunMemoryMaxSamples)
	for _, observation := range observations {
		category := knownRunMemoryCategory(observation.Category)
		counts[category]++
		if len(samples) >= quietRunMemoryMaxSamples ||
			(observation.Category != recon.CategoryHostname && observation.Category != recon.CategoryHTTPEndpoint) {
			continue
		}
		key := cleanRunMemoryKey(observation.StableKey)
		if key == "" {
			continue
		}
		samples = append(samples, runMemorySample{Category: observation.Category, Key: key})
	}

	content, err := json.Marshal(quietRunMemorySummary{
		SchemaVersion: 1, ProgramID: programID, RunID: runID, Stage: stage, ScopeHash: scopeHash,
		CompletedAt: now.UTC(), ObservationCounts: counts, Samples: samples,
		Notice: "Deterministic summary of untrusted tool observations. It does not validate vulnerabilities or grant authorization.",
	})
	if err != nil {
		return fmt.Errorf("encode quiet-run memory summary: %w", err)
	}
	if len(content) > 16<<10 {
		return fmt.Errorf("quiet-run memory summary exceeds 16 KiB")
	}

	title := "Run summary: " + stage
	var supersedesID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM program_memories
		WHERE program_id = ? AND kind = 'fact' AND source_kind = 'run' AND title = ?
		AND scope_hash = ? AND status = 'active' ORDER BY created_at DESC, id LIMIT 1`,
		programID, title, scopeHash).Scan(&supersedesID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("find prior quiet-run memory summary: %w", err)
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `UPDATE program_memories SET status = 'superseded', updated_at = ?
			WHERE id = ? AND program_id = ? AND status = 'active'`, now.Unix(), supersedesID, programID); err != nil {
			return fmt.Errorf("supersede prior quiet-run memory summary: %w", err)
		}
	} else {
		supersedesID = ""
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO program_memories(
		id, program_id, kind, title, content, source_kind, source_id, scope_hash, confidence,
		status, observed_at, expires_at, supersedes_id, created_at, updated_at)
		VALUES (?, ?, 'fact', ?, ?, 'run', ?, ?, 1.0, 'active', ?, ?, NULLIF(?, ''), ?, ?)`,
		uuid.NewString(), programID, title, string(content), runID, scopeHash,
		now.Unix(), now.Add(quietRunMemoryRetention).Unix(), supersedesID, now.Unix(), now.Unix()); err != nil {
		return fmt.Errorf("store quiet-run memory summary: %w", err)
	}
	return nil
}

func knownRunMemoryCategory(category string) string {
	switch category {
	case recon.CategoryHostname, recon.CategoryHTTPEndpoint, recon.CategoryVulnFinding,
		"service", "tls_certificate":
		return category
	default:
		return "other"
	}
}

func cleanRunMemoryKey(value string) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "�")
	var clean strings.Builder
	for _, character := range value {
		if character == '\n' || character == '\t' || character >= 0x20 {
			clean.WriteRune(character)
		}
	}
	value = clean.String()
	if len(value) <= quietRunMemoryMaxKeyBytes {
		return value
	}
	limit := quietRunMemoryMaxKeyBytes - len("…")
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit] + "…"
}
