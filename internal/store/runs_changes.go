package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func (s *Store) ListChangeEvents(ctx context.Context, programID string, limit int) ([]ChangeEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, program_id, run_id, stage, category, stable_key, change_type,
		COALESCE(old_value, ''), COALESCE(new_value, ''), material, created_at
		FROM change_events`
	args := []any{}
	if programID != "" {
		query += ` WHERE program_id = ?`
		args = append(args, programID)
	}
	query += ` ORDER BY created_at DESC, id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list change events: %w", err)
	}
	defer rows.Close()
	events := make([]ChangeEvent, 0)
	for rows.Next() {
		var event ChangeEvent
		var material int
		var createdAt int64
		if err := rows.Scan(&event.ID, &event.ProgramID, &event.RunID, &event.Stage, &event.Category,
			&event.StableKey, &event.ChangeType, &event.OldValue, &event.NewValue, &material, &createdAt); err != nil {
			return nil, fmt.Errorf("scan change event: %w", err)
		}
		event.Material = material != 0
		event.CreatedAt = time.Unix(createdAt, 0).UTC()
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate change events: %w", err)
	}
	return events, nil
}

func normalizeObservations(observations []recon.Observation, now time.Time) []recon.Observation {
	byKey := make(map[string]recon.Observation, len(observations))
	for _, observation := range observations {
		observation.Category = strings.TrimSpace(observation.Category)
		observation.StableKey = strings.TrimSpace(observation.StableKey)
		observation.Value = strings.TrimSpace(observation.Value)
		observation.Source = strings.TrimSpace(observation.Source)
		observation.ToolVersion = strings.TrimSpace(observation.ToolVersion)
		if observation.ObservedAt.IsZero() {
			observation.ObservedAt = now
		}
		if observation.Category == "" || observation.StableKey == "" || observation.Value == "" {
			continue
		}
		key := observation.Category + "\x00" + observation.StableKey
		byKey[key] = observation
	}
	result := make([]recon.Observation, 0, len(byKey))
	for _, observation := range byKey {
		result = append(result, observation)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Category == result[j].Category {
			return result[i].StableKey < result[j].StableKey
		}
		return result[i].Category < result[j].Category
	})
	return result
}

func insertBaselineObservation(ctx context.Context, tx *sql.Tx, programID, stage, scopeHash, profileVersion, normalizerVersion string, observation recon.Observation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO baseline_observations(
		program_id, stage, scope_hash, profile_version, normalizer_version, category, stable_key,
		normalized_value, source, first_seen_at, last_seen_at, missing_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT(program_id, stage, scope_hash, profile_version, normalizer_version, category, stable_key)
		DO UPDATE SET normalized_value = excluded.normalized_value, source = excluded.source,
			last_seen_at = excluded.last_seen_at, missing_count = 0`, programID, stage, scopeHash, profileVersion,
		normalizerVersion, observation.Category, observation.StableKey, observation.Value, observation.Source,
		observation.ObservedAt.UTC().Unix(), observation.ObservedAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("save baseline observation: %w", err)
	}
	return nil
}

func compareWithBaseline(ctx context.Context, tx *sql.Tx, programID, stage, scopeHash, profileVersion, normalizerVersion, runID string, observations []recon.Observation, now time.Time) ([]ChangeEvent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT category, stable_key, normalized_value, source, first_seen_at, missing_count
		FROM baseline_observations WHERE program_id = ? AND stage = ? AND scope_hash = ? AND profile_version = ? AND normalizer_version = ?`,
		programID, stage, scopeHash, profileVersion, normalizerVersion)
	if err != nil {
		return nil, fmt.Errorf("read baseline observations: %w", err)
	}
	type baselineFact struct {
		category, key, value, source string
		firstSeen                    int64
		missing                      int
	}
	baseline := make(map[string]baselineFact)
	for rows.Next() {
		var fact baselineFact
		if err := rows.Scan(&fact.category, &fact.key, &fact.value, &fact.source, &fact.firstSeen, &fact.missing); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan baseline observation: %w", err)
		}
		baseline[fact.category+"\x00"+fact.key] = fact
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate baseline observations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close baseline observations: %w", err)
	}

	seen := make(map[string]struct{}, len(observations))
	events := make([]ChangeEvent, 0)
	for _, observation := range observations {
		key := observation.Category + "\x00" + observation.StableKey
		seen[key] = struct{}{}
		previous, exists := baseline[key]
		if !exists {
			event, err := insertChangeEvent(ctx, tx, programID, runID, stage, scopeHash, observation.Category,
				observation.StableKey, "added", "", observation.Value, now)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		} else if previous.value != observation.Value {
			event, err := insertChangeEvent(ctx, tx, programID, runID, stage, scopeHash, observation.Category,
				observation.StableKey, "changed", previous.value, observation.Value, now)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
		if err := insertBaselineObservation(ctx, tx, programID, stage, scopeHash, profileVersion, normalizerVersion, observation); err != nil {
			return nil, err
		}
	}

	for key, fact := range baseline {
		if _, exists := seen[key]; exists {
			continue
		}
		missingCount := fact.missing + 1
		if missingCount >= 2 {
			event, err := insertChangeEvent(ctx, tx, programID, runID, stage, scopeHash, fact.category, fact.key, "removed", fact.value, "", now)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
			if _, err := tx.ExecContext(ctx, `DELETE FROM baseline_observations WHERE program_id = ? AND stage = ? AND scope_hash = ?
				AND profile_version = ? AND normalizer_version = ? AND category = ? AND stable_key = ?`,
				programID, stage, scopeHash, profileVersion, normalizerVersion, fact.category, fact.key); err != nil {
				return nil, fmt.Errorf("remove confirmed missing observation: %w", err)
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE baseline_observations SET missing_count = ? WHERE program_id = ? AND stage = ? AND scope_hash = ?
			AND profile_version = ? AND normalizer_version = ? AND category = ? AND stable_key = ?`, missingCount,
			programID, stage, scopeHash, profileVersion, normalizerVersion, fact.category, fact.key); err != nil {
			return nil, fmt.Errorf("mark observation missing: %w", err)
		}
	}
	return events, nil
}

func insertChangeEvent(ctx context.Context, tx *sql.Tx, programID, runID, stage, scopeHash, category, stableKey, changeType, oldValue, newValue string, now time.Time) (ChangeEvent, error) {
	material := isMaterial(category, changeType)
	event := ChangeEvent{
		ID:         uuid.NewString(),
		ProgramID:  programID,
		RunID:      runID,
		Stage:      stage,
		Category:   category,
		StableKey:  stableKey,
		ChangeType: changeType,
		OldValue:   oldValue,
		NewValue:   newValue,
		Material:   material,
		CreatedAt:  now,
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO change_events(id, program_id, run_id, stage, scope_hash, category, stable_key,
		change_type, old_value, new_value, material, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?)`,
		event.ID, programID, runID, stage, scopeHash, category, stableKey, changeType, oldValue, newValue, boolToInt(material), now.Unix())
	if err != nil {
		return ChangeEvent{}, fmt.Errorf("record change event: %w", err)
	}
	if err := createAgentEventSession(ctx, tx, event, scopeHash, now); err != nil {
		return ChangeEvent{}, err
	}
	return event, nil
}

func isMaterial(category, changeType string) bool {
	switch category {
	case recon.CategoryHostname, recon.CategoryHTTPEndpoint, "service", "tls_certificate", recon.CategoryVulnFinding:
		return true
	default:
		return false
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
