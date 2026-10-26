package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

type ChangeEvent struct {
	ID         string
	ProgramID  string
	RunID      string
	Stage      string
	Category   string
	StableKey  string
	ChangeType string
	OldValue   string
	NewValue   string
	Material   bool
	CreatedAt  time.Time
}

func (s *Store) ValidateRunAuthorization(ctx context.Context, runID string, now time.Time) error {
	var status, runAuthorizationID, currentAuthorizationID, runScopeHash, currentScopeHash string
	var expiresAtNS int64
	err := s.db.QueryRowContext(ctx, `SELECT p.status, r.authorization_id, a.id, r.scope_hash, p.scope_hash, a.expires_at_ns
		FROM runs r JOIN programs p ON p.id = r.program_id
		JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
		WHERE r.id = ? AND r.status = 'running'`, runID).Scan(&status, &runAuthorizationID, &currentAuthorizationID, &runScopeHash, &currentScopeHash, &expiresAtNS)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("run %q is no longer active", runID)
		}
		return fmt.Errorf("validate run authorization: %w", err)
	}
	if status != "active" {
		return fmt.Errorf("program is %s", status)
	}
	if runAuthorizationID != currentAuthorizationID {
		return fmt.Errorf("run authorization has been replaced")
	}
	if expiresAtNS <= now.UTC().UnixNano() {
		return fmt.Errorf("authorization has expired")
	}
	if runScopeHash != currentScopeHash {
		return fmt.Errorf("program scope changed after the run was scheduled")
	}
	return nil
}

func (s *Store) CompleteRun(ctx context.Context, runID string, collection recon.Collection, complete bool, runErr error, now time.Time) ([]ChangeEvent, error) {
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin run completion: %w", err)
	}
	defer tx.Rollback()

	var programID, authorizationID, stage, trigger, scopeHash, profileVersion, normalizerVersion string
	if err := tx.QueryRowContext(ctx, `SELECT program_id, authorization_id, stage, trigger, scope_hash, profile_version, normalizer_version
		FROM runs WHERE id = ? AND status = 'running'`, runID).Scan(&programID, &authorizationID, &stage, &trigger, &scopeHash, &profileVersion, &normalizerVersion); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("running job %q not found", runID)
		}
		return nil, fmt.Errorf("load running job: %w", err)
	}
	if collection.ProfileVersion != "" {
		profileVersion = collection.ProfileVersion
		if _, err := tx.ExecContext(ctx, `UPDATE runs SET profile_version = ? WHERE id = ?`, profileVersion, runID); err != nil {
			return nil, fmt.Errorf("record profile version: %w", err)
		}
	}
	toolVersions := make(map[string]string, len(collection.Tools))
	for _, tool := range collection.Tools {
		toolVersions[tool.ID] = tool.Version
		if _, err := tx.ExecContext(ctx, `INSERT INTO tool_runs(run_id, tool_id, binary, version, status, error)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(run_id, tool_id) DO UPDATE SET binary = excluded.binary,
			version = excluded.version, status = excluded.status, error = excluded.error`,
			runID, tool.ID, tool.Binary, tool.Version, tool.Status, nullIfEmpty(tool.Error)); err != nil {
			return nil, fmt.Errorf("record tool run %s: %w", tool.ID, err)
		}
	}
	if err := s.persistArtifacts(ctx, tx, programID, runID, collection.Artifacts, now); err != nil {
		return nil, err
	}

	observations := collection.Observations
	for index := range observations {
		if observations[index].ToolVersion == "" {
			observations[index].ToolVersion = toolVersions[observations[index].Source]
		}
	}
	observations = normalizeObservations(observations, now)
	for _, observation := range observations {
		if _, err := tx.ExecContext(ctx, `INSERT INTO observations(run_id, category, stable_key, normalized_value, source, tool_version, observed_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(run_id, category, stable_key) DO UPDATE SET
			normalized_value = excluded.normalized_value, source = excluded.source,
			tool_version = excluded.tool_version, observed_at = excluded.observed_at`, runID,
			observation.Category, observation.StableKey, observation.Value, observation.Source,
			observation.ToolVersion, observation.ObservedAt.UTC().Unix()); err != nil {
			return nil, fmt.Errorf("save observation: %w", err)
		}
	}

	var programStatus, currentAuthorizationID string
	var expiresAtNS int64
	if err := tx.QueryRowContext(ctx, `SELECT p.status, a.id, a.expires_at_ns FROM programs p
		JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL WHERE p.id = ?`, programID).
		Scan(&programStatus, &currentAuthorizationID, &expiresAtNS); err != nil {
		return nil, fmt.Errorf("revalidate authorization before completing run: %w", err)
	}

	status := "complete"
	errorText := ""
	if programStatus != "active" || currentAuthorizationID != authorizationID || expiresAtNS <= now.UnixNano() {
		status = "interrupted"
		errorText = "program paused or authorization expired before run completion"
	} else if runErr != nil {
		status = "failed"
		errorText = runErr.Error()
	} else if !complete {
		status = "partial"
		errorText = "collection did not complete"
	}

	events := make([]ChangeEvent, 0)
	if status == "complete" {
		var establishedAt int64
		err := tx.QueryRowContext(ctx, `SELECT established_at FROM baselines WHERE program_id = ? AND stage = ? AND scope_hash = ?
			AND profile_version = ? AND normalizer_version = ?`, programID, stage, scopeHash, profileVersion, normalizerVersion).Scan(&establishedAt)
		if err == sql.ErrNoRows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO baselines(program_id, stage, scope_hash, profile_version, normalizer_version, established_at, last_complete_run_id)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, programID, stage, scopeHash, profileVersion, normalizerVersion, now.Unix(), runID); err != nil {
				return nil, fmt.Errorf("create baseline: %w", err)
			}
			for _, observation := range observations {
				if err := insertBaselineObservation(ctx, tx, programID, stage, scopeHash, profileVersion, normalizerVersion, observation); err != nil {
					return nil, err
				}
			}
		} else if err != nil {
			return nil, fmt.Errorf("find baseline: %w", err)
		} else {
			events, err = compareWithBaseline(ctx, tx, programID, stage, scopeHash, profileVersion, normalizerVersion, runID, observations, now)
			if err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE baselines SET last_complete_run_id = ? WHERE program_id = ? AND stage = ? AND scope_hash = ?
				AND profile_version = ? AND normalizer_version = ?`, runID, programID, stage, scopeHash, profileVersion, normalizerVersion); err != nil {
				return nil, fmt.Errorf("advance baseline: %w", err)
			}
		}
	}

	if _, err := tx.ExecContext(ctx, `UPDATE runs SET status = ?, finished_at = ?, error = NULLIF(?, '') WHERE id = ?`, status, now.Unix(), errorText, runID); err != nil {
		return nil, fmt.Errorf("finish run: %w", err)
	}
	if status == "complete" {
		if err := captureRunFindingCandidates(ctx, tx, programID, runID, stage, scopeHash, observations, now); err != nil {
			return nil, err
		}
	}
	// Material events already enter the dedicated event-triage/handoff queue.
	// Quiet runs get a compact factual summary instead, never a finding verdict.
	if status == "complete" && !hasMaterialChangeEvent(events) {
		if err := captureQuietRunMemory(ctx, tx, programID, runID, stage, scopeHash, observations, now); err != nil {
			return nil, err
		}
	}
	if trigger == "schedule" {
		if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET lease_until = NULL, last_run_at = ? WHERE program_id = ? AND stage = ?`, now.Unix(), programID, stage); err != nil {
			return nil, fmt.Errorf("release schedule lease: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit run completion: %w", err)
	}
	return events, nil
}

func hasMaterialChangeEvent(events []ChangeEvent) bool {
	for _, event := range events {
		if event.Material {
			return true
		}
	}
	return false
}

type ArtifactRecord struct {
	ID           string
	RunID        string
	RelativePath string
	MediaType    string
	SHA256       string
	SizeBytes    int64
	CreatedAt    time.Time
}

func (s *Store) ListArtifacts(ctx context.Context, runID string) ([]ArtifactRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, run_id, relative_path, media_type, sha256, size_bytes, created_at
		FROM artifacts WHERE run_id = ? ORDER BY relative_path`, runID)
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}
	defer rows.Close()
	records := make([]ArtifactRecord, 0)
	for rows.Next() {
		var record ArtifactRecord
		var createdAt int64
		if err := rows.Scan(&record.ID, &record.RunID, &record.RelativePath, &record.MediaType,
			&record.SHA256, &record.SizeBytes, &createdAt); err != nil {
			return nil, fmt.Errorf("scan artifact: %w", err)
		}
		record.CreatedAt = time.Unix(createdAt, 0).UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifacts: %w", err)
	}
	return records, nil
}

func (s *Store) LatestRunStatus(ctx context.Context, programID, stage string) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM runs WHERE program_id = ? AND stage = ? ORDER BY started_at DESC LIMIT 1`, programID, stage).Scan(&status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("no runs found for program %q stage %q", programID, stage)
		}
		return "", fmt.Errorf("read latest run status: %w", err)
	}
	return status, nil
}

var artifactNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

func (s *Store) persistArtifacts(ctx context.Context, tx *sql.Tx, programID, runID string, artifacts []recon.Artifact, now time.Time) error {
	for _, artifact := range artifacts {
		if !artifactNamePattern.MatchString(artifact.Name) || filepath.Base(artifact.Name) != artifact.Name || artifact.Name == "." || artifact.Name == ".." {
			return fmt.Errorf("invalid artifact name %q", artifact.Name)
		}
		if len(artifact.Data) > 32<<20 {
			return fmt.Errorf("artifact %q exceeds the 32 MiB storage limit", artifact.Name)
		}
		directory := filepath.Join(s.homeDir, "artifacts", programID, runID)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create artifact directory: %w", err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return fmt.Errorf("restrict artifact directory permissions: %w", err)
		}
		finalPath := filepath.Join(directory, artifact.Name)
		temporaryPath := finalPath + ".tmp-" + uuid.NewString()
		file, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("create artifact file: %w", err)
		}
		_, writeErr := io.Copy(file, bytes.NewReader(artifact.Data))
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			_ = os.Remove(temporaryPath)
			return fmt.Errorf("write artifact %q: %w", artifact.Name, errors.Join(writeErr, syncErr, closeErr))
		}
		if err := os.Rename(temporaryPath, finalPath); err != nil {
			_ = os.Remove(temporaryPath)
			return fmt.Errorf("commit artifact file: %w", err)
		}
		if err := os.Chmod(finalPath, 0o600); err != nil {
			return fmt.Errorf("restrict artifact file permissions: %w", err)
		}
		sum := sha256.Sum256(artifact.Data)
		relativePath, err := filepath.Rel(s.homeDir, finalPath)
		if err != nil {
			return fmt.Errorf("resolve artifact path: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO artifacts(id, run_id, relative_path, media_type, sha256, size_bytes, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, uuid.NewString(), runID, filepath.ToSlash(relativePath), artifact.MediaType,
			hex.EncodeToString(sum[:]), len(artifact.Data), now.UTC().Unix()); err != nil {
			return fmt.Errorf("record artifact: %w", err)
		}
	}
	return nil
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

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
