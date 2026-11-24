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
	var killSwitch int
	err := s.db.QueryRowContext(ctx, `SELECT p.status, r.authorization_id, a.id, r.scope_hash, p.scope_hash, a.expires_at_ns, ks.engaged
		FROM runs r JOIN programs p ON p.id = r.program_id
		JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
		JOIN system_kill_switch ks ON ks.id = 1
		WHERE r.id = ? AND r.status = 'running'`, runID).Scan(&status, &runAuthorizationID, &currentAuthorizationID, &runScopeHash, &currentScopeHash, &expiresAtNS, &killSwitch)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("run %q is no longer active", runID)
		}
		return fmt.Errorf("validate run authorization: %w", err)
	}
	if killSwitch != 0 {
		return fmt.Errorf("%w; scheduled recon may not send requests", ErrKillSwitchEngaged)
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
