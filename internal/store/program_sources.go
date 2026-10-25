package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

const maxStoredProgramSourceBytes = 32 << 20

type ProgramSourceSnapshot struct {
	ID                 string
	ProgramID          string
	SourceHash         string
	CandidateScopeHash string
	SourceJSON         json.RawMessage
	CandidateScope     *assessment.Scope
	AppliedScope       *assessment.Scope
	AppliedScopeHash   string
	Warnings           []string
	Blockers           []string
	Status             string
	ScopeApplied       bool
	FetchedAt          time.Time
	ReviewedAt         *time.Time
}

// RecordProgramSourceSnapshot stores a normalized, read-only source snapshot.
// A new source revision becomes pending and pauses an active program. An exact
// repeat of the pending snapshot is idempotent.
func (s *Store) RecordProgramSourceSnapshot(
	ctx context.Context,
	programID string,
	sourceJSON []byte,
	candidate *assessment.Scope,
	warnings, blockers []string,
	now time.Time,
) (ProgramSourceSnapshot, bool, error) {
	if len(sourceJSON) > maxStoredProgramSourceBytes {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("program source snapshot exceeds %d bytes", maxStoredProgramSourceBytes)
	}
	if len(sourceJSON) == 0 || !json.Valid(sourceJSON) {
		return ProgramSourceSnapshot{}, false, errors.New("program source snapshot is not valid JSON")
	}
	trimmedJSON := bytes.TrimSpace(sourceJSON)
	if len(trimmedJSON) == 0 || trimmedJSON[0] != '{' {
		return ProgramSourceSnapshot{}, false, errors.New("program source snapshot must be a JSON object")
	}
	var compactBuffer bytes.Buffer
	if err := json.Compact(&compactBuffer, sourceJSON); err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("compact program source snapshot: %w", err)
	}
	compactJSON := compactBuffer.Bytes()
	if len(compactJSON) == 0 {
		return ProgramSourceSnapshot{}, false, errors.New("program source snapshot is empty")
	}

	var normalizedCandidate *assessment.Scope
	var candidateJSON []byte
	var candidateHash string
	if candidate != nil {
		normalized, err := assessment.NormalizeScope(*candidate)
		if err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("normalize source scope candidate: %w", err)
		}
		candidateHash, err = assessment.ScopeFingerprint(normalized)
		if err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("fingerprint source scope candidate: %w", err)
		}
		candidateJSON, err = json.Marshal(normalized)
		if err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("encode source scope candidate: %w", err)
		}
		normalizedCandidate = &normalized
	}
	warningsJSON, err := json.Marshal(warnings)
	if err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("encode source warnings: %w", err)
	}
	blockersJSON, err := json.Marshal(blockers)
	if err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("encode source blockers: %w", err)
	}
	sourceSum := sha256.Sum256(compactJSON)
	sourceHash := hex.EncodeToString(sourceSum[:])
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("begin source snapshot transaction: %w", err)
	}
	defer tx.Rollback()

	var sourcePlatform, programStatus string
	if err := tx.QueryRowContext(ctx, `SELECT source_platform, status FROM programs WHERE id = ?`, programID).
		Scan(&sourcePlatform, &programStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("program %q not found", programID)
		}
		return ProgramSourceSnapshot{}, false, fmt.Errorf("load program for source sync: %w", err)
	}
	if sourcePlatform != "hackerone" {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("program %q is not configured for HackerOne source sync", programID)
	}

	var approvedHash sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT source_hash FROM program_source_snapshots
		WHERE program_id = ? AND status IN ('approved', 'unchanged') ORDER BY fetched_at DESC, rowid DESC LIMIT 1`, programID).Scan(&approvedHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("load approved source revision: %w", err)
	}
	var pendingID, pendingHash string
	if err := tx.QueryRowContext(ctx, `SELECT id, source_hash FROM program_source_snapshots
		WHERE program_id = ? AND status = 'pending' ORDER BY fetched_at DESC LIMIT 1`, programID).Scan(&pendingID, &pendingHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("load pending source revision: %w", err)
	}

	if pendingID != "" && pendingHash == sourceHash {
		if programStatus == string(assessment.ProgramActive) {
			if _, err := tx.ExecContext(ctx, `UPDATE programs SET status = ?, updated_at = ? WHERE id = ?`, assessment.ProgramPaused, now.Unix(), programID); err != nil {
				return ProgramSourceSnapshot{}, false, fmt.Errorf("pause program with pending source review: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET lease_until = NULL WHERE program_id = ?`, programID); err != nil {
				return ProgramSourceSnapshot{}, false, fmt.Errorf("clear leases for pending source review: %w", err)
			}
		}
		snapshot, err := scanProgramSourceSnapshot(tx.QueryRowContext(ctx, sourceSnapshotSelect+` WHERE id = ?`, pendingID))
		if err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("load existing pending source snapshot: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("commit repeated source snapshot: %w", err)
		}
		return snapshot, true, nil
	}

	status := "pending"
	changed := true
	if approvedHash.Valid && approvedHash.String == sourceHash {
		status = "unchanged"
		changed = false
	}
	if _, err := tx.ExecContext(ctx, `UPDATE program_source_snapshots SET status = 'superseded'
		WHERE program_id = ? AND status = 'pending'`, programID); err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("supersede prior source review: %w", err)
	}

	snapshotID := uuid.NewString()
	var scopeHashValue, scopeJSONValue any
	if normalizedCandidate != nil {
		scopeHashValue = candidateHash
		scopeJSONValue = string(candidateJSON)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO program_source_snapshots(
		id, program_id, source_hash, candidate_scope_hash, source_json, candidate_scope_json,
		warnings_json, blockers_json, status, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, snapshotID, programID, sourceHash,
		scopeHashValue, string(compactJSON), scopeJSONValue, string(warningsJSON), string(blockersJSON), status, now.Unix()); err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("store program source snapshot: %w", err)
	}

	if status == "pending" && programStatus == string(assessment.ProgramActive) {
		if _, err := tx.ExecContext(ctx, `UPDATE programs SET status = ?, updated_at = ? WHERE id = ?`, assessment.ProgramPaused, now.Unix(), programID); err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("pause program for source review: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE stage_schedules SET lease_until = NULL WHERE program_id = ?`, programID); err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("clear leases for source review: %w", err)
		}
	}

	snapshot, err := scanProgramSourceSnapshot(tx.QueryRowContext(ctx, sourceSnapshotSelect+` WHERE id = ?`, snapshotID))
	if err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("load stored source snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("commit source snapshot: %w", err)
	}
	return snapshot, changed, nil
}

func (s *Store) GetLatestProgramSourceSnapshot(ctx context.Context, programID string) (ProgramSourceSnapshot, error) {
	snapshot, err := scanProgramSourceSnapshot(s.db.QueryRowContext(ctx, sourceSnapshotSelect+
		` WHERE program_id = ? ORDER BY fetched_at DESC, rowid DESC LIMIT 1`, programID))
	if errors.Is(err, sql.ErrNoRows) {
		return ProgramSourceSnapshot{}, fmt.Errorf("program %q has no source snapshots", programID)
	}
	if err != nil {
		return ProgramSourceSnapshot{}, fmt.Errorf("get latest program source snapshot: %w", err)
	}
	return snapshot, nil
}

// ApproveProgramSourceSnapshot either applies the reviewed source candidate or
// explicitly acknowledges the source while retaining the local scope. It
// never reactivates the program.
func (s *Store) ApproveProgramSourceSnapshot(ctx context.Context, programID string, applyCandidate bool, now time.Time) (ProgramSourceSnapshot, bool, error) {
	return s.ApproveProgramSourceSnapshotWithPorts(ctx, programID, applyCandidate, nil, now)
}

func (s *Store) ApproveProgramSourceSnapshotWithPorts(ctx context.Context, programID string, applyCandidate bool, ports []uint16, now time.Time) (ProgramSourceSnapshot, bool, error) {
	now = now.UTC()
	if !applyCandidate && len(ports) > 0 {
		return ProgramSourceSnapshot{}, false, errors.New("--port can only be used with an applied scope candidate")
	}
	for _, port := range ports {
		if port == 0 {
			return ProgramSourceSnapshot{}, false, errors.New("approved scope ports must be between 1 and 65535")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("begin source approval: %w", err)
	}
	defer tx.Rollback()

	snapshot, err := scanProgramSourceSnapshot(tx.QueryRowContext(ctx, sourceSnapshotSelect+
		` WHERE program_id = ? AND status = 'pending' ORDER BY fetched_at DESC LIMIT 1`, programID))
	if errors.Is(err, sql.ErrNoRows) {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("program %q has no pending source review", programID)
	}
	if err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("load pending source snapshot: %w", err)
	}

	scopeChanged := false
	var appliedScopeJSON, appliedScopeHash any
	if applyCandidate {
		if snapshot.CandidateScope == nil {
			return ProgramSourceSnapshot{}, false, errors.New("pending HackerOne snapshot has no representable scope candidate; use --keep-current-scope after review")
		}
		if len(snapshot.Blockers) > 0 {
			return ProgramSourceSnapshot{}, false, errors.New("pending HackerOne snapshot has unmapped or incomplete assets; use --keep-current-scope or extend the scope mapper before applying")
		}
		candidate := *snapshot.CandidateScope
		if len(ports) > 0 {
			appliedToBroadAssets := false
			for index := range candidate.Entries {
				entry := &candidate.Entries[index]
				if entry.Effect != assessment.ScopeInclude || entry.Type == assessment.ScopeURL {
					continue
				}
				entry.Ports = append([]uint16(nil), ports...)
				appliedToBroadAssets = true
			}
			if !appliedToBroadAssets {
				return ProgramSourceSnapshot{}, false, errors.New("--port only applies to included domain, wildcard, IP, and CIDR assets; this candidate has none")
			}
		}
		candidate, err := assessment.NormalizeScope(candidate)
		if err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("normalize approved scope: %w", err)
		}
		candidateHash, err := assessment.ScopeFingerprint(candidate)
		if err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("fingerprint approved scope: %w", err)
		}
		candidateJSON, err := json.Marshal(candidate)
		if err != nil {
			return ProgramSourceSnapshot{}, false, fmt.Errorf("encode approved scope candidate: %w", err)
		}
		appliedScopeHash = candidateHash
		appliedScopeJSON = string(candidateJSON)
		var currentHash string
		if err := tx.QueryRowContext(ctx, `SELECT scope_hash FROM programs WHERE id = ?`, programID).Scan(&currentHash); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ProgramSourceSnapshot{}, false, fmt.Errorf("program %q not found", programID)
			}
			return ProgramSourceSnapshot{}, false, fmt.Errorf("load current program scope: %w", err)
		}
		if currentHash != candidateHash {
			result, err := tx.ExecContext(ctx, `UPDATE programs
				SET scope_json = ?, scope_hash = ?, scope_revision = scope_revision + 1, updated_at = ?
				WHERE id = ?`, string(candidateJSON), candidateHash, now.Unix(), programID)
			if err != nil {
				return ProgramSourceSnapshot{}, false, fmt.Errorf("apply approved source scope: %w", err)
			}
			if count, err := result.RowsAffected(); err != nil || count != 1 {
				if err != nil {
					return ProgramSourceSnapshot{}, false, fmt.Errorf("verify applied source scope: %w", err)
				}
				return ProgramSourceSnapshot{}, false, fmt.Errorf("program %q not found", programID)
			}
			scopeChanged = true
		}
	}

	if _, err := tx.ExecContext(ctx, `UPDATE program_source_snapshots
		SET status = 'approved', scope_applied = ?, applied_scope_hash = ?, applied_scope_json = ?, reviewed_at = ?
		WHERE id = ? AND status = 'pending'`,
		boolToInt(applyCandidate), appliedScopeHash, appliedScopeJSON, now.Unix(), snapshot.ID); err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("approve program source snapshot: %w", err)
	}
	snapshot, err = scanProgramSourceSnapshot(tx.QueryRowContext(ctx, sourceSnapshotSelect+` WHERE id = ?`, snapshot.ID))
	if err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("reload approved source snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ProgramSourceSnapshot{}, false, fmt.Errorf("commit source approval: %w", err)
	}
	return snapshot, scopeChanged, nil
}

const sourceSnapshotSelect = `SELECT id, program_id, source_hash, COALESCE(candidate_scope_hash, ''), source_json,
	COALESCE(candidate_scope_json, ''), COALESCE(applied_scope_hash, ''), COALESCE(applied_scope_json, ''),
	warnings_json, blockers_json, status, scope_applied, fetched_at, reviewed_at
	FROM program_source_snapshots`

type sourceSnapshotScanner interface {
	Scan(dest ...any) error
}

func scanProgramSourceSnapshot(row sourceSnapshotScanner) (ProgramSourceSnapshot, error) {
	var snapshot ProgramSourceSnapshot
	var sourceJSON, candidateJSON, appliedJSON, warningsJSON, blockersJSON string
	var scopeApplied int
	var fetchedAt int64
	var reviewedAt sql.NullInt64
	if err := row.Scan(&snapshot.ID, &snapshot.ProgramID, &snapshot.SourceHash, &snapshot.CandidateScopeHash,
		&sourceJSON, &candidateJSON, &snapshot.AppliedScopeHash, &appliedJSON, &warningsJSON, &blockersJSON,
		&snapshot.Status, &scopeApplied, &fetchedAt, &reviewedAt); err != nil {
		return ProgramSourceSnapshot{}, err
	}
	snapshot.SourceJSON = json.RawMessage(sourceJSON)
	if candidateJSON != "" {
		var candidate assessment.Scope
		if err := json.Unmarshal([]byte(candidateJSON), &candidate); err != nil {
			return ProgramSourceSnapshot{}, fmt.Errorf("decode candidate scope: %w", err)
		}
		snapshot.CandidateScope = &candidate
	}
	if appliedJSON != "" {
		var applied assessment.Scope
		if err := json.Unmarshal([]byte(appliedJSON), &applied); err != nil {
			return ProgramSourceSnapshot{}, fmt.Errorf("decode applied scope: %w", err)
		}
		snapshot.AppliedScope = &applied
	}
	if err := json.Unmarshal([]byte(warningsJSON), &snapshot.Warnings); err != nil {
		return ProgramSourceSnapshot{}, fmt.Errorf("decode source warnings: %w", err)
	}
	if err := json.Unmarshal([]byte(blockersJSON), &snapshot.Blockers); err != nil {
		return ProgramSourceSnapshot{}, fmt.Errorf("decode source blockers: %w", err)
	}
	snapshot.ScopeApplied = scopeApplied != 0
	snapshot.FetchedAt = time.Unix(fetchedAt, 0).UTC()
	if reviewedAt.Valid {
		value := time.Unix(reviewedAt.Int64, 0).UTC()
		snapshot.ReviewedAt = &value
	}
	return snapshot, nil
}
