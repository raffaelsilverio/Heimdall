package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maxProgramMemoryTitleBytes   = 200
	maxProgramMemoryContentBytes = 64 << 10
	maxProgramMemoryQueryBytes   = 2 << 10
)

type ProgramMemory struct {
	ID                  string
	ProgramID           string
	Kind                string
	Title               string
	Content             string
	SourceKind          string
	SourceID            string
	ScopeHash           string
	SourceHash          string
	Confidence          float64
	Status              string
	ObservedAt          time.Time
	VerifiedAt          *time.Time
	ExpiresAt           *time.Time
	SupersedesID        string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	ScopeStale          bool
	SourceStale         bool
	SourceReviewPending bool
}

type AddProgramMemoryParams struct {
	ProgramID    string
	Kind         string
	Title        string
	Content      string
	SourceKind   string
	SourceID     string
	ScopeHash    string
	SourceHash   string
	Confidence   float64
	ObservedAt   time.Time
	VerifiedAt   *time.Time
	ExpiresAt    *time.Time
	SupersedesID string
}

func (s *Store) AddProgramMemory(ctx context.Context, params AddProgramMemoryParams, now time.Time) (ProgramMemory, error) {
	params.ProgramID = strings.TrimSpace(params.ProgramID)
	params.Kind = strings.TrimSpace(strings.ToLower(params.Kind))
	params.Title = strings.TrimSpace(params.Title)
	params.SourceKind = strings.TrimSpace(strings.ToLower(params.SourceKind))
	params.SourceID = strings.TrimSpace(params.SourceID)
	params.ScopeHash = strings.TrimSpace(params.ScopeHash)
	params.SourceHash = strings.TrimSpace(params.SourceHash)
	params.SupersedesID = strings.TrimSpace(params.SupersedesID)
	if params.ProgramID == "" {
		return ProgramMemory{}, errors.New("program id is required; memory is always program-scoped")
	}
	if !validProgramMemoryKind(params.Kind) {
		return ProgramMemory{}, fmt.Errorf("unsupported memory kind %q", params.Kind)
	}
	if params.Title == "" || len(params.Title) > maxProgramMemoryTitleBytes {
		return ProgramMemory{}, fmt.Errorf("memory title must contain 1-%d bytes", maxProgramMemoryTitleBytes)
	}
	if strings.TrimSpace(params.Content) == "" || len(params.Content) > maxProgramMemoryContentBytes {
		return ProgramMemory{}, fmt.Errorf("memory content must contain 1-%d bytes", maxProgramMemoryContentBytes)
	}
	if !utf8.ValidString(params.Title) || !utf8.ValidString(params.Content) || !utf8.ValidString(params.SourceID) {
		return ProgramMemory{}, errors.New("memory title, content, and source id must be valid UTF-8")
	}
	if params.SourceKind == "" {
		params.SourceKind = "operator"
	}
	if !validMemorySourceKind(params.SourceKind) {
		return ProgramMemory{}, fmt.Errorf("unsupported memory source kind %q", params.SourceKind)
	}
	if params.Confidence < 0 || params.Confidence > 1 {
		return ProgramMemory{}, errors.New("memory confidence must be between 0 and 1")
	}
	if math.IsNaN(params.Confidence) || math.IsInf(params.Confidence, 0) {
		return ProgramMemory{}, errors.New("memory confidence must be a finite number")
	}
	if len(params.SourceID) > 512 {
		return ProgramMemory{}, errors.New("memory source id exceeds 512 bytes")
	}
	if err := validateMemoryHash("scope hash", params.ScopeHash); err != nil {
		return ProgramMemory{}, err
	}
	if err := validateMemoryHash("source hash", params.SourceHash); err != nil {
		return ProgramMemory{}, err
	}
	now = now.UTC()
	if params.ObservedAt.IsZero() {
		params.ObservedAt = now
	} else {
		params.ObservedAt = params.ObservedAt.UTC()
		if params.ObservedAt.After(now.Add(5 * time.Minute)) {
			return ProgramMemory{}, errors.New("memory observed-at time is unexpectedly in the future")
		}
	}
	if params.VerifiedAt != nil {
		value := params.VerifiedAt.UTC()
		if value.After(now.Add(5 * time.Minute)) {
			return ProgramMemory{}, errors.New("memory verified-at time is unexpectedly in the future")
		}
		params.VerifiedAt = &value
	}
	if params.Kind == "finding_verified" {
		if params.VerifiedAt == nil {
			return ProgramMemory{}, errors.New("verified findings require --verified and a timestamp")
		}
		if params.SourceKind != "run" && params.SourceKind != "artifact" {
			return ProgramMemory{}, errors.New("verified findings must cite a run or artifact from the same program")
		}
	}
	if params.ExpiresAt != nil {
		value := params.ExpiresAt.UTC()
		if !value.After(now) {
			return ProgramMemory{}, errors.New("memory expiry must be in the future")
		}
		params.ExpiresAt = &value
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProgramMemory{}, fmt.Errorf("begin program memory insert: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM programs WHERE id = ?`, params.ProgramID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProgramMemory{}, fmt.Errorf("program %q not found", params.ProgramID)
		}
		return ProgramMemory{}, fmt.Errorf("check memory program: %w", err)
	}

	derivedScopeHash, derivedSourceHash, err := validateMemorySource(ctx, tx, params.ProgramID, params.Kind, params.SourceKind, params.SourceID)
	if err != nil {
		return ProgramMemory{}, err
	}
	if derivedScopeHash != "" {
		if params.ScopeHash != "" && params.ScopeHash != derivedScopeHash {
			return ProgramMemory{}, errors.New("memory scope hash does not match its cited source")
		}
		params.ScopeHash = derivedScopeHash
	}
	if derivedSourceHash != "" {
		if params.SourceHash != "" && params.SourceHash != derivedSourceHash {
			return ProgramMemory{}, errors.New("memory source hash does not match its cited source snapshot")
		}
		params.SourceHash = derivedSourceHash
	}

	if params.SupersedesID != "" {
		var oldKind, oldStatus string
		if err := tx.QueryRowContext(ctx, `SELECT kind, status FROM program_memories WHERE id = ? AND program_id = ?`,
			params.SupersedesID, params.ProgramID).Scan(&oldKind, &oldStatus); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ProgramMemory{}, errors.New("superseded memory must belong to the same program")
			}
			return ProgramMemory{}, fmt.Errorf("load superseded memory: %w", err)
		}
		if oldStatus != "active" || oldKind != params.Kind {
			return ProgramMemory{}, errors.New("only an active memory item of the same kind can be superseded")
		}
	}

	memory := ProgramMemory{
		ID: uuid.NewString(), ProgramID: params.ProgramID, Kind: params.Kind, Title: params.Title,
		Content: params.Content, SourceKind: params.SourceKind, SourceID: params.SourceID,
		ScopeHash: params.ScopeHash, SourceHash: params.SourceHash, Confidence: params.Confidence,
		Status: "active", ObservedAt: params.ObservedAt, VerifiedAt: params.VerifiedAt,
		ExpiresAt: params.ExpiresAt, SupersedesID: params.SupersedesID, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO program_memories(
		id, program_id, kind, title, content, source_kind, source_id, scope_hash, source_hash,
		confidence, status, observed_at, verified_at, expires_at, supersedes_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, 'active', ?, ?, ?, NULLIF(?, ''), ?, ?)`,
		memory.ID, memory.ProgramID, memory.Kind, memory.Title, memory.Content, memory.SourceKind, memory.SourceID,
		memory.ScopeHash, memory.SourceHash, memory.Confidence, memory.ObservedAt.Unix(), nullableUnix(memory.VerifiedAt),
		nullableUnix(memory.ExpiresAt), memory.SupersedesID, now.Unix(), now.Unix()); err != nil {
		return ProgramMemory{}, fmt.Errorf("store program memory: %w", err)
	}
	if params.SupersedesID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE program_memories SET status = 'superseded', updated_at = ?
			WHERE id = ? AND program_id = ? AND status = 'active'`, now.Unix(), params.SupersedesID, params.ProgramID); err != nil {
			return ProgramMemory{}, fmt.Errorf("supersede prior memory: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return ProgramMemory{}, fmt.Errorf("commit program memory: %w", err)
	}
	return memory, nil
}

func (s *Store) GetProgramMemory(ctx context.Context, programID, memoryID string) (ProgramMemory, error) {
	programID = strings.TrimSpace(programID)
	memoryID = strings.TrimSpace(memoryID)
	if programID == "" {
		return ProgramMemory{}, errors.New("program id is required; memory is always program-scoped")
	}
	if strings.TrimSpace(memoryID) == "" {
		return ProgramMemory{}, errors.New("memory id is required")
	}
	memory, err := scanProgramMemory(s.db.QueryRowContext(ctx, programMemorySelect+` WHERE m.program_id = ? AND m.id = ?`, programID, memoryID))
	if errors.Is(err, sql.ErrNoRows) {
		return ProgramMemory{}, fmt.Errorf("memory %q not found in program %q", memoryID, programID)
	}
	if err != nil {
		return ProgramMemory{}, fmt.Errorf("get program memory: %w", err)
	}
	return s.annotateMemoryFreshness(ctx, memory)
}

func (s *Store) ListProgramMemories(ctx context.Context, programID string, limit int, now time.Time) ([]ProgramMemory, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return nil, errors.New("program id is required; memory is always program-scoped")
	}
	if err := s.requireMemoryProgram(ctx, programID); err != nil {
		return nil, err
	}
	limit = normalizeMemoryLimit(limit)
	rows, err := s.db.QueryContext(ctx, programMemorySelect+` WHERE m.program_id = ? AND m.status = 'active'
		AND (m.expires_at IS NULL OR m.expires_at > ?) ORDER BY m.observed_at DESC, m.id LIMIT ?`,
		programID, now.UTC().Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("list program memory: %w", err)
	}
	defer rows.Close()
	memories, err := scanProgramMemories(rows)
	if err != nil {
		return nil, err
	}
	return s.annotateMemoriesFreshness(ctx, memories)
}

func (s *Store) SearchProgramMemories(ctx context.Context, programID, query string, limit int, now time.Time) ([]ProgramMemory, error) {
	programID = strings.TrimSpace(programID)
	query = strings.TrimSpace(query)
	if programID == "" {
		return nil, errors.New("program id is required; memory is always program-scoped")
	}
	if err := s.requireMemoryProgram(ctx, programID); err != nil {
		return nil, err
	}
	if query == "" || len(query) > maxProgramMemoryQueryBytes {
		return nil, fmt.Errorf("memory query must contain 1-%d bytes", maxProgramMemoryQueryBytes)
	}
	ftsQuery, err := quotedMemoryQuery(query)
	if err != nil {
		return nil, err
	}
	limit = normalizeMemoryLimit(limit)
	rows, err := s.db.QueryContext(ctx, `SELECT `+memoryColumns+`
		FROM program_memory_fts f
		JOIN program_memories m ON m.rowid = f.rowid AND m.id = f.memory_id AND m.program_id = f.program_id
		WHERE program_memory_fts MATCH ? AND f.program_id = ? AND m.status = 'active'
		AND (m.expires_at IS NULL OR m.expires_at > ?)
		ORDER BY CASE WHEN instr(lower(m.title), lower(?)) > 0 THEN 0 ELSE 1 END,
		m.observed_at DESC, m.id LIMIT ?`, ftsQuery, programID, now.UTC().Unix(), query, limit)
	if err != nil {
		return nil, fmt.Errorf("search program memory: %w", err)
	}
	defer rows.Close()
	memories, err := scanProgramMemories(rows)
	if err != nil {
		return nil, err
	}
	return s.annotateMemoriesFreshness(ctx, memories)
}

func (s *Store) requireMemoryProgram(ctx context.Context, programID string) error {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM programs WHERE id = ?`, programID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("program %q not found", programID)
		}
		return fmt.Errorf("check memory program: %w", err)
	}
	return nil
}

func (s *Store) ArchiveProgramMemory(ctx context.Context, programID, memoryID string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	memoryID = strings.TrimSpace(memoryID)
	if programID == "" {
		return errors.New("program id is required; memory is always program-scoped")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE program_memories SET status = 'archived', updated_at = ?
		WHERE program_id = ? AND id = ? AND status = 'active'`, now.UTC().Unix(), programID, memoryID)
	if err != nil {
		return fmt.Errorf("archive program memory: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check archived program memory: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("active memory %q not found in program %q", memoryID, programID)
	}
	return nil
}

func (s *Store) RestoreProgramMemory(ctx context.Context, programID, memoryID string, now time.Time) error {
	programID = strings.TrimSpace(programID)
	memoryID = strings.TrimSpace(memoryID)
	if programID == "" {
		return errors.New("program id is required; memory is always program-scoped")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE program_memories SET status = 'active', updated_at = ?
		WHERE program_id = ? AND id = ? AND status = 'archived'
		AND (expires_at IS NULL OR expires_at > ?)`, now.UTC().Unix(), programID, memoryID, now.UTC().Unix())
	if err != nil {
		return fmt.Errorf("restore program memory: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check restored program memory: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("unexpired archived memory %q not found in program %q", memoryID, programID)
	}
	return nil
}
