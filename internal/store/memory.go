package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
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

func validateMemorySource(ctx context.Context, tx *sql.Tx, programID, memoryKind, sourceKind, sourceID string) (string, string, error) {
	if sourceKind == "operator" {
		return "", "", nil
	}
	if sourceID == "" {
		return "", "", fmt.Errorf("source id is required for memory source kind %q", sourceKind)
	}
	var scopeHash, sourceHash string
	var err error
	var runStatus string
	switch sourceKind {
	case "run":
		err = tx.QueryRowContext(ctx, `SELECT scope_hash, status FROM runs WHERE id = ? AND program_id = ?`, sourceID, programID).Scan(&scopeHash, &runStatus)
	case "event":
		err = tx.QueryRowContext(ctx, `SELECT scope_hash FROM change_events WHERE id = ? AND program_id = ?`, sourceID, programID).Scan(&scopeHash)
	case "session":
		err = tx.QueryRowContext(ctx, `SELECT scope_hash FROM sessions WHERE id = ? AND program_id = ?`, sourceID, programID).Scan(&scopeHash)
	case "source_snapshot":
		var candidateHash sql.NullString
		err = tx.QueryRowContext(ctx, `SELECT source_hash, COALESCE(applied_scope_hash, candidate_scope_hash, '') FROM program_source_snapshots
			WHERE id = ? AND program_id = ?`, sourceID, programID).Scan(&sourceHash, &candidateHash)
		if err == nil && candidateHash.String != "" {
			scopeHash = candidateHash.String
		}
	case "artifact":
		err = tx.QueryRowContext(ctx, `SELECT r.scope_hash, r.status FROM artifacts a JOIN runs r ON r.id = a.run_id
			WHERE a.id = ? AND r.program_id = ?`, sourceID, programID).Scan(&scopeHash, &runStatus)
	default:
		return "", "", fmt.Errorf("unsupported memory source kind %q", sourceKind)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("memory source %q was not found in program %q", sourceID, programID)
	}
	if err != nil {
		return "", "", fmt.Errorf("validate memory source: %w", err)
	}
	if memoryKind == "finding_verified" && runStatus != "complete" {
		return "", "", errors.New("verified findings must cite evidence from a complete run")
	}
	return scopeHash, sourceHash, nil
}

func (s *Store) annotateMemoriesFreshness(ctx context.Context, memories []ProgramMemory) ([]ProgramMemory, error) {
	if len(memories) == 0 {
		return memories, nil
	}
	programID := memories[0].ProgramID
	var currentScopeHash string
	var currentSourceHash sql.NullString
	var pendingReview int
	if err := s.db.QueryRowContext(ctx, `SELECT p.scope_hash,
		(SELECT source_hash FROM program_source_snapshots WHERE program_id = p.id AND status IN ('approved', 'unchanged')
		 ORDER BY fetched_at DESC, rowid DESC LIMIT 1),
		(SELECT COUNT(*) FROM program_source_snapshots WHERE program_id = p.id AND status = 'pending')
		FROM programs p WHERE p.id = ?`, programID).Scan(&currentScopeHash, &currentSourceHash, &pendingReview); err != nil {
		return nil, fmt.Errorf("load program memory context: %w", err)
	}
	for index := range memories {
		memory := &memories[index]
		memory.ScopeStale = memory.ScopeHash != "" && memory.ScopeHash != currentScopeHash
		memory.SourceReviewPending = pendingReview > 0
		if memory.SourceKind == "source_snapshot" && memory.SourceHash != "" {
			memory.SourceStale = memory.SourceReviewPending || !currentSourceHash.Valid || memory.SourceHash != currentSourceHash.String
		}
	}
	return memories, nil
}

func (s *Store) annotateMemoryFreshness(ctx context.Context, memory ProgramMemory) (ProgramMemory, error) {
	memories, err := s.annotateMemoriesFreshness(ctx, []ProgramMemory{memory})
	if err != nil {
		return ProgramMemory{}, err
	}
	return memories[0], nil
}

type memoryRowScanner interface {
	Scan(dest ...any) error
}

type memoryRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

const memoryColumns = `m.id, m.program_id, m.kind, m.title, m.content, m.source_kind, COALESCE(m.source_id, ''),
	COALESCE(m.scope_hash, ''), COALESCE(m.source_hash, ''), m.confidence, m.status, m.observed_at,
	m.verified_at, m.expires_at, COALESCE(m.supersedes_id, ''), m.created_at, m.updated_at`

const programMemorySelect = `SELECT ` + memoryColumns + ` FROM program_memories m`

func scanProgramMemory(row memoryRowScanner) (ProgramMemory, error) {
	var memory ProgramMemory
	var observedAt, createdAt, updatedAt int64
	var verifiedAt, expiresAt sql.NullInt64
	if err := row.Scan(&memory.ID, &memory.ProgramID, &memory.Kind, &memory.Title, &memory.Content,
		&memory.SourceKind, &memory.SourceID, &memory.ScopeHash, &memory.SourceHash, &memory.Confidence,
		&memory.Status, &observedAt, &verifiedAt, &expiresAt, &memory.SupersedesID, &createdAt, &updatedAt); err != nil {
		return ProgramMemory{}, err
	}
	memory.ObservedAt = time.Unix(observedAt, 0).UTC()
	memory.CreatedAt = time.Unix(createdAt, 0).UTC()
	memory.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if verifiedAt.Valid {
		value := time.Unix(verifiedAt.Int64, 0).UTC()
		memory.VerifiedAt = &value
	}
	if expiresAt.Valid {
		value := time.Unix(expiresAt.Int64, 0).UTC()
		memory.ExpiresAt = &value
	}
	return memory, nil
}

func scanProgramMemories(rows memoryRows) ([]ProgramMemory, error) {
	memories := make([]ProgramMemory, 0)
	for rows.Next() {
		memory, err := scanProgramMemory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan program memory: %w", err)
		}
		memories = append(memories, memory)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate program memory: %w", err)
	}
	return memories, nil
}

func validProgramMemoryKind(kind string) bool {
	switch kind {
	case "fact", "hypothesis", "negative_result", "decision", "finding_candidate", "finding_verified", "procedure", "handoff":
		return true
	default:
		return false
	}
}

func validMemorySourceKind(kind string) bool {
	switch kind {
	case "operator", "run", "event", "session", "source_snapshot", "artifact":
		return true
	default:
		return false
	}
}

func quotedMemoryQuery(query string) (string, error) {
	terms := strings.Fields(query)
	quoted := make([]string, 0, len(terms))
	hasWord := false
	for _, term := range terms {
		for _, character := range term {
			if unicode.IsLetter(character) || unicode.IsNumber(character) {
				hasWord = true
				break
			}
		}
		term = strings.ReplaceAll(term, `"`, `""`)
		quoted = append(quoted, `"`+term+`"`)
	}
	if !hasWord {
		return "", errors.New("memory search query must contain a letter or number")
	}
	return strings.Join(quoted, " AND "), nil
}

func normalizeMemoryLimit(limit int) int {
	if limit <= 0 || limit > 100 {
		return 20
	}
	return limit
}

func nullableUnix(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Unix()
}

func validateMemoryHash(name, value string) error {
	if value == "" {
		return nil
	}
	if len(value) != 64 {
		return fmt.Errorf("%s must be a 64-character SHA-256 hex digest", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be a SHA-256 hex digest", name)
	}
	return nil
}
