package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

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
