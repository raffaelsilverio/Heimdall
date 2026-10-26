package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
)

const maxAgentEventTriageAttempts = 5

const (
	maxTriageMemoryCandidates = 20
	maxTriageMemoryItems      = 5
	maxTriageMemoryTitleBytes = 200
	maxTriageMemoryBodyBytes  = 1200
	maxTriageMemoryTotalBytes = 8 << 10
)

// Compatibility aliases keep the persistence API convenient while shared
// application contracts live outside the SQLite adapter package.
type AgentEventTaskLease = contract.TaskLease
type AgentEventTriageContext = contract.TriageContext
type AgentEventTriageOutput = contract.TriageOutput
type AgentEventTriageResult = contract.TriageResult

var (
	ErrAgentEventTriageLeaseLost      = contract.ErrTriageLeaseLost
	ErrAgentEventTriageContextChanged = contract.ErrTriageContextChanged
)

type AgentTaskStatus struct {
	ID             string
	ProgramID      string
	EventID        string
	SessionID      string
	Status         string
	TriageStatus   string
	Attempts       int
	TriageAttempts int
	CreatedAt      time.Time
	TriagedAt      *time.Time
	TriageError    string
}

func (s *Store) ListAgentTaskStatuses(ctx context.Context, programID string, limit int) ([]AgentTaskStatus, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return nil, errors.New("program id is required; agent tasks are always program-scoped")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.id, e.program_id, t.event_id, COALESCE(t.session_id, ''),
		t.status, j.status, t.attempts, j.attempts, t.created_at, j.triaged_at, COALESCE(j.error, '')
		FROM agent_tasks t JOIN change_events e ON e.id = t.event_id
		JOIN agent_event_triage_jobs j ON j.task_id = t.id
		WHERE e.program_id = ? ORDER BY t.created_at DESC, t.id LIMIT ?`, programID, limit)
	if err != nil {
		return nil, fmt.Errorf("list program agent tasks: %w", err)
	}
	defer rows.Close()
	items := make([]AgentTaskStatus, 0)
	for rows.Next() {
		var item AgentTaskStatus
		var createdAt int64
		var triagedAt sql.NullInt64
		if err := rows.Scan(&item.ID, &item.ProgramID, &item.EventID, &item.SessionID, &item.Status,
			&item.TriageStatus, &item.Attempts, &item.TriageAttempts, &createdAt, &triagedAt, &item.TriageError); err != nil {
			return nil, fmt.Errorf("scan program agent task: %w", err)
		}
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		if triagedAt.Valid {
			value := time.Unix(triagedAt.Int64, 0).UTC()
			item.TriagedAt = &value
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate program agent tasks: %w", err)
	}
	return items, nil
}

func (s *Store) RetryAgentEventTriage(ctx context.Context, programID, taskID string) error {
	programID = strings.TrimSpace(programID)
	taskID = strings.TrimSpace(taskID)
	if programID == "" || taskID == "" {
		return errors.New("program id and task id are required")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE agent_event_triage_jobs
		SET status = 'pending', attempts = 0, lease_until = NULL, triaged_at = NULL, error = NULL, updated_at = unixepoch()
		WHERE task_id = ? AND status = 'failed'
		AND task_id IN (SELECT t.id FROM agent_tasks t JOIN change_events e ON e.id = t.event_id
			WHERE t.status = 'pending' AND e.program_id = ?)`, taskID, programID)
	if err != nil {
		return fmt.Errorf("retry agent event triage: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check retried agent event triage: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("failed triage task %q not found in program %q", taskID, programID)
	}
	return nil
}

// ClaimAgentEventTasks leases deterministic event-triage work. The separate
// agent_tasks.status remains reserved for the later planner/executor queue.
func (s *Store) ClaimAgentEventTasks(ctx context.Context, now time.Time, leaseDuration time.Duration, limit int) ([]AgentEventTaskLease, error) {
	now = now.UTC()
	if leaseDuration <= 0 {
		leaseDuration = time.Minute
	}
	if leaseDuration > 10*time.Minute {
		return nil, errors.New("agent event triage lease cannot exceed 10 minutes")
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin agent event triage claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE agent_event_triage_jobs SET status = 'failed', lease_until = NULL,
		error = COALESCE(error, 'maximum triage attempts exceeded'), updated_at = ?
		WHERE attempts >= ? AND (status = 'pending' OR (status = 'running' AND COALESCE(lease_until, 0) <= ?))
		AND task_id IN (SELECT id FROM agent_tasks WHERE status = 'pending')`,
		now.Unix(), maxAgentEventTriageAttempts, now.Unix()); err != nil {
		return nil, fmt.Errorf("expire exhausted event triage jobs: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT j.task_id, j.attempts FROM agent_event_triage_jobs j
		JOIN agent_tasks t ON t.id = j.task_id JOIN change_events e ON e.id = t.event_id
		WHERE t.status = 'pending' AND j.attempts < ? AND e.material = 1
		AND (j.status = 'pending' OR (j.status = 'running' AND COALESCE(j.lease_until, 0) <= ?))
		ORDER BY j.created_at, j.task_id LIMIT ?`, maxAgentEventTriageAttempts, now.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("find pending event triage jobs: %w", err)
	}
	type candidate struct {
		id       string
		attempts int
	}
	candidates := make([]candidate, 0, limit)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.attempts); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan pending event triage job: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate pending event triage jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close pending event triage jobs: %w", err)
	}
	leases := make([]AgentEventTaskLease, 0, len(candidates))
	for _, item := range candidates {
		attempt := item.attempts + 1
		result, err := tx.ExecContext(ctx, `UPDATE agent_event_triage_jobs
			SET status = 'running', attempts = ?, lease_until = ?, error = NULL, updated_at = ?
			WHERE task_id = ? AND attempts = ?
			AND (status = 'pending' OR (status = 'running' AND COALESCE(lease_until, 0) <= ?))
			AND task_id IN (SELECT id FROM agent_tasks WHERE status = 'pending')`,
			attempt, now.Add(leaseDuration).Unix(), now.Unix(), item.id, item.attempts, now.Unix())
		if err != nil {
			return nil, fmt.Errorf("lease event triage job %s: %w", item.id, err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("check event triage lease %s: %w", item.id, err)
		}
		if changed == 1 {
			leases = append(leases, AgentEventTaskLease{ID: item.id, Attempt: attempt})
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit event triage leases: %w", err)
	}
	return leases, nil
}

func (s *Store) LoadAgentEventTriageContext(ctx context.Context, lease AgentEventTaskLease, now time.Time) (AgentEventTriageContext, error) {
	return loadAgentEventTriageContext(ctx, s.db, lease, now.UTC())
}

type triageQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type triageQueryer interface {
	triageQueryRower
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadAgentEventTriageContext(ctx context.Context, queryer triageQueryer, lease AgentEventTaskLease, now time.Time) (AgentEventTriageContext, error) {
	if lease.ID == "" || lease.Attempt < 1 {
		return AgentEventTriageContext{}, errors.New("valid agent event triage lease is required")
	}
	var contextData AgentEventTriageContext
	var taskStatus, triageStatus string
	var attempt int
	var leaseUntil, eventCreatedAt int64
	var expiry sql.NullInt64
	err := queryer.QueryRowContext(ctx, `SELECT t.status, j.status, j.attempts, COALESCE(j.lease_until, 0),
		t.event_id, COALESCE(t.session_id, ''), e.program_id, e.run_id, e.stage, e.scope_hash,
		e.category, e.stable_key, e.change_type, e.created_at, p.status, p.scope_hash,
		a.expires_at_ns,
		(SELECT COUNT(*) FROM program_source_snapshots ps WHERE ps.program_id = p.id AND ps.status = 'pending'),
		COALESCE(se.kind, ''), COALESCE(se.status, ''), COALESCE(se.program_id, ''), COALESCE(se.trigger_event_id, '')
		FROM agent_tasks t JOIN agent_event_triage_jobs j ON j.task_id = t.id
		JOIN change_events e ON e.id = t.event_id JOIN programs p ON p.id = e.program_id
		LEFT JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
		LEFT JOIN sessions se ON se.id = t.session_id WHERE t.id = ?`, lease.ID).
		Scan(&taskStatus, &triageStatus, &attempt, &leaseUntil, &contextData.EventID, &contextData.SessionID,
			&contextData.ProgramID, &contextData.RunID, &contextData.Stage, &contextData.EventScopeHash,
			&contextData.Category, &contextData.StableKey, &contextData.ChangeType, &eventCreatedAt,
			&contextData.ProgramStatus, &contextData.CurrentScopeHash, &expiry, &contextData.SourceReviewPending,
			&contextData.SessionKind, &contextData.SessionStatus, &contextData.SessionProgramID, &contextData.SessionEventID)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentEventTriageContext{}, ErrAgentEventTriageLeaseLost
	}
	if err != nil {
		return AgentEventTriageContext{}, fmt.Errorf("load event triage context: %w", err)
	}
	if taskStatus != "pending" || triageStatus != "running" || attempt != lease.Attempt || leaseUntil <= now.Unix() {
		return AgentEventTriageContext{}, ErrAgentEventTriageLeaseLost
	}
	if contextData.SessionID != "" && (contextData.SessionKind != "agent_event" ||
		contextData.SessionProgramID != contextData.ProgramID || contextData.SessionEventID != contextData.EventID) {
		return AgentEventTriageContext{}, errors.New("agent event session does not match its event and program")
	}
	contextData.Lease = lease
	contextData.ObservedAt = time.Unix(eventCreatedAt, 0).UTC()
	if expiry.Valid {
		value := time.Unix(0, expiry.Int64).UTC()
		contextData.AuthorizationExpiresAt = &value
		contextData.AuthorizationValid = value.After(now)
	}
	if !contextData.SourceReviewPending && contextData.EventScopeHash == contextData.CurrentScopeHash {
		contextData.Memory, err = loadCurrentTriageMemory(ctx, queryer, contextData.ProgramID, contextData.EventScopeHash, now)
		if err != nil {
			return AgentEventTriageContext{}, err
		}
	}
	return contextData, nil
}

func loadCurrentTriageMemory(ctx context.Context, queryer triageQueryer, programID, scopeHash string, now time.Time) ([]contract.TriageMemoryItem, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT m.id, m.kind, m.title, m.content, m.source_kind, m.confidence
		FROM program_memories m JOIN programs p ON p.id = m.program_id
		WHERE m.program_id = ? AND p.scope_hash = ? AND m.status = 'active'
		AND (m.expires_at IS NULL OR m.expires_at > ?)
		AND (m.scope_hash IS NULL OR m.scope_hash = p.scope_hash)
		AND NOT EXISTS (SELECT 1 FROM program_source_snapshots ps WHERE ps.program_id = p.id AND ps.status = 'pending')
		AND (m.source_kind != 'source_snapshot' OR (m.source_hash IS NOT NULL AND m.source_hash = (
			SELECT ps.source_hash FROM program_source_snapshots ps WHERE ps.program_id = p.id
			AND ps.status IN ('approved', 'unchanged') ORDER BY ps.fetched_at DESC, ps.rowid DESC LIMIT 1)))
		ORDER BY m.observed_at DESC, m.created_at DESC, m.id LIMIT ?`,
		programID, scopeHash, now.UTC().Unix(), maxTriageMemoryCandidates)
	if err != nil {
		return nil, fmt.Errorf("query current program memory for triage: %w", err)
	}
	defer rows.Close()

	items := make([]contract.TriageMemoryItem, 0, maxTriageMemoryItems)
	totalBytes := 0
	for rows.Next() {
		var item contract.TriageMemoryItem
		if err := rows.Scan(&item.ID, &item.Kind, &item.Title, &item.Content, &item.SourceKind, &item.Confidence); err != nil {
			return nil, fmt.Errorf("scan current program memory for triage: %w", err)
		}
		item.Title = boundedMemoryBriefText(item.Title, maxTriageMemoryTitleBytes)
		item.Content = boundedMemoryBriefText(item.Content, maxTriageMemoryBodyBytes)
		itemBytes := len(item.ID) + len(item.Kind) + len(item.Title) + len(item.Content) + len(item.SourceKind)
		if item.Title == "" || item.Content == "" {
			continue
		}
		if len(items) >= maxTriageMemoryItems || totalBytes+itemBytes > maxTriageMemoryTotalBytes {
			break
		}
		items = append(items, item)
		totalBytes += itemBytes
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate current program memory for triage: %w", err)
	}
	return items, nil
}

func boundedMemoryBriefText(value string, maximum int) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "�")
	if len(value) <= maximum {
		return value
	}
	const suffix = " [truncated]"
	maximum -= len(suffix)
	for maximum > 0 && !utf8.RuneStart(value[maximum]) {
		maximum--
	}
	if maximum <= 0 {
		return ""
	}
	return value[:maximum] + suffix
}

func (s *Store) CompleteAgentEventTriage(ctx context.Context, lease AgentEventTaskLease, output AgentEventTriageOutput, now time.Time) (AgentEventTriageResult, error) {
	now = now.UTC()
	output.ProgramID = strings.TrimSpace(output.ProgramID)
	output.EventID = strings.TrimSpace(output.EventID)
	output.EventScopeHash = strings.TrimSpace(output.EventScopeHash)
	output.Title = strings.TrimSpace(output.Title)
	if output.ProgramID == "" || output.EventID == "" || output.Title == "" || len(output.Title) > maxProgramMemoryTitleBytes ||
		!utf8.ValidString(output.Title) || len(output.BriefJSON) == 0 || len(output.BriefJSON) > maxProgramMemoryContentBytes ||
		!json.Valid(output.BriefJSON) || output.CapturedAt.IsZero() || output.CapturedAt.After(now.Add(5*time.Minute)) {
		return AgentEventTriageResult{}, errors.New("agent event triage output is incomplete or invalid")
	}
	var briefIdentity struct {
		ProgramID      string    `json:"program_id"`
		EventID        string    `json:"event_id"`
		EventScopeHash string    `json:"event_scope_hash"`
		CapturedAt     time.Time `json:"captured_at"`
		CurrentProgram struct {
			Status                 string     `json:"status"`
			ScopeHash              string     `json:"current_scope_hash"`
			ScopeMatchesEvent      bool       `json:"scope_matches_event"`
			SourceReviewPending    bool       `json:"source_review_pending"`
			AuthorizationValid     bool       `json:"authorization_valid_at_triage"`
			AuthorizationExpiresAt *time.Time `json:"authorization_expires_at,omitempty"`
		} `json:"current_program"`
		Memory []contract.TriageMemoryItem `json:"memory,omitempty"`
	}
	if err := json.Unmarshal(output.BriefJSON, &briefIdentity); err != nil ||
		briefIdentity.ProgramID != output.ProgramID || briefIdentity.EventID != output.EventID ||
		briefIdentity.EventScopeHash != output.EventScopeHash || !briefIdentity.CapturedAt.Equal(output.CapturedAt) ||
		briefIdentity.CurrentProgram.Status != output.ProgramStatus ||
		briefIdentity.CurrentProgram.ScopeHash != output.CurrentScopeHash ||
		briefIdentity.CurrentProgram.ScopeMatchesEvent != output.ScopeMatchesEvent ||
		briefIdentity.CurrentProgram.SourceReviewPending != output.SourceReviewPending ||
		briefIdentity.CurrentProgram.AuthorizationValid != output.AuthorizationValid ||
		!sameOptionalTime(briefIdentity.CurrentProgram.AuthorizationExpiresAt, output.AuthorizationExpiresAt) {
		return AgentEventTriageResult{}, errors.New("event brief identity does not match its triage output")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentEventTriageResult{}, fmt.Errorf("begin event triage completion: %w", err)
	}
	defer tx.Rollback()
	current, err := loadAgentEventTriageContext(ctx, tx, lease, now)
	if err != nil {
		return AgentEventTriageResult{}, err
	}
	if output.ProgramID != current.ProgramID || output.EventID != current.EventID || output.EventScopeHash != current.EventScopeHash {
		return AgentEventTriageResult{}, errors.New("agent event triage output does not match its leased source event")
	}
	if output.ProgramStatus != current.ProgramStatus || output.CurrentScopeHash != current.CurrentScopeHash ||
		output.ScopeMatchesEvent != (output.EventScopeHash == current.CurrentScopeHash) ||
		output.SourceReviewPending != current.SourceReviewPending || output.AuthorizationValid != current.AuthorizationValid ||
		!sameOptionalTime(output.AuthorizationExpiresAt, current.AuthorizationExpiresAt) ||
		!sameTriageMemoryItems(briefIdentity.Memory, current.Memory) {
		return AgentEventTriageResult{}, ErrAgentEventTriageContextChanged
	}

	var memoryID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM program_memories
		WHERE program_id = ? AND kind = 'handoff' AND source_kind = 'event' AND source_id = ? AND status = 'active'
		ORDER BY created_at DESC LIMIT 1`, current.ProgramID, current.EventID).Scan(&memoryID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AgentEventTriageResult{}, fmt.Errorf("check existing event handoff memory: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		memoryID = uuid.NewString()
		if _, err := tx.ExecContext(ctx, `INSERT INTO program_memories(
			id, program_id, kind, title, content, source_kind, source_id, scope_hash, confidence,
			status, observed_at, created_at, updated_at)
			VALUES (?, ?, 'handoff', ?, ?, 'event', ?, ?, 1, 'active', ?, ?, ?)`,
			memoryID, current.ProgramID, output.Title, string(output.BriefJSON), current.EventID,
			current.EventScopeHash, current.ObservedAt.Unix(), now.Unix(), now.Unix()); err != nil {
			return AgentEventTriageResult{}, fmt.Errorf("store event handoff memory: %w", err)
		}
	}

	messageStored := false
	if current.SessionID != "" && current.SessionStatus == "open" {
		var sequence int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence), 0) + 1 FROM session_messages WHERE session_id = ?`, current.SessionID).Scan(&sequence); err != nil {
			return AgentEventTriageResult{}, fmt.Errorf("allocate event session message: %w", err)
		}
		metadata, err := json.Marshal(map[string]any{
			"source": "heimdall-agent-triage", "event_id": current.EventID, "program_id": current.ProgramID,
			"trust": "untrusted-recon-data", "tools_executed": false,
		})
		if err != nil {
			return AgentEventTriageResult{}, fmt.Errorf("encode event session metadata: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO session_messages(
			id, session_id, sequence, role, content, metadata_json, provider, model, created_at)
			VALUES (?, ?, ?, 'tool', ?, ?, 'heimdall', 'event-triage-v1', ?)`,
			uuid.NewString(), current.SessionID, sequence, string(output.BriefJSON), string(metadata), now.Unix()); err != nil {
			return AgentEventTriageResult{}, fmt.Errorf("save event triage message: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET updated_at = ? WHERE id = ? AND status = 'open'`, now.Unix(), current.SessionID); err != nil {
			return AgentEventTriageResult{}, fmt.Errorf("update event session: %w", err)
		}
		messageStored = true
	}

	result := AgentEventTriageResult{
		TaskID: lease.ID, ProgramID: current.ProgramID, EventID: current.EventID, MemoryID: memoryID,
		SessionMessageStored: messageStored, ScopeCurrent: current.EventScopeHash == current.CurrentScopeHash,
		ProgramStatus: current.ProgramStatus, SourceReviewPending: current.SourceReviewPending,
		AuthorizationValid: current.AuthorizationValid, CompletedAt: now,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return AgentEventTriageResult{}, fmt.Errorf("encode event triage result: %w", err)
	}
	update, err := tx.ExecContext(ctx, `UPDATE agent_event_triage_jobs
		SET status = 'complete', lease_until = NULL, triaged_at = ?, error = NULL, result_json = ?, updated_at = ?
		WHERE task_id = ? AND status = 'running' AND attempts = ? AND lease_until > ?
		AND task_id IN (SELECT id FROM agent_tasks WHERE status = 'pending')`,
		now.Unix(), string(resultJSON), now.Unix(), lease.ID, lease.Attempt, now.Unix())
	if err != nil {
		return AgentEventTriageResult{}, fmt.Errorf("complete agent event triage job: %w", err)
	}
	if count, err := update.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return AgentEventTriageResult{}, fmt.Errorf("verify agent event triage completion: %w", err)
		}
		return AgentEventTriageResult{}, ErrAgentEventTriageLeaseLost
	}
	if err := tx.Commit(); err != nil {
		return AgentEventTriageResult{}, fmt.Errorf("commit agent event triage: %w", err)
	}
	return result, nil
}

func sameTriageMemoryItems(left, right []contract.TriageMemoryItem) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func (s *Store) FailAgentEventTriage(ctx context.Context, lease AgentEventTaskLease, cause error, now time.Time) error {
	if lease.ID == "" || lease.Attempt < 1 {
		return errors.New("valid agent event triage lease is required")
	}
	errorText := "unknown deterministic triage error"
	if cause != nil {
		errorText = strings.ToValidUTF8(cause.Error(), "�")
		if len(errorText) > 2048 {
			errorText = string([]rune(errorText)[:2048])
		}
	}
	result, err := s.db.ExecContext(ctx, `UPDATE agent_event_triage_jobs SET
		status = CASE WHEN attempts >= ? THEN 'failed' ELSE 'pending' END,
		lease_until = NULL, error = ?, updated_at = ?
		WHERE task_id = ? AND status = 'running' AND attempts = ? AND lease_until > ?
		AND task_id IN (SELECT id FROM agent_tasks WHERE status = 'pending')`,
		maxAgentEventTriageAttempts, errorText, now.UTC().Unix(), lease.ID, lease.Attempt, now.UTC().Unix())
	if err != nil {
		return fmt.Errorf("record agent event triage failure: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check agent event triage failure: %w", err)
	}
	if count != 1 {
		return ErrAgentEventTriageLeaseLost
	}
	return nil
}
