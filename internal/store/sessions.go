package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxSessionMessageBytes = 1 << 20

type Session struct {
	ID             string
	ProgramID      string
	Kind           string
	Title          string
	Status         string
	ScopeHash      string
	TriggerEventID string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ClosedAt       *time.Time
}

type SessionMessage struct {
	ID        string
	SessionID string
	Sequence  int64
	Role      string
	Content   string
	Metadata  json.RawMessage
	Provider  string
	Model     string
	CreatedAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, programID, title string, now time.Time) (Session, error) {
	program, err := s.GetProgram(ctx, programID)
	if err != nil {
		return Session{}, err
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "Interactive session"
	}
	if len(title) > 200 {
		return Session{}, errors.New("session title exceeds 200 bytes")
	}
	now = now.UTC()
	session := Session{
		ID:        uuid.NewString(),
		ProgramID: programID,
		Kind:      "interactive",
		Title:     title,
		Status:    "open",
		ScopeHash: program.ScopeHash,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id, program_id, kind, title, status, scope_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, session.ID, session.ProgramID, session.Kind, session.Title, session.Status, session.ScopeHash, now.Unix(), now.Unix()); err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return session, nil
}

func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	var session Session
	var createdAt, updatedAt int64
	var closedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, program_id, kind, title, status, scope_hash, COALESCE(trigger_event_id, ''), created_at, updated_at, closed_at
		FROM sessions WHERE id = ?`, id).Scan(&session.ID, &session.ProgramID, &session.Kind, &session.Title,
		&session.Status, &session.ScopeHash, &session.TriggerEventID, &createdAt, &updatedAt, &closedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, fmt.Errorf("session %q not found", id)
	}
	if err != nil {
		return Session{}, fmt.Errorf("get session: %w", err)
	}
	session.CreatedAt = time.Unix(createdAt, 0).UTC()
	session.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if closedAt.Valid {
		closed := time.Unix(closedAt.Int64, 0).UTC()
		session.ClosedAt = &closed
	}
	return session, nil
}

func (s *Store) ListSessions(ctx context.Context, programID string, limit int) ([]Session, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, program_id, kind, title, status, scope_hash, COALESCE(trigger_event_id, ''), created_at, updated_at, closed_at FROM sessions`
	args := make([]any, 0, 2)
	if programID != "" {
		query += ` WHERE program_id = ?`
		args = append(args, programID)
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()
	sessions := make([]Session, 0)
	for rows.Next() {
		var session Session
		var createdAt, updatedAt int64
		var closedAt sql.NullInt64
		if err := rows.Scan(&session.ID, &session.ProgramID, &session.Kind, &session.Title, &session.Status,
			&session.ScopeHash, &session.TriggerEventID, &createdAt, &updatedAt, &closedAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		session.CreatedAt = time.Unix(createdAt, 0).UTC()
		session.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		if closedAt.Valid {
			closed := time.Unix(closedAt.Int64, 0).UTC()
			session.ClosedAt = &closed
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

func (s *Store) ListSessionMessages(ctx context.Context, sessionID string, limit int) ([]SessionMessage, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, session_id, sequence, role, content, metadata_json,
		COALESCE(provider, ''), COALESCE(model, ''), created_at FROM (
			SELECT id, session_id, sequence, role, content, metadata_json, provider, model, created_at
			FROM session_messages WHERE session_id = ? ORDER BY sequence DESC LIMIT ?
		) ORDER BY sequence`, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("list session messages: %w", err)
	}
	defer rows.Close()
	messages := make([]SessionMessage, 0)
	for rows.Next() {
		var message SessionMessage
		var metadata string
		var createdAt int64
		if err := rows.Scan(&message.ID, &message.SessionID, &message.Sequence, &message.Role, &message.Content,
			&metadata, &message.Provider, &message.Model, &createdAt); err != nil {
			return nil, fmt.Errorf("scan session message: %w", err)
		}
		message.Metadata = json.RawMessage(metadata)
		message.CreatedAt = time.Unix(createdAt, 0).UTC()
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate session messages: %w", err)
	}
	return messages, nil
}

func (s *Store) AppendSessionMessage(ctx context.Context, sessionID, role, content, provider, model string, metadata json.RawMessage, now time.Time) (SessionMessage, error) {
	role = strings.TrimSpace(strings.ToLower(role))
	switch role {
	case "system", "user", "assistant", "tool":
	default:
		return SessionMessage{}, fmt.Errorf("unsupported session message role %q", role)
	}
	if strings.TrimSpace(content) == "" {
		return SessionMessage{}, errors.New("session message content is required")
	}
	if len(content) > maxSessionMessageBytes {
		return SessionMessage{}, fmt.Errorf("session message exceeds %d bytes", maxSessionMessageBytes)
	}
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	if !json.Valid(metadata) {
		return SessionMessage{}, errors.New("session message metadata must be valid JSON")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SessionMessage{}, fmt.Errorf("begin message append: %w", err)
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM sessions WHERE id = ?`, sessionID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SessionMessage{}, fmt.Errorf("session %q not found", sessionID)
		}
		return SessionMessage{}, fmt.Errorf("load session: %w", err)
	}
	if status != "open" {
		return SessionMessage{}, fmt.Errorf("session is %s", status)
	}
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence), 0) + 1 FROM session_messages WHERE session_id = ?`, sessionID).Scan(&sequence); err != nil {
		return SessionMessage{}, fmt.Errorf("allocate message sequence: %w", err)
	}
	message := SessionMessage{ID: uuid.NewString(), SessionID: sessionID, Sequence: sequence, Role: role, Content: content,
		Metadata: append(json.RawMessage(nil), metadata...), Provider: provider, Model: model, CreatedAt: now}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_messages(id, session_id, sequence, role, content, metadata_json, provider, model, created_at)
		VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?)`, message.ID, sessionID, sequence, role, content, string(metadata), provider, model, now.Unix()); err != nil {
		return SessionMessage{}, fmt.Errorf("append session message: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET updated_at = ? WHERE id = ?`, now.Unix(), sessionID); err != nil {
		return SessionMessage{}, fmt.Errorf("update session timestamp: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SessionMessage{}, fmt.Errorf("commit session message: %w", err)
	}
	return message, nil
}

func (s *Store) CloseSession(ctx context.Context, sessionID string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE sessions SET status = 'closed', updated_at = ?, closed_at = ? WHERE id = ? AND status = 'open'`, now.UTC().Unix(), now.UTC().Unix(), sessionID)
	if err != nil {
		return fmt.Errorf("close session: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check session close: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("open session %q not found", sessionID)
	}
	return nil
}

func createAgentEventSession(ctx context.Context, tx *sql.Tx, event ChangeEvent, scopeHash string, now time.Time) error {
	if !event.Material {
		return nil
	}
	sessionID := uuid.NewString()
	title := fmt.Sprintf("Recon change: %s %s %s", event.ChangeType, event.Category, event.StableKey)
	if len(title) > 200 {
		title = title[:200]
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id, program_id, kind, title, status, scope_hash, trigger_event_id, created_at, updated_at)
		VALUES (?, ?, 'agent_event', ?, 'open', ?, ?, ?, ?)`, sessionID, event.ProgramID, title, scopeHash, event.ID, now.UTC().Unix(), now.UTC().Unix()); err != nil {
		return fmt.Errorf("create agent event session: %w", err)
	}
	taskID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_tasks(id, event_id, status, created_at, session_id)
		VALUES (?, ?, 'pending', ?, ?)`, taskID, event.ID, now.UTC().Unix(), sessionID); err != nil {
		return fmt.Errorf("enqueue agent task: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_event_triage_jobs(task_id, status, created_at, updated_at)
		VALUES (?, 'pending', ?, ?)`, taskID, now.UTC().Unix(), now.UTC().Unix()); err != nil {
		return fmt.Errorf("enqueue deterministic agent event triage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_cycle_jobs(task_id, program_id, event_id, event_scope_hash,
		automation_revision, status, created_at, updated_at)
		SELECT ?, ?, ?, ?, revision, 'pending', ?, ?
		FROM program_agent_automation WHERE program_id = ? AND enabled = 1`,
		taskID, event.ProgramID, event.ID, scopeHash, now.UTC().Unix(), now.UTC().Unix(), event.ProgramID); err != nil {
		return fmt.Errorf("enqueue consented agent cycle: %w", err)
	}
	return nil
}
