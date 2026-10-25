package contract

import (
	"context"
	"errors"
	"time"
)

var (
	ErrTriageLeaseLost      = errors.New("agent event triage lease was lost")
	ErrTriageContextChanged = errors.New("agent event triage context changed while preparing the handoff")
)

type TaskLease struct {
	ID      string
	Attempt int
}

type TriageContext struct {
	Lease                  TaskLease
	ProgramID              string
	EventID                string
	SessionID              string
	SessionKind            string
	SessionStatus          string
	SessionProgramID       string
	SessionEventID         string
	RunID                  string
	Stage                  string
	EventScopeHash         string
	Category               string
	StableKey              string
	ChangeType             string
	ObservedAt             time.Time
	ProgramStatus          string
	CurrentScopeHash       string
	SourceReviewPending    bool
	AuthorizationValid     bool
	AuthorizationExpiresAt *time.Time
}

type TriageOutput struct {
	ProgramID              string
	EventID                string
	EventScopeHash         string
	Title                  string
	BriefJSON              []byte
	CapturedAt             time.Time
	ProgramStatus          string
	CurrentScopeHash       string
	ScopeMatchesEvent      bool
	SourceReviewPending    bool
	AuthorizationValid     bool
	AuthorizationExpiresAt *time.Time
}

type TriageResult struct {
	TaskID               string
	ProgramID            string
	EventID              string
	MemoryID             string
	SessionMessageStored bool
	ScopeCurrent         bool
	ProgramStatus        string
	SourceReviewPending  bool
	AuthorizationValid   bool
	CompletedAt          time.Time
}

type TriageRepository interface {
	ClaimAgentEventTasks(ctx context.Context, now time.Time, leaseDuration time.Duration, limit int) ([]TaskLease, error)
	LoadAgentEventTriageContext(ctx context.Context, lease TaskLease, now time.Time) (TriageContext, error)
	CompleteAgentEventTriage(ctx context.Context, lease TaskLease, output TriageOutput, now time.Time) (TriageResult, error)
	FailAgentEventTriage(ctx context.Context, lease TaskLease, cause error, now time.Time) error
}
