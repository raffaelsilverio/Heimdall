package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
)

type TriageRepository = contract.TriageRepository

// TriageWorker prepares deterministic, program-scoped handoffs for material
// recon events. It does not call a model or execute tools.
type TriageWorker struct {
	Store         TriageRepository
	BatchSize     int
	LeaseDuration time.Duration
}

func (w TriageWorker) RunCycle(ctx context.Context, now time.Time) (int, error) {
	if w.Store == nil {
		return 0, errors.New("agent triage worker requires a repository")
	}
	batchSize := w.BatchSize
	if batchSize <= 0 || batchSize > 50 {
		batchSize = 10
	}
	leaseDuration := w.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 2 * time.Minute
	}
	leases, err := w.Store.ClaimAgentEventTasks(ctx, now.UTC(), leaseDuration, batchSize)
	if err != nil {
		return 0, err
	}
	completed := 0
	var failures []error
	for _, lease := range leases {
		if ctx.Err() != nil {
			return completed, errors.Join(append(failures, ctx.Err())...)
		}
		if err := w.triageLease(ctx, lease, now.UTC()); err != nil {
			if errors.Is(err, contract.ErrTriageLeaseLost) {
				continue
			}
			failErr := w.Store.FailAgentEventTriage(ctx, lease, err, now.UTC())
			if failErr != nil && !errors.Is(failErr, contract.ErrTriageLeaseLost) {
				failures = append(failures, fmt.Errorf("record triage failure for task %s: %w", lease.ID, failErr))
			}
			failures = append(failures, fmt.Errorf("triage task %s: %w", lease.ID, err))
			continue
		}
		completed++
	}
	return completed, errors.Join(failures...)
}

func (w TriageWorker) triageLease(ctx context.Context, lease contract.TaskLease, now time.Time) error {
	for attempt := 0; attempt < 2; attempt++ {
		contextData, err := w.Store.LoadAgentEventTriageContext(ctx, lease, now)
		if err != nil {
			return err
		}
		output, err := BuildAgentEventTriageOutput(contextData, now)
		if err != nil {
			return err
		}
		_, err = w.Store.CompleteAgentEventTriage(ctx, lease, output, now)
		if errors.Is(err, contract.ErrTriageContextChanged) {
			continue
		}
		return err
	}
	return contract.ErrTriageContextChanged
}

// BuildAgentEventTriageOutput contains application-level summary rules. The
// event fields are untrusted observation data; the output is descriptive only.
func BuildAgentEventTriageOutput(source contract.TriageContext, capturedAt time.Time) (contract.TriageOutput, error) {
	if source.ProgramID == "" || source.EventID == "" || source.EventScopeHash == "" {
		return contract.TriageOutput{}, errors.New("event triage context is missing its program, event, or scope identity")
	}
	stableKey := sanitizeEventTarget(source.StableKey)
	brief := eventTriageBrief{
		SchemaVersion:  1,
		ProgramID:      source.ProgramID,
		EventID:        source.EventID,
		RunID:          source.RunID,
		Stage:          source.Stage,
		EventScopeHash: source.EventScopeHash,
		CapturedAt:     capturedAt.UTC(),
		Event: eventTriageDetails{
			Category: boundedTriageText(source.Category, 256), StableKey: stableKey,
			ChangeType: source.ChangeType, ObservedAt: source.ObservedAt,
		},
		CurrentProgram: eventTriageProgramState{
			Status: source.ProgramStatus, ScopeHash: source.CurrentScopeHash,
			ScopeMatchesEvent:   source.EventScopeHash == source.CurrentScopeHash,
			SourceReviewPending: source.SourceReviewPending, AuthorizationValid: source.AuthorizationValid,
			AuthorizationExpiresAt: source.AuthorizationExpiresAt,
		},
		Memory: append([]contract.TriageMemoryItem(nil), source.Memory...),
		Notice: "Deterministic event context only; no LLM call or tool execution occurred. This record does not grant authorization.",
	}
	briefJSON, err := json.Marshal(brief)
	if err != nil {
		return contract.TriageOutput{}, fmt.Errorf("encode deterministic event brief: %w", err)
	}
	if len(briefJSON) > 64<<10 {
		return contract.TriageOutput{}, errors.New("deterministic event brief exceeds 64 KiB")
	}
	title := boundedTriageText(fmt.Sprintf("Recon handoff: %s %s %s", source.ChangeType, source.Category, stableKey), 200)
	if strings.TrimSpace(title) == "" {
		title = "Recon event handoff"
	}
	return contract.TriageOutput{
		ProgramID: source.ProgramID, EventID: source.EventID, EventScopeHash: source.EventScopeHash,
		Title: title, BriefJSON: briefJSON, CapturedAt: capturedAt.UTC(),
		ProgramStatus: source.ProgramStatus, CurrentScopeHash: source.CurrentScopeHash,
		ScopeMatchesEvent:   source.EventScopeHash == source.CurrentScopeHash,
		SourceReviewPending: source.SourceReviewPending, AuthorizationValid: source.AuthorizationValid,
		AuthorizationExpiresAt: source.AuthorizationExpiresAt,
	}, nil
}

type eventTriageBrief struct {
	SchemaVersion  int                         `json:"schema_version"`
	ProgramID      string                      `json:"program_id"`
	EventID        string                      `json:"event_id"`
	RunID          string                      `json:"run_id"`
	Stage          string                      `json:"stage"`
	EventScopeHash string                      `json:"event_scope_hash"`
	CapturedAt     time.Time                   `json:"captured_at"`
	Event          eventTriageDetails          `json:"event"`
	CurrentProgram eventTriageProgramState     `json:"current_program"`
	Memory         []contract.TriageMemoryItem `json:"memory,omitempty"`
	Notice         string                      `json:"notice"`
}

type eventTriageDetails struct {
	Category   string    `json:"category"`
	StableKey  string    `json:"stable_key"`
	ChangeType string    `json:"change_type"`
	ObservedAt time.Time `json:"observed_at"`
}

type eventTriageProgramState struct {
	Status                 string     `json:"status"`
	ScopeHash              string     `json:"current_scope_hash"`
	ScopeMatchesEvent      bool       `json:"scope_matches_event"`
	SourceReviewPending    bool       `json:"source_review_pending"`
	AuthorizationValid     bool       `json:"authorization_valid_at_triage"`
	AuthorizationExpiresAt *time.Time `json:"authorization_expires_at,omitempty"`
}

func sanitizeEventTarget(value string) string {
	value = boundedTriageText(value, 4096)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" ||
		(!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) {
		return value
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return boundedTriageText(parsed.String(), 4096)
}

func boundedTriageText(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "�")
	var clean strings.Builder
	for _, character := range value {
		if character == '\n' || character == '\t' || !unicode.IsControl(character) {
			clean.WriteRune(character)
		}
	}
	value = clean.String()
	if len(value) <= maxBytes {
		return value
	}
	const suffix = " [truncated]"
	maxBytes -= len(suffix)
	for maxBytes > 0 && !utf8.RuneStart(value[maxBytes]) {
		maxBytes--
	}
	if maxBytes <= 0 {
		return ""
	}
	return value[:maxBytes] + suffix
}
