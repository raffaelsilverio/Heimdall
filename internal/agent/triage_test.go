package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
)

func openTriageStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func createMaterialReconEvent(t *testing.T, database *store.Store, start time.Time) (assessment.Program, store.ChangeEvent) {
	t.Helper()
	ctx := context.Background()
	program, err := database.CreateProgram(ctx, store.CreateProgramParams{
		Name:                   "Triage integration",
		AuthorizationReference: "internal:triage-test",
		ExpiresAt:              start.Add(24 * time.Hour),
		Timezone:               "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Type: assessment.ScopeWildcardDomain, Value: "example.test",
		}}},
	}, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageOSINT, "* * * * *", "UTC", true, start.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, start); err != nil {
		t.Fatal(err)
	}

	run := func(at time.Time, hosts ...string) []store.ChangeEvent {
		t.Helper()
		jobs, err := database.ClaimDueSchedules(ctx, at, time.Hour)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("ClaimDueSchedules returned %d jobs, err=%v", len(jobs), err)
		}
		observations := make([]recon.Observation, 0, len(hosts))
		for _, host := range hosts {
			observations = append(observations, recon.Observation{
				Category: recon.CategoryHostname, StableKey: host, Value: host,
				Source: "subfinder", ToolVersion: "vtest", ObservedAt: at,
			})
		}
		events, err := database.CompleteRun(ctx, jobs[0].RunID,
			recon.Collection{Observations: observations}, true, nil, at)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	if events := run(start, "base.example.test"); len(events) != 0 {
		t.Fatalf("initial baseline unexpectedly emitted events: %+v", events)
	}
	events := run(start.Add(time.Minute), "base.example.test", "new.example.test")
	if len(events) != 1 || events[0].ChangeType != "added" {
		t.Fatalf("expected one material hostname event, got %+v", events)
	}
	return program, events[0]
}

func TestTriageWorkerCreatesScopedMemoryAndSessionHandoff(t *testing.T) {
	database := openTriageStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	program, event := createMaterialReconEvent(t, database, start)
	if err := database.PauseProgram(ctx, program.ID, start.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	worker := TriageWorker{Store: database, BatchSize: 5, LeaseDuration: time.Minute}

	processed, err := worker.RunCycle(ctx, start.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if processed != 1 {
		t.Fatalf("triaged %d tasks, want 1", processed)
	}
	tasks, err := database.ListAgentTaskStatuses(ctx, program.ID, 10)
	if err != nil || len(tasks) != 1 || tasks[0].Status != "pending" || tasks[0].TriageStatus != "complete" || tasks[0].TriagedAt == nil {
		t.Fatalf("triage status is not inspectable or changed the later agent queue: tasks=%+v err=%v", tasks, err)
	}
	if err := database.RetryAgentEventTriage(ctx, program.ID, tasks[0].ID); err == nil {
		t.Fatal("completed triage task was incorrectly requeued")
	}

	sessions, err := database.ListSessions(ctx, program.ID, 10)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("event session not found: sessions=%+v err=%v", sessions, err)
	}
	messages, err := database.ListSessionMessages(ctx, sessions[0].ID, 10)
	if err != nil || len(messages) != 1 || messages[0].Role != "tool" {
		t.Fatalf("deterministic handoff message missing: messages=%+v err=%v", messages, err)
	}
	var brief map[string]any
	if err := json.Unmarshal([]byte(messages[0].Content), &brief); err != nil {
		t.Fatalf("triage message is not structured JSON: %v", err)
	}
	if brief["event_id"] != event.ID || !strings.Contains(messages[0].Content, "no LLM call or tool execution occurred") {
		t.Fatalf("triage handoff omitted event provenance or safety note: %s", messages[0].Content)
	}
	if !strings.Contains(messages[0].Content, `"status":"paused"`) {
		t.Fatalf("triage brief did not reflect the current paused program state: %s", messages[0].Content)
	}
	if strings.Contains(messages[0].Content, "old_value") || strings.Contains(messages[0].Content, "new_value") {
		t.Fatalf("triage message copied raw event values instead of linking to the source event: %s", messages[0].Content)
	}

	memories, err := database.ListProgramMemories(ctx, program.ID, 10, start.Add(3*time.Minute))
	if err != nil || len(memories) != 1 {
		t.Fatalf("program handoff memory missing: memories=%+v err=%v", memories, err)
	}
	if memories[0].Kind != "handoff" || memories[0].SourceKind != "event" || memories[0].SourceID != event.ID || memories[0].ScopeHash != program.ScopeHash {
		t.Fatalf("handoff memory lost per-program provenance: %+v", memories[0])
	}
	search, err := database.SearchProgramMemories(ctx, program.ID, "new.example.test", 10, start.Add(3*time.Minute))
	if err != nil || len(search) != 1 || search[0].ID != memories[0].ID {
		t.Fatalf("event handoff was not searchable within its program: results=%+v err=%v", search, err)
	}
	processed, err = worker.RunCycle(ctx, start.Add(4*time.Minute))
	if err != nil || processed != 0 {
		t.Fatalf("completed triage was repeated: processed=%d err=%v", processed, err)
	}
}

func TestExpiredTriageLeaseCannotCommitAfterReclaim(t *testing.T) {
	database := openTriageStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	program, event := createMaterialReconEvent(t, database, start)
	first, err := database.ClaimAgentEventTasks(ctx, start.Add(2*time.Minute), 30*time.Second, 1)
	if err != nil || len(first) != 1 || first[0].Attempt != 1 {
		t.Fatalf("first triage claim = %+v err=%v", first, err)
	}
	firstContext, err := database.LoadAgentEventTriageContext(ctx, first[0], start.Add(2*time.Minute+5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	firstOutput, err := BuildAgentEventTriageOutput(firstContext, start.Add(2*time.Minute+5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := database.ClaimAgentEventTasks(ctx, start.Add(2*time.Minute+10*time.Second), 30*time.Second, 1)
	if err != nil || len(waiting) != 0 {
		t.Fatalf("unexpired triage lease was reclaimed: leases=%+v err=%v", waiting, err)
	}
	second, err := database.ClaimAgentEventTasks(ctx, start.Add(2*time.Minute+31*time.Second), 30*time.Second, 1)
	if err != nil || len(second) != 1 || second[0].Attempt != 2 {
		t.Fatalf("expired triage lease was not reclaimed: leases=%+v err=%v", second, err)
	}
	if _, err := database.CompleteAgentEventTriage(ctx, first[0], firstOutput, start.Add(2*time.Minute+32*time.Second)); err != store.ErrAgentEventTriageLeaseLost {
		t.Fatalf("stale worker completion err=%v, want ErrAgentEventTriageLeaseLost", err)
	}
	secondContext, err := database.LoadAgentEventTriageContext(ctx, second[0], start.Add(2*time.Minute+32*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	secondOutput, err := BuildAgentEventTriageOutput(secondContext, start.Add(2*time.Minute+32*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CompleteAgentEventTriage(ctx, second[0], secondOutput, start.Add(2*time.Minute+32*time.Second)); err != nil {
		t.Fatalf("current lease failed to complete: %v", err)
	}
	handoffs, err := database.ListProgramMemories(ctx, program.ID, 10, start.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(handoffs) != 1 || handoffs[0].SourceID != event.ID {
		t.Fatalf("triage created duplicate or missing handoff memories: %+v", handoffs)
	}
}

func TestEventTriageBriefSanitizesSensitiveURLComponents(t *testing.T) {
	const scopeHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	output, err := BuildAgentEventTriageOutput(store.AgentEventTriageContext{
		ProgramID: "program-a", EventID: "event-a", RunID: "run-a", Stage: "web",
		EventScopeHash: scopeHash, Category: "http_endpoint",
		StableKey:  "https://user:password@example.test/account?token=private#fragment",
		ChangeType: "added", ObservedAt: now, ProgramStatus: "active", CurrentScopeHash: scopeHash,
		AuthorizationValid: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	content := string(output.BriefJSON)
	if strings.Contains(content, "password") || strings.Contains(content, "private") || strings.Contains(content, "fragment") {
		t.Fatalf("triage brief retained URL credentials, query, or fragment: %s", content)
	}
	if !strings.Contains(content, "https://example.test/account") || !output.ScopeMatchesEvent {
		t.Fatalf("sanitized target or policy context missing: %+v %s", output, content)
	}
}
