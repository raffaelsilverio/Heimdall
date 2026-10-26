package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
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
	if _, err := database.AddProgramMemory(ctx, store.AddProgramMemoryParams{
		ProgramID: program.ID, Kind: "hypothesis", Title: "Current same-program note",
		Content: "Prior same-program hypothesis for triage context.", SourceKind: "operator", ScopeHash: program.ScopeHash, Confidence: 0.6,
	}, start.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddProgramMemory(ctx, store.AddProgramMemoryParams{
		ProgramID: program.ID, Kind: "fact", Title: "Stale scope note",
		Content: "This note belongs to another scope revision.", SourceKind: "operator",
		ScopeHash: strings.Repeat("a", 64), Confidence: 1,
	}, start.Add(91*time.Second)); err != nil {
		t.Fatal(err)
	}
	otherProgram, err := database.CreateProgram(ctx, store.CreateProgramParams{
		Name: "Other triage program", AuthorizationReference: "internal:triage-other",
		ExpiresAt: start.Add(24 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "other.test"}}},
	}, start)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddProgramMemory(ctx, store.AddProgramMemoryParams{
		ProgramID: otherProgram.ID, Kind: "fact", Title: "Foreign secret note",
		Content: "Cross-program data must never enter this handoff.", SourceKind: "operator", Confidence: 1,
	}, start.Add(92*time.Second)); err != nil {
		t.Fatal(err)
	}
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
	var triageBrief struct {
		Memory []contract.TriageMemoryItem `json:"memory"`
	}
	if err := json.Unmarshal([]byte(messages[0].Content), &triageBrief); err != nil {
		t.Fatal(err)
	}
	if len(triageBrief.Memory) < 2 || !strings.Contains(messages[0].Content, "Current same-program note") ||
		strings.Contains(messages[0].Content, "Foreign secret note") || strings.Contains(messages[0].Content, "Stale scope note") {
		t.Fatalf("triage memory briefing leaked cross-program or stale notes, or omitted current notes: %+v", triageBrief.Memory)
	}
	if !strings.Contains(messages[0].Content, `"status":"paused"`) {
		t.Fatalf("triage brief did not reflect the current paused program state: %s", messages[0].Content)
	}
	if strings.Contains(messages[0].Content, "old_value") || strings.Contains(messages[0].Content, "new_value") {
		t.Fatalf("triage message copied raw event values instead of linking to the source event: %s", messages[0].Content)
	}

	memories, err := database.ListProgramMemories(ctx, program.ID, 10, start.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("program handoff memory missing: memories=%+v err=%v", memories, err)
	}
	var handoff *store.ProgramMemory
	for index := range memories {
		if memories[index].Kind == "handoff" && memories[index].SourceKind == "event" && memories[index].SourceID == event.ID {
			handoff = &memories[index]
			break
		}
	}
	if handoff == nil || handoff.ScopeHash != program.ScopeHash {
		t.Fatalf("handoff memory lost per-program provenance: %+v", memories)
	}
	search, err := database.SearchProgramMemories(ctx, program.ID, "new.example.test", 10, start.Add(3*time.Minute))
	if err != nil || len(search) != 1 || search[0].ID != handoff.ID {
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
	var matchingHandoffs int
	for _, memory := range handoffs {
		if memory.Kind == "handoff" && memory.SourceKind == "event" && memory.SourceID == event.ID {
			matchingHandoffs++
		}
	}
	if matchingHandoffs != 1 {
		t.Fatalf("triage created duplicate or missing handoff memories: %+v", handoffs)
	}
}

func TestTriageRejectsMemoryBriefThatChangedBeforeCommit(t *testing.T) {
	database := openTriageStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.August, 15, 0, 0, 0, 0, time.UTC)
	program, _ := createMaterialReconEvent(t, database, start)
	leases, err := database.ClaimAgentEventTasks(ctx, start.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim triage task: leases=%+v err=%v", leases, err)
	}
	triageContext, err := database.LoadAgentEventTriageContext(ctx, leases[0], start.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildAgentEventTriageOutput(triageContext, start.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddProgramMemory(ctx, store.AddProgramMemoryParams{
		ProgramID: program.ID, Kind: "fact", Title: "Added during triage",
		Content: "Memory changed after the briefing snapshot.", SourceKind: "operator", ScopeHash: program.ScopeHash, Confidence: 1,
	}, start.Add(2*time.Minute+time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CompleteAgentEventTriage(ctx, leases[0], output, start.Add(2*time.Minute+2*time.Second)); err != store.ErrAgentEventTriageContextChanged {
		t.Fatalf("stale memory briefing completion error = %v, want context-changed", err)
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
