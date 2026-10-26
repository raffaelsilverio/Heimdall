package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func TestCompleteRunCapturesAndSupersedesQuietRunMemory(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.October, 20, 0, 0, 0, 0, time.UTC)
	program := createActiveProgram(t, database, start)

	run := func(at time.Time, hosts ...string) (string, []ChangeEvent) {
		t.Helper()
		jobs, err := database.ClaimDueSchedules(ctx, at, time.Hour)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("claim scheduled run: jobs=%d err=%v", len(jobs), err)
		}
		observations := make([]recon.Observation, 0, len(hosts))
		for _, host := range hosts {
			observations = append(observations, recon.Observation{
				Category: recon.CategoryHostname, StableKey: host, Value: host, Source: "test-tool",
			})
		}
		events, err := database.CompleteRun(ctx, jobs[0].RunID, recon.Collection{Observations: observations}, true, nil, at)
		if err != nil {
			t.Fatalf("complete run: %v", err)
		}
		return jobs[0].RunID, events
	}

	firstRun, events := run(start, "a.example.com")
	if len(events) != 0 {
		t.Fatalf("initial baseline unexpectedly emitted events: %+v", events)
	}
	memories, err := database.ListProgramMemories(ctx, program.ID, 10, start.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(memories) != 1 || memories[0].SourceKind != "run" || memories[0].SourceID != firstRun || memories[0].ScopeHash != program.ScopeHash {
		t.Fatalf("quiet run memory is missing run/scope provenance: %+v", memories)
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(memories[0].Content), &summary); err != nil {
		t.Fatalf("quiet run memory is not valid summary JSON: %v", err)
	}
	if summary["notice"] == nil || !strings.Contains(summary["notice"].(string), "does not validate vulnerabilities") {
		t.Fatalf("summary does not clearly distinguish observation from validation: %+v", summary)
	}
	if memories[0].ExpiresAt == nil || !memories[0].ExpiresAt.Equal(start.Add(30*24*time.Hour)) {
		t.Fatalf("quiet run memory has unexpected retention: %+v", memories[0].ExpiresAt)
	}

	secondRun, events := run(start.Add(time.Minute), "a.example.com")
	if len(events) != 0 {
		t.Fatalf("unchanged run unexpectedly emitted events: %+v", events)
	}
	memories, err = database.ListProgramMemories(ctx, program.ID, 10, start.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(memories) != 1 || memories[0].SourceID != secondRun || memories[0].SupersedesID == "" {
		t.Fatalf("latest quiet-run summary did not supersede the previous active summary: %+v", memories)
	}
	previous, err := database.GetProgramMemory(ctx, program.ID, memories[0].SupersedesID)
	if err != nil || previous.Status != "superseded" || previous.SourceID != firstRun {
		t.Fatalf("superseded run summary lost history: memory=%+v err=%v", previous, err)
	}

	materialRun, events := run(start.Add(2*time.Minute), "a.example.com", "b.example.com")
	if len(events) != 1 || !events[0].Material {
		t.Fatalf("new hostname should create a material event: %+v", events)
	}
	memories, err = database.ListProgramMemories(ctx, program.ID, 10, start.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(memories) != 1 || memories[0].SourceID != secondRun || memories[0].SourceID == materialRun {
		t.Fatalf("material run was incorrectly captured as a quiet summary: %+v", memories)
	}
}
