package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func createActiveProgram(t *testing.T, database *Store, now time.Time) assessment.Program {
	t.Helper()
	program, err := database.CreateProgram(context.Background(), CreateProgramParams{
		Name:                   "Example Program",
		AuthorizationReference: "https://example.test/program",
		ExpiresAt:              now.Add(24 * time.Hour),
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Type: assessment.ScopeWildcardDomain, Value: "example.com",
		}}},
		Timezone: "UTC",
	}, now)
	if err != nil {
		t.Fatalf("CreateProgram returned an error: %v", err)
	}
	if err := database.SetStageSchedule(context.Background(), program.ID, recon.StageOSINT, "* * * * *", "UTC", true, now.Add(-time.Minute)); err != nil {
		t.Fatalf("SetStageSchedule returned an error: %v", err)
	}
	if err := database.ActivateProgram(context.Background(), program.ID, now); err != nil {
		t.Fatalf("ActivateProgram returned an error: %v", err)
	}
	return program
}

func TestBaselineAndConfirmedRemoval(t *testing.T) {
	database := openTestStore(t)
	start := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	program := createActiveProgram(t, database, start)

	run := func(at time.Time, hosts ...string) []ChangeEvent {
		t.Helper()
		jobs, err := database.ClaimDueSchedules(context.Background(), at, time.Hour)
		if err != nil {
			t.Fatalf("ClaimDueSchedules returned an error: %v", err)
		}
		if len(jobs) != 1 {
			t.Fatalf("claimed %d jobs, want 1", len(jobs))
		}
		observations := make([]recon.Observation, 0, len(hosts))
		for _, host := range hosts {
			observations = append(observations, recon.Observation{
				Category: recon.CategoryHostname, StableKey: host, Value: host, Source: "test", ToolVersion: "test-v1",
			})
		}
		events, err := database.CompleteRun(context.Background(), jobs[0].RunID, recon.Collection{Observations: observations}, true, nil, at)
		if err != nil {
			t.Fatalf("CompleteRun returned an error: %v", err)
		}
		return events
	}

	if events := run(start, "one.example.com"); len(events) != 0 {
		t.Fatalf("initial baseline produced events: %+v", events)
	}
	seeds, err := database.InScopeHostSeeds(context.Background(), program.ID, program.ScopeHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != 1 || seeds[0] != "one.example.com" {
		t.Fatalf("unexpected active target seeds: %+v", seeds)
	}
	added := run(start.Add(time.Minute), "one.example.com", "two.example.com")
	if len(added) != 1 || added[0].ChangeType != "added" || added[0].StableKey != "two.example.com" || !added[0].Material {
		t.Fatalf("unexpected addition event: %+v", added)
	}
	sessions, err := database.ListSessions(context.Background(), program.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Kind != "agent_event" || sessions[0].TriggerEventID != added[0].ID {
		t.Fatalf("material change did not create its own agent session: %+v", sessions)
	}
	var pendingTasks int
	if err := database.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM agent_tasks WHERE session_id = ? AND status = 'pending'`, sessions[0].ID).Scan(&pendingTasks); err != nil {
		t.Fatal(err)
	}
	if pendingTasks != 1 {
		t.Fatalf("material change session has %d pending agent tasks, want 1", pendingTasks)
	}
	if events := run(start.Add(2*time.Minute), "two.example.com"); len(events) != 0 {
		t.Fatalf("first absence should not create a removal: %+v", events)
	}
	seeds, err = database.InScopeHostSeeds(context.Background(), program.ID, program.ScopeHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != 1 || seeds[0] != "two.example.com" {
		t.Fatalf("first-miss host was still included in active targets: %+v", seeds)
	}
	removed := run(start.Add(3*time.Minute), "two.example.com")
	if len(removed) != 1 || removed[0].ChangeType != "removed" || removed[0].StableKey != "one.example.com" {
		t.Fatalf("unexpected confirmed-removal event: %+v", removed)
	}
}

func TestPartialRunDoesNotAdvanceBaseline(t *testing.T) {
	database := openTestStore(t)
	start := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	_ = createActiveProgram(t, database, start)
	claim := func(at time.Time) DueJob {
		t.Helper()
		jobs, err := database.ClaimDueSchedules(context.Background(), at, time.Hour)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("claim due job: jobs=%d err=%v", len(jobs), err)
		}
		return jobs[0]
	}
	first := claim(start)
	if _, err := database.CompleteRun(context.Background(), first.RunID, recon.Collection{Observations: []recon.Observation{{Category: recon.CategoryHostname, StableKey: "a.example.com", Value: "a.example.com", Source: "test"}}}, true, nil, start); err != nil {
		t.Fatal(err)
	}
	partial := claim(start.Add(time.Minute))
	if _, err := database.CompleteRun(context.Background(), partial.RunID, recon.Collection{}, false, nil, start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	missingOnce := claim(start.Add(2 * time.Minute))
	if events, err := database.CompleteRun(context.Background(), missingOnce.RunID, recon.Collection{}, true, nil, start.Add(2*time.Minute)); err != nil || len(events) != 0 {
		t.Fatalf("first complete absence: events=%+v err=%v", events, err)
	}
	missingTwice := claim(start.Add(3 * time.Minute))
	events, err := database.CompleteRun(context.Background(), missingTwice.RunID, recon.Collection{}, true, nil, start.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ChangeType != "removed" {
		t.Fatalf("partial run affected absence threshold: %+v", events)
	}
}

func TestRunFinishingAfterAuthorizationExpiryCannotAdvanceBaseline(t *testing.T) {
	database := openTestStore(t)
	start := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	program, err := database.CreateProgram(context.Background(), CreateProgramParams{
		Name:                   "Expires during run",
		AuthorizationReference: "internal:expiry-test",
		ExpiresAt:              start.Add(24 * time.Hour),
		Scope:                  assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "example.com"}}},
		Timezone:               "UTC",
	}, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(context.Background(), program.ID, start); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimDueSchedules(context.Background(), start, time.Hour)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim scheduled run: jobs=%d err=%v", len(jobs), err)
	}
	if err := database.ValidateRunAuthorization(context.Background(), jobs[0].RunID, start); err != nil {
		t.Fatalf("valid run authorization was rejected: %v", err)
	}
	if err := database.ValidateRunAuthorization(context.Background(), jobs[0].RunID, start.Add(24*time.Hour+time.Second)); err == nil {
		t.Fatal("expired run authorization was accepted")
	}
	_, err = database.CompleteRun(context.Background(), jobs[0].RunID, recon.Collection{Observations: []recon.Observation{{
		Category: recon.CategoryHostname, StableKey: "www.example.com", Value: "www.example.com", Source: "test",
	}}}, true, nil, start.Add(24*time.Hour+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var status string
	if err := database.db.QueryRowContext(context.Background(), `SELECT status FROM runs WHERE id = ?`, jobs[0].RunID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "interrupted" {
		t.Fatalf("run status = %q, want interrupted", status)
	}
	var baselines int
	if err := database.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM baselines WHERE program_id = ?`, program.ID).Scan(&baselines); err != nil {
		t.Fatal(err)
	}
	if baselines != 0 {
		t.Fatal("run after expiry advanced the baseline")
	}
}

func TestCompleteRunPersistsArtifactAndToolProvenance(t *testing.T) {
	database := openTestStore(t)
	start := time.Now().UTC().Truncate(time.Minute)
	program := createActiveProgram(t, database, start)
	jobs, err := database.ClaimDueSchedules(context.Background(), start, time.Hour)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim scheduled run: jobs=%d err=%v", len(jobs), err)
	}
	collection := recon.Collection{
		ProfileVersion: "osint-test-profile",
		Tools:          []recon.ToolResult{{ID: "subfinder", Binary: "/opt/subfinder", Version: "vtest", Status: "complete"}},
		Artifacts:      []recon.Artifact{{Name: "subfinder.jsonl", MediaType: "application/x-ndjson", Data: []byte(`{"host":"www.example.com"}` + "\n")}},
	}
	if _, err := database.CompleteRun(context.Background(), jobs[0].RunID, collection, true, nil, start); err != nil {
		t.Fatal(err)
	}
	artifacts, err := database.ListArtifacts(context.Background(), jobs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("got %d artifact records, want 1", len(artifacts))
	}
	artifactPath := filepath.Join(database.homeDir, filepath.FromSlash(artifacts[0].RelativePath))
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(collection.Artifacts[0].Data) {
		t.Fatalf("artifact data mismatch: %q", data)
	}
	var profileVersion string
	if err := database.db.QueryRowContext(context.Background(), `SELECT profile_version FROM runs WHERE id = ?`, jobs[0].RunID).Scan(&profileVersion); err != nil {
		t.Fatal(err)
	}
	if profileVersion != collection.ProfileVersion {
		t.Fatalf("stored profile version = %q, want %q", profileVersion, collection.ProfileVersion)
	}
	var version string
	if err := database.db.QueryRowContext(context.Background(), `SELECT version FROM tool_runs WHERE run_id = ? AND tool_id = 'subfinder'`, jobs[0].RunID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "vtest" {
		t.Fatalf("stored tool version = %q, want vtest", version)
	}
	if program.ID != jobs[0].Program.ID {
		t.Fatal("claimed program mismatch")
	}
}
