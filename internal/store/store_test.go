package store

import (
	"context"
	"database/sql"
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

func TestCreateActivateAndListProgram(t *testing.T) {
	database := openTestStore(t)
	now := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	program := createActiveProgram(t, database, now)
	if program.Status != assessment.ProgramDraft {
		t.Fatalf("new program status = %q, want draft", program.Status)
	}
	stored, err := database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != assessment.ProgramActive {
		t.Fatalf("stored program status = %q, want active", stored.Status)
	}
	if stored.AuthorizationReference != "https://example.test/program" {
		t.Errorf("authorization reference was not stored: %q", stored.AuthorizationReference)
	}
	programs, err := database.ListPrograms(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(programs) != 1 || programs[0].ID != program.ID {
		t.Fatalf("unexpected listed programs: %+v", programs)
	}
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

func TestExpiredAuthorizationPausesProgramAndSchedule(t *testing.T) {
	database := openTestStore(t)
	start := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	program := createActiveProgram(t, database, start)
	if err := database.SetStageSchedule(context.Background(), program.ID, recon.StageOSINT, "0 3 * * *", "UTC", true, start); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimDueSchedules(context.Background(), start.Add(25*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("expired authorization produced %d jobs", len(jobs))
	}
	stored, err := database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != assessment.ProgramPaused {
		t.Fatalf("expired program status = %q, want paused", stored.Status)
	}
	var enabled int
	if err := database.db.QueryRowContext(context.Background(), `SELECT enabled FROM stage_schedules WHERE program_id = ? AND stage = ?`, program.ID, recon.StageOSINT).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatal("expired authorization left the schedule enabled")
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

func TestMissedDailyScheduleCoalescesToOneCatchUp(t *testing.T) {
	database := openTestStore(t)
	start := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	program, err := database.CreateProgram(context.Background(), CreateProgramParams{
		Name:                   "Catch-up test",
		AuthorizationReference: "internal:catch-up-test",
		ExpiresAt:              start.Add(30 * 24 * time.Hour),
		Scope:                  assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "example.com"}}},
		Timezone:               "UTC",
	}, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(context.Background(), program.ID, start); err != nil {
		t.Fatal(err)
	}
	catchUpAt := start.Add(5 * 24 * time.Hour)
	first, err := database.ClaimDueSchedules(context.Background(), catchUpAt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("catch-up claimed %d runs, want one", len(first))
	}
	second, err := database.ClaimDueSchedules(context.Background(), catchUpAt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("coalesced catch-up created %d additional runs", len(second))
	}
}

func TestDNSStageScheduleIsOptIn(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Minute)
	program, err := database.CreateProgram(context.Background(), CreateProgramParams{
		Name:                   "DNS schedule test",
		AuthorizationReference: "internal:dns-schedule",
		ExpiresAt:              now.Add(48 * time.Hour),
		Scope:                  assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeWildcardDomain, Value: "example.com"}}},
		Timezone:               "UTC",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var dnsSchedules int
	if err := database.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM stage_schedules WHERE program_id = ? AND stage = ?`, program.ID, recon.StageDNS).Scan(&dnsSchedules); err != nil {
		t.Fatal(err)
	}
	if dnsSchedules != 0 {
		t.Fatal("new program unexpectedly received an active DNS schedule")
	}
	if err := database.SetStageSchedule(context.Background(), program.ID, recon.StageDNS, "0 4 * * *", "UTC", false, now); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(context.Background(), program.ID, now); err != nil {
		t.Fatal(err)
	}
	var enabled int
	if err := database.db.QueryRowContext(context.Background(), `SELECT enabled FROM stage_schedules WHERE program_id = ? AND stage = ?`, program.ID, recon.StageDNS).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatal("program activation enabled an explicitly disabled DNS schedule")
	}
	if err := database.SetStageSchedule(context.Background(), program.ID, recon.StageDNS, "0 4 * * *", "UTC", true, now); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(context.Background(), `SELECT enabled FROM stage_schedules WHERE program_id = ? AND stage = ?`, program.ID, recon.StageDNS).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Fatal("explicitly enabled DNS schedule was not persisted")
	}
}

func TestWebSchedulePersistsPortPolicyAndLimitsOnlyOnOptIn(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Minute)
	program, err := database.CreateProgram(context.Background(), CreateProgramParams{
		Name:                   "Web policy test",
		AuthorizationReference: "internal:web-policy",
		ExpiresAt:              now.Add(48 * time.Hour),
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Type: assessment.ScopeWildcardDomain, Value: "example.com", Ports: []uint16{443, 80},
		}}},
		Timezone: "UTC",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var webSchedules int
	if err := database.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM stage_schedules WHERE program_id = ? AND stage = ?`, program.ID, recon.StageWeb).Scan(&webSchedules); err != nil {
		t.Fatal(err)
	}
	if webSchedules != 0 {
		t.Fatal("new program unexpectedly received a web schedule")
	}
	limits := recon.StageLimits{RateLimitPerSecond: 1, MaxConcurrency: 1, MaxTargets: 25, TimeoutSeconds: 90}
	if err := database.SetStageSchedule(context.Background(), program.ID, recon.StageWeb, "0 6 * * 1", "UTC", true, now, limits); err != nil {
		t.Fatal(err)
	}
	var rate, concurrency, targets, timeout int
	if err := database.db.QueryRowContext(context.Background(), `SELECT rate_limit_per_second, max_concurrency, max_targets, timeout_seconds
		FROM stage_schedules WHERE program_id = ? AND stage = ?`, program.ID, recon.StageWeb).Scan(&rate, &concurrency, &targets, &timeout); err != nil {
		t.Fatal(err)
	}
	if rate != limits.RateLimitPerSecond || concurrency != limits.MaxConcurrency || targets != limits.MaxTargets || timeout != limits.TimeoutSeconds {
		t.Fatalf("stored limits = %d/%d/%d/%d, want %+v", rate, concurrency, targets, timeout, limits)
	}
	if err := database.SetStageSchedule(context.Background(), program.ID, recon.StageWeb, "0 7 * * 1", "UTC", true, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(context.Background(), `SELECT rate_limit_per_second, max_concurrency, max_targets, timeout_seconds
		FROM stage_schedules WHERE program_id = ? AND stage = ?`, program.ID, recon.StageWeb).Scan(&rate, &concurrency, &targets, &timeout); err != nil {
		t.Fatal(err)
	}
	if rate != limits.RateLimitPerSecond || concurrency != limits.MaxConcurrency || targets != limits.MaxTargets || timeout != limits.TimeoutSeconds {
		t.Fatalf("schedule-only update changed limits to %d/%d/%d/%d", rate, concurrency, targets, timeout)
	}
	stored, err := database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Scope.Entries) != 1 || len(stored.Scope.Entries[0].Ports) != 2 || stored.Scope.Entries[0].Ports[0] != 80 || stored.Scope.Entries[0].Ports[1] != 443 {
		t.Fatalf("authorized ports were not normalized and persisted: %+v", stored.Scope)
	}
}

func TestChangedToolProfileStartsNewBaseline(t *testing.T) {
	database := openTestStore(t)
	start := time.Now().UTC().Truncate(time.Minute)
	program := createActiveProgram(t, database, start)
	first, err := database.ClaimDueSchedules(context.Background(), start, time.Hour)
	if err != nil || len(first) != 1 {
		t.Fatalf("claim initial run: jobs=%d err=%v", len(first), err)
	}
	if _, err := database.CompleteRun(context.Background(), first[0].RunID, recon.Collection{
		ProfileVersion: "passive-v1",
		Observations:   []recon.Observation{{Category: recon.CategoryHostname, StableKey: "www.example.com", Value: "www.example.com", Source: "subfinder"}},
	}, true, nil, start); err != nil {
		t.Fatal(err)
	}
	second, err := database.ClaimDueSchedules(context.Background(), start.Add(time.Minute), time.Hour)
	if err != nil || len(second) != 1 {
		t.Fatalf("claim changed-profile run: jobs=%d err=%v", len(second), err)
	}
	events, err := database.CompleteRun(context.Background(), second[0].RunID, recon.Collection{ProfileVersion: "passive-v2"}, true, nil, start.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("tool profile change was compared against an incompatible baseline: %+v", events)
	}
	var baselines int
	if err := database.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM baselines WHERE program_id = ?`, program.ID).Scan(&baselines); err != nil {
		t.Fatal(err)
	}
	if baselines != 2 {
		t.Fatalf("got %d profile baselines, want 2", baselines)
	}
	seeds, err := database.InScopeHostSeeds(context.Background(), program.ID, program.ScopeHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != 0 {
		t.Fatalf("old-profile host seeds leaked into the active web inventory: %+v", seeds)
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

func TestUpgradeFromInitialSchemaPreservesAuthorizationExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE schema_migrations(version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	initialMigration, err := migrationFiles.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(string(initialMigration)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES ('001_initial.sql', 1)`); err != nil {
		t.Fatal(err)
	}
	const expirySeconds int64 = 2_000_000_000
	if _, err := database.Exec(`INSERT INTO programs(id, name, status, scope_json, scope_hash, scope_revision, created_at, updated_at)
		VALUES ('legacy-program', 'Legacy', 'draft', ?, 'legacy-hash', 1, 1, 1)`, `{"entries":[{"effect":"include","type":"domain","value":"example.com"}]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO authorizations(id, program_id, reference, expires_at, created_at)
		VALUES ('legacy-auth', 'legacy-program', 'internal:legacy', ?, 1)`, expirySeconds); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	program, err := upgraded.GetProgram(context.Background(), "legacy-program")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(expirySeconds, 0).UTC()
	if !program.ExpiresAt.Equal(want) {
		t.Fatalf("upgraded expiry = %s, want %s", program.ExpiresAt, want)
	}
	for _, table := range []string{"tool_runs", "artifacts"} {
		var count int
		if err := upgraded.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("migration did not create %s", table)
		}
	}
}

func TestInteractiveSessionPersistsMessagesAndCanBeClosed(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC()
	program := createActiveProgram(t, database, now)
	session, err := database.CreateSession(context.Background(), program.ID, "Triage notes", now)
	if err != nil {
		t.Fatal(err)
	}
	if session.Kind != "interactive" || session.Status != "open" {
		t.Fatalf("unexpected session state: %+v", session)
	}
	if _, err := database.AppendSessionMessage(context.Background(), session.ID, "user", "Check the observed hostname", "", "", nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AppendSessionMessage(context.Background(), session.ID, "assistant", "I will review the evidence.", "openai", "test-model", nil, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	messages, err := database.ListSessionMessages(context.Background(), session.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Sequence != 1 || messages[1].Provider != "openai" || messages[1].Model != "test-model" {
		t.Fatalf("unexpected persisted messages: %+v", messages)
	}
	if err := database.CloseSession(context.Background(), session.ID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AppendSessionMessage(context.Background(), session.ID, "user", "after close", "", "", nil, now.Add(3*time.Second)); err == nil {
		t.Fatal("closed session accepted a new message")
	}
}
