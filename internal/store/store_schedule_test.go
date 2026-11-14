package store

import (
	"context"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

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
