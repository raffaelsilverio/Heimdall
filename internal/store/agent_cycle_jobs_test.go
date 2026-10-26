package store

import (
	"context"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func TestAgentCycleQueueRequiresConsentAndEnforcesDailyCapWithoutReplay(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.October, 26, 0, 0, 0, 0, time.UTC)
	program, err := createQueueTestProgram(t, database, "Queued adaptive program", start, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", false, start.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		at := start.Add(time.Duration(index) * time.Minute)
		jobs, err := database.ClaimDueSchedules(ctx, at, time.Hour)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("claim source recon run %d: jobs=%d err=%v", index, len(jobs), err)
		}
		observations := []recon.Observation{{
			Category: recon.CategoryHTTPEndpoint, StableKey: "https://cycle.example.test/base", Value: "https://cycle.example.test/base", Source: "test",
		}}
		if index >= 1 {
			observations = append(observations, recon.Observation{
				Category: recon.CategoryHTTPEndpoint, StableKey: "https://cycle.example.test/route-" + string(rune('0'+index)),
				Value: "https://cycle.example.test/route-" + string(rune('0'+index)), Source: "test",
			})
		}
		if _, err := database.CompleteRun(ctx, jobs[0].RunID, recon.Collection{Observations: observations}, true, nil, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", true, start.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}

	leases, err := database.ClaimAgentCycleJobs(ctx, start.Add(3*time.Minute), 30*time.Second, 5)
	if err != nil || len(leases) != 1 {
		t.Fatalf("daily request cap should lease exactly one of two queued tasks: leases=%+v err=%v", leases, err)
	}
	if leases[0].AutomationRevision <= 0 || leases[0].ActionRunID == "" || leases[0].EventScopeHash != program.ScopeHash ||
		leases[0].Automation.PlannerModel != "queue-test-model" || leases[0].Stage != recon.StageOSINT || leases[0].RequestBudget != 1 {
		t.Fatalf("cycle lease omitted the consent/scope snapshot: %+v", leases[0])
	}
	again, err := database.ClaimAgentCycleJobs(ctx, start.Add(4*time.Minute), 30*time.Second, 5)
	if err != nil || len(again) != 0 {
		t.Fatalf("daily request budget was exceeded: leases=%+v err=%v", again, err)
	}
	var dailyUsage int
	var dailyRequests int
	if err := database.db.QueryRowContext(ctx, `SELECT cycles_started, requests_reserved FROM agent_cycle_daily_usage WHERE program_id = ? AND utc_day = '2026-10-26'`, program.ID).Scan(&dailyUsage, &dailyRequests); err != nil || dailyUsage != 1 || dailyRequests != 1 {
		t.Fatalf("daily cycle/request usage was not atomically charged: cycles=%d requests=%d err=%v", dailyUsage, dailyRequests, err)
	}
	// An expired running lease is moved to review, never reclaimed or replayed.
	recovered, err := database.ClaimAgentCycleJobs(ctx, start.Add(4*time.Minute+31*time.Second), 30*time.Second, 5)
	if err != nil || len(recovered) != 0 {
		t.Fatalf("expired adaptive lease was replayed: leases=%+v err=%v", recovered, err)
	}
	cycleJobs, err := database.ListAgentCycleJobs(ctx, program.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	foundReview := false
	for _, job := range cycleJobs {
		if job.TaskID == leases[0].TaskID && job.Status == "needs_review" {
			foundReview = true
		}
	}
	if !foundReview {
		t.Fatalf("expired cycle job was not marked for review: %+v", cycleJobs)
	}
	if err := database.ResolveAgentCycleJobReview(ctx, program.ID, leases[0].TaskID,
		"assessed_no_action", "test-operator", "Reviewed expired lease; no action-run ledger was created.", start.Add(4*time.Minute+32*time.Second)); err != nil {
		t.Fatalf("resolve expired no-action cycle job: %v", err)
	}
	cycleJobs, err = database.ListAgentCycleJobs(ctx, program.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	foundReviewed := false
	for _, job := range cycleJobs {
		if job.TaskID == leases[0].TaskID && job.Status == "failed" && job.ReviewDecision == "assessed_no_action" && job.ReviewedAt != nil {
			foundReviewed = true
		}
	}
	if !foundReviewed {
		t.Fatalf("operator cycle-job review was not recorded: %+v", cycleJobs)
	}
	if err := database.ResolveAgentCycleJobReview(ctx, program.ID, leases[0].TaskID,
		"assessed_completed", "test-operator", "Duplicate review", start.Add(4*time.Minute+33*time.Second)); err == nil {
		t.Fatal("cycle job review was recorded twice")
	}
	if _, err := database.DisableProgramAgentAutomation(ctx, program.ID, "operator", "Disable queued automation", start.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	count, err := database.ClaimAgentCycleJobs(ctx, start.Add(6*time.Minute), 30*time.Second, 5)
	if err != nil || len(count) != 0 {
		t.Fatalf("revoked automation was still claimable: leases=%+v err=%v", count, err)
	}
	cycleJobs, err = database.ListAgentCycleJobs(ctx, program.ID, 10)
	if err != nil || len(cycleJobs) != 2 {
		t.Fatalf("cycle queue was not inspectable: jobs=%+v err=%v", cycleJobs, err)
	}
	for _, job := range cycleJobs {
		if job.Status != "cancelled" && job.Status != "failed" {
			t.Fatalf("unexpected queued job state after consent revocation: %+v", job)
		}
	}
}

func TestMaterialEventDoesNotQueueCycleWithoutPersistentAutomationConsent(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.October, 27, 0, 0, 0, 0, time.UTC)
	program, err := createQueueTestProgram(t, database, "No consent adaptive program", start, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", false, start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for index, host := range []string{"https://cycle.example.test/base", "https://cycle.example.test/new"} {
		at := start.Add(time.Duration(index) * time.Minute)
		jobs, err := database.ClaimDueSchedules(ctx, at, time.Hour)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("claim recon run: jobs=%d err=%v", len(jobs), err)
		}
		if _, err := database.CompleteRun(ctx, jobs[0].RunID, recon.Collection{Observations: []recon.Observation{{
			Category: recon.CategoryHTTPEndpoint, StableKey: host, Value: host, Source: "test",
		}}}, true, nil, at); err != nil {
			t.Fatal(err)
		}
	}
	cycleJobs, err := database.ListAgentCycleJobs(ctx, program.ID, 10)
	if err != nil || len(cycleJobs) != 0 {
		t.Fatalf("event queued an adaptive cycle without consent: jobs=%+v err=%v", cycleJobs, err)
	}
}

func createQueueTestProgram(t *testing.T, database *Store, name string, now time.Time, enableAutomation bool) (assessment.Program, error) {
	t.Helper()
	ctx := context.Background()
	program, err := database.CreateProgram(ctx, CreateProgramParams{
		Name: name, AuthorizationReference: "internal:agent-cycle-queue",
		ExpiresAt: now.Add(10 * 24 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "cycle.example.test", Ports: []uint16{443},
		}}},
	}, now)
	if err != nil {
		return assessment.Program{}, err
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", true, now); err != nil {
		return assessment.Program{}, err
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageOSINT, "* * * * *", "UTC", true, now); err != nil {
		return assessment.Program{}, err
	}
	if err := database.ActivateProgram(ctx, program.ID, now); err != nil {
		return assessment.Program{}, err
	}
	if _, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 2, MaxRequestsPerRun: 2, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, now.Add(time.Second)); err != nil {
		return assessment.Program{}, err
	}
	if enableAutomation {
		expires := now.Add(5 * 24 * time.Hour)
		if _, err := database.SetProgramAgentAutomation(ctx, program.ID, ProgramAgentAutomation{
			Enabled: true, PlannerProvider: "openai", PlannerModel: "queue-test-model",
			ContextEgressExpiresAt: &expires, AllowModelContextEgress: true, AllowActiveRequests: true,
			MaxCyclesPerDay: 2, MaxRequestsPerDay: 1, MaxStepsPerCycle: 2, ReviewedBy: "test-operator", ReviewReason: "Queue test consent",
		}, now.Add(2*time.Second)); err != nil {
			return assessment.Program{}, err
		}
	}
	return program, nil
}
