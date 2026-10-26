package execution

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/raffaelsilverio/Heimdall/providers"
)

type cycleWorkerModel struct {
	requests []providers.Request
}

func (m *cycleWorkerModel) Name() string { return "openai" }

func (m *cycleWorkerModel) Generate(_ context.Context, request providers.Request) (providers.Response, error) {
	m.requests = append(m.requests, request)
	return providers.Response{Content: `{"actions":[]}`}, nil
}

func TestAgentCycleWorkerConsumesOnlyNewConsentedQueueJobs(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	program, err := database.CreateProgram(ctx, store.CreateProgramParams{
		Name: "Cycle worker test", AuthorizationReference: "internal:cycle-worker",
		ExpiresAt: now.Add(24 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Effect: assessment.ScopeInclude, Type: assessment.ScopeWildcardDomain, Value: "worker.example.test",
		}}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageOSINT, "* * * * *", "UTC", true, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "0 0 1 1 *", "UTC", true, now); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 2, MaxRequestsPerRun: 2, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(12 * time.Hour)
	if _, err := database.SetProgramAgentAutomation(ctx, program.ID, store.ProgramAgentAutomation{
		Enabled: true, PlannerProvider: "openai", PlannerModel: "cycle-worker-test-model",
		ContextEgressExpiresAt: &expires, AllowModelContextEgress: true, AllowActiveRequests: true,
		MaxCyclesPerDay: 2, MaxRequestsPerDay: 1, MaxStepsPerCycle: 2, ReviewedBy: "test-operator", ReviewReason: "Local test consent",
	}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", false, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}

	completeRecon := func(at time.Time, hosts ...string) []store.ChangeEvent {
		t.Helper()
		jobs, err := database.ClaimDueSchedules(ctx, at, time.Hour)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("claim recon source run: jobs=%d err=%v", len(jobs), err)
		}
		if jobs[0].Stage != recon.StageOSINT {
			t.Fatalf("test expected OSINT source run, got stage=%s", jobs[0].Stage)
		}
		observations := make([]recon.Observation, 0, len(hosts))
		for _, host := range hosts {
			observations = append(observations, recon.Observation{
				Category: recon.CategoryHostname, StableKey: host, Value: host, Source: "test",
			})
		}
		events, err := database.CompleteRun(ctx, jobs[0].RunID, recon.Collection{Observations: observations}, true, nil, at)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	if events := completeRecon(now, "base.worker.example.test"); len(events) != 0 {
		t.Fatalf("initial baseline unexpectedly generated material events: %+v", events)
	}
	events := completeRecon(now.Add(time.Minute), "base.worker.example.test", "new.worker.example.test")
	if len(events) != 1 || !events[0].Material {
		t.Fatalf("expected one material event to queue: %+v", events)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ListAgentCycleJobs(ctx, program.ID, 10)
	if err != nil || len(jobs) != 1 || jobs[0].Status != "pending" {
		consent, _ := database.GetProgramAgentAutomation(ctx, program.ID)
		pending, _ := database.HasPendingProgramSourceReview(ctx, program.ID)
		tasks, _ := database.ListAgentTaskStatuses(ctx, program.ID, 10)
		t.Fatalf("consented material event was not queued: jobs=%+v tasks=%+v err=%v consent=%+v authorization_expires=%s source_pending=%t now=%s", jobs, tasks, err, consent, program.ExpiresAt, pending, time.Now().UTC())
	}

	model := &cycleWorkerModel{}
	worker := AgentCycleWorker{
		Store: database,
		NewProvider: func(provider, _ string) (providers.Provider, error) {
			if provider != "openai" {
				t.Fatalf("provider = %q, want consent-bound openai", provider)
			}
			return model, nil
		},
	}
	processed, err := worker.RunCycle(ctx, now.Add(2*time.Minute))
	if err != nil || processed != 1 {
		t.Fatalf("consented adaptive cycle worker: processed=%d err=%v", processed, err)
	}
	if len(model.requests) != 1 || !strings.Contains(model.requests[0].Messages[1].Content, "new.worker.example.test") ||
		!strings.Contains(model.requests[0].Messages[1].Content, "Material recon event") {
		t.Fatalf("planner did not receive the bounded event seed: %+v", model.requests)
	}
	jobs, err = database.ListAgentCycleJobs(ctx, program.ID, 10)
	if err != nil || len(jobs) != 1 || jobs[0].Status != "completed" || jobs[0].ActionRunID == "" {
		t.Fatalf("adaptive job lifecycle was not persisted: jobs=%+v err=%v", jobs, err)
	}
	run, err := database.GetAgentActionRun(ctx, program.ID, jobs[0].ActionRunID)
	if err != nil || run.Status != "completed" || run.MaxRequests != 1 || run.PlannerCalls != 1 || run.PlannerProvider != "openai" || run.PlannerModel != "cycle-worker-test-model" {
		t.Fatalf("automation planner call was not audited: run=%+v err=%v", run, err)
	}
	consent, err := database.GetProgramAgentAutomation(ctx, program.ID)
	if err != nil || consent.CyclesStartedToday != 1 || consent.RequestsReservedToday != 1 {
		t.Fatalf("daily automatic cycle/request reservations were not surfaced: consent=%+v err=%v", consent, err)
	}
	processed, err = worker.RunCycle(ctx, now.Add(3*time.Minute))
	if err != nil || processed != 0 || len(model.requests) != 1 {
		t.Fatalf("completed event cycle was replayed: processed=%d providerCalls=%d err=%v", processed, len(model.requests), err)
	}
}
