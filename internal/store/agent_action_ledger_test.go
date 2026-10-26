package store

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

type ledgerGrantJSON struct {
	ProgramID      string               `json:"program_id"`
	ScopeHash      string               `json:"scope_hash"`
	PolicyRevision int64                `json:"policy_revision"`
	Stage          string               `json:"stage"`
	Class          contract.ActionClass `json:"class"`
	Targets        []string             `json:"targets"`
	RequestBudget  int                  `json:"request_budget"`
	Limits         recon.StageLimits    `json:"limits"`
	ValidUntil     time.Time            `json:"valid_until"`
	Proposal       struct {
		Stage          string   `json:"stage"`
		ScopeHash      string   `json:"scope_hash"`
		Targets        []string `json:"targets"`
		EstimatedCalls int      `json:"estimated_calls"`
	} `json:"proposal"`
}

func TestAgentActionLedgerReservesBudgetsIdempotentlyAndPreventsReplay(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.October, 22, 0, 0, 0, 0, time.UTC)
	program := createLedgerProgram(t, database, start, "Ledger program one")
	policy, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageOSINT}, AllowedClasses: []contract.ActionClass{contract.ActionPassive},
		MaxActionsPerRun: 2, MaxRequestsPerRun: 3, MaxRequestsPerAction: 2, MaxTargetsPerAction: 3,
	}, start.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now := start.Add(2 * time.Second)
	cycleID := uuid.NewString()
	cycle, err := database.CreateAgentActionRun(ctx, cycleID, program.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	cycleAgain, err := database.CreateAgentActionRun(ctx, cycleID, program.ID, now.Add(time.Second))
	if err != nil || cycleAgain.ID != cycle.ID || cycleAgain.CreatedAt != cycle.CreatedAt {
		t.Fatalf("idempotent action run creation changed the snapshot: run=%+v err=%v", cycleAgain, err)
	}
	if err := database.RecordAgentActionPlannerCall(ctx, program.ID, cycle.ID, "test-provider", "test-model", []string{"memory-id-1"}, now); err != nil {
		t.Fatal(err)
	}
	if err := database.RecordAgentActionPlannerCall(ctx, program.ID, cycle.ID, "test-provider", "test-model", nil, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	cycle, err = database.GetAgentActionRun(ctx, program.ID, cycle.ID)
	if err != nil || cycle.PlannerCalls != 2 || cycle.MemoryItemsSent != 1 || len(cycle.MemoryIDsSent) != 1 ||
		cycle.MemoryIDsSent[0] != "memory-id-1" || cycle.PlannerProvider != "test-provider" {
		t.Fatalf("planner egress was not auditable: run=%+v err=%v", cycle, err)
	}

	input := ledgerReservationInput(cycle, policy.Revision, uuid.NewString(), 1, 2, now.Add(time.Minute))
	var forged ledgerGrantJSON
	if err := json.Unmarshal(input.ProposalJSON, &forged); err != nil {
		t.Fatal(err)
	}
	forged.Targets = []string{"outside.test"}
	input.ProposalJSON, err = json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.ReserveAgentAction(ctx, input, now); err == nil || !strings.Contains(err.Error(), "current program scope") {
		t.Fatalf("out-of-scope serialized grant was reserved: %v", err)
	}
	input = ledgerReservationInput(cycle, policy.Revision, input.ID, 1, 2, now.Add(time.Minute))
	first, created, err := database.ReserveAgentAction(ctx, input, now)
	if err != nil || !created || first.Status != "reserved" {
		t.Fatalf("reserve first action: reservation=%+v created=%t err=%v", first, created, err)
	}
	duplicate, created, err := database.ReserveAgentAction(ctx, input, now.Add(time.Second))
	if err != nil || created || duplicate.ID != first.ID {
		t.Fatalf("idempotent reservation was charged twice: reservation=%+v created=%t err=%v", duplicate, created, err)
	}

	second := ledgerReservationInput(cycle, policy.Revision, uuid.NewString(), 2, 2, now.Add(time.Minute))
	if _, _, err := database.ReserveAgentAction(ctx, second, now); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("request budget overrun was accepted: %v", err)
	}
	second.RequestBudget = 1
	second.ProposalJSON = ledgerGrantJSONBytes(t, cycle, policy.Revision, 1, second.GrantValidUntil)
	reservedSecond, created, err := database.ReserveAgentAction(ctx, second, now)
	if err != nil || !created {
		t.Fatalf("reserve remaining request budget: action=%+v created=%t err=%v", reservedSecond, created, err)
	}
	third := ledgerReservationInput(cycle, policy.Revision, uuid.NewString(), 3, 1, now.Add(time.Minute))
	if _, _, err := database.ReserveAgentAction(ctx, third, now); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("action count budget overrun was accepted: %v", err)
	}

	stored, err := database.GetAgentActionRun(ctx, program.ID, cycle.ID)
	if err != nil || stored.ActionsReserved != 2 || stored.RequestsReserved != 3 {
		t.Fatalf("ledger counters are wrong: run=%+v err=%v", stored, err)
	}
	if _, err := database.GetAgentActionRun(ctx, "another-program", cycle.ID); err == nil {
		t.Fatal("action run retrieval crossed program boundary")
	}
	listedRuns, err := database.ListAgentActionRuns(ctx, program.ID, 10)
	if err != nil || len(listedRuns) != 1 || listedRuns[0].ID != cycle.ID {
		t.Fatalf("program-scoped action run listing failed: runs=%+v err=%v", listedRuns, err)
	}
	if _, err := database.ListAgentActionRuns(ctx, "", 10); err == nil {
		t.Fatal("action run listing without program id unexpectedly succeeded")
	}

	started, err := database.StartAgentAction(ctx, program.ID, cycle.ID, first.ID, time.Minute, now.Add(2*time.Second))
	if err != nil || started.Status != "running" || started.LeaseUntil == nil {
		t.Fatalf("just-in-time action start failed: action=%+v err=%v", started, err)
	}
	if _, err := database.StartAgentAction(ctx, program.ID, cycle.ID, first.ID, time.Minute, now.Add(3*time.Second)); err == nil || !strings.Contains(err.Error(), "cannot be started or replayed") {
		t.Fatalf("running action was replayed: %v", err)
	}
	if err := database.ConsumeAgentActionRequest(ctx, program.ID, cycle.ID, first.ID, now.Add(3*time.Second)); err != nil {
		t.Fatalf("first actual request unit was not consumed: %v", err)
	}
	if err := database.ConsumeAgentActionRequest(ctx, program.ID, cycle.ID, first.ID, now.Add(3*time.Second)); err != nil {
		t.Fatalf("second actual request unit was not consumed: %v", err)
	}
	if err := database.ConsumeAgentActionRequest(ctx, program.ID, cycle.ID, first.ID, now.Add(3*time.Second)); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("actual request budget overrun was accepted: %v", err)
	}
	if err := database.FinishAgentAction(ctx, program.ID, cycle.ID, first.ID, "completed", now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.CancelReservedAgentAction(ctx, program.ID, cycle.ID, reservedSecond.ID, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.CloseAgentActionRun(ctx, program.ID, cycle.ID, "completed", now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	reservations, err := database.ListAgentActionReservations(ctx, program.ID, cycle.ID)
	if err != nil || len(reservations) != 2 {
		t.Fatalf("action reservations are not auditable: actions=%+v err=%v", reservations, err)
	}
	if reservations[0].RequestsConsumed != 2 {
		t.Fatalf("per-action request consumption was not persisted: %+v", reservations)
	}
	stored, err = database.GetAgentActionRun(ctx, program.ID, cycle.ID)
	if err != nil || stored.RequestsConsumed != 2 {
		t.Fatalf("per-run request consumption was not persisted: run=%+v err=%v", stored, err)
	}
}

func TestAgentActionLedgerFailClosedOnPolicyDriftAndExpiredLease(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.October, 23, 0, 0, 0, 0, time.UTC)
	program := createLedgerProgram(t, database, start, "Ledger program two")
	policy, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageOSINT}, AllowedClasses: []contract.ActionClass{contract.ActionPassive},
		MaxActionsPerRun: 2, MaxRequestsPerRun: 10, MaxRequestsPerAction: 5, MaxTargetsPerAction: 3,
	}, start.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now := start.Add(2 * time.Second)
	cycle, err := database.CreateAgentActionRun(ctx, uuid.NewString(), program.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	input := ledgerReservationInput(cycle, policy.Revision, uuid.NewString(), 1, 2, now.Add(time.Minute))
	reserved, created, err := database.ReserveAgentAction(ctx, input, now)
	if err != nil || !created {
		t.Fatalf("reserve action before policy drift: created=%t err=%v", created, err)
	}
	updatedPolicy, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.StartAgentAction(ctx, program.ID, cycle.ID, reserved.ID, time.Minute, now.Add(2*time.Second)); err == nil {
		t.Fatal("action started after policy revision changed")
	}
	if err := database.CancelReservedAgentAction(ctx, program.ID, cycle.ID, reserved.ID, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.CloseAgentActionRun(ctx, program.ID, cycle.ID, "cancelled", now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if updatedPolicy.Revision == policy.Revision {
		t.Fatal("policy reset did not advance its revision")
	}

	// A separate cycle demonstrates that an expired lease is uncertain, not retried.
	policy, err = database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageOSINT}, AllowedClasses: []contract.ActionClass{contract.ActionPassive},
		MaxActionsPerRun: 1, MaxRequestsPerRun: 5, MaxRequestsPerAction: 5, MaxTargetsPerAction: 3,
	}, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	secondCycle, err := database.CreateAgentActionRun(ctx, uuid.NewString(), program.ID, now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	secondInput := ledgerReservationInput(secondCycle, policy.Revision, uuid.NewString(), 1, 1, now.Add(time.Minute))
	uncertain, _, err := database.ReserveAgentAction(ctx, secondInput, now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.StartAgentAction(ctx, program.ID, secondCycle.ID, uncertain.ID, 10*time.Second, now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	recovered, err := database.RecoverExpiredAgentActions(ctx, now.Add(18*time.Second))
	if err != nil || recovered != 1 {
		t.Fatalf("expired action lease recovery: recovered=%d err=%v", recovered, err)
	}
	items, err := database.ListAgentActionReservations(ctx, program.ID, secondCycle.ID)
	if err != nil || len(items) != 1 || items[0].Status != "uncertain" {
		t.Fatalf("expired running action was not marked uncertain: actions=%+v err=%v", items, err)
	}
	storedRun, err := database.GetAgentActionRun(ctx, program.ID, secondCycle.ID)
	if err != nil || storedRun.Status != "needs_review" || storedRun.RequestsReserved != 1 {
		t.Fatalf("uncertain action did not fail closed with budget consumed: run=%+v err=%v", storedRun, err)
	}
	if err := database.CloseAgentActionRun(ctx, program.ID, secondCycle.ID, "failed", now.Add(19*time.Second)); err == nil {
		t.Fatal("uncertain action run was closed without review")
	}
	if err := database.ResolveUncertainAgentAction(ctx, program.ID, secondCycle.ID, uncertain.ID,
		"assessed_not_executed", "test-operator", "Reviewed local executor state; no request was recorded in the target logs.", now.Add(20*time.Second)); err != nil {
		t.Fatalf("record explicit uncertain-action review: %v", err)
	}
	items, err = database.ListAgentActionReservations(ctx, program.ID, secondCycle.ID)
	if err != nil || len(items) != 1 || items[0].Status != "uncertain" || items[0].ReviewDecision != "assessed_not_executed" ||
		items[0].ReviewedBy != "test-operator" || items[0].ReviewedAt == nil {
		t.Fatalf("operator review did not preserve uncertainty and audit fields: actions=%+v err=%v", items, err)
	}
	storedRun, err = database.GetAgentActionRun(ctx, program.ID, secondCycle.ID)
	if err != nil || storedRun.Status != "failed" || storedRun.RequestsReserved != 1 {
		t.Fatalf("reviewed uncertain run did not close without refunding its budget: run=%+v err=%v", storedRun, err)
	}
	if err := database.ResolveUncertainAgentAction(ctx, program.ID, secondCycle.ID, uncertain.ID,
		"assessed_completed", "test-operator", "Attempt second review.", now.Add(21*time.Second)); err == nil {
		t.Fatal("uncertain action was reviewed twice")
	}
}

func TestAgentActionLedgerConcurrentReservationsCannotOverspend(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.October, 24, 0, 0, 0, 0, time.UTC)
	program := createLedgerProgram(t, database, start, "Concurrent ledger program")
	policy, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageOSINT}, AllowedClasses: []contract.ActionClass{contract.ActionPassive},
		MaxActionsPerRun: 1, MaxRequestsPerRun: 1, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, start.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now := start.Add(2 * time.Second)
	run, err := database.CreateAgentActionRun(ctx, uuid.NewString(), program.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 8
	var wait sync.WaitGroup
	var successes int
	var successID string
	var unexpected []error
	var resultMu sync.Mutex
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			input := ledgerReservationInput(run, policy.Revision, uuid.NewString(), 1, 1, now.Add(time.Minute))
			_, created, err := database.ReserveAgentAction(ctx, input, now)
			resultMu.Lock()
			defer resultMu.Unlock()
			if err == nil && created {
				successes++
				successID = input.ID
				return
			}
			if err == nil || !strings.Contains(err.Error(), "budget") {
				unexpected = append(unexpected, err)
			}
		}()
	}
	wait.Wait()
	if successes != 1 || len(unexpected) != 0 {
		t.Fatalf("concurrent ledger reservations overspent or failed unexpectedly: successes=%d errors=%v", successes, unexpected)
	}
	if _, err := database.StartAgentAction(ctx, program.ID, run.ID, successID, time.Minute, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var consumed int
	var consumeErrors []error
	wait = sync.WaitGroup{}
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			err := database.ConsumeAgentActionRequest(ctx, program.ID, run.ID, successID, now.Add(2*time.Second))
			resultMu.Lock()
			defer resultMu.Unlock()
			if err == nil {
				consumed++
				return
			}
			if !strings.Contains(err.Error(), "budget") {
				consumeErrors = append(consumeErrors, err)
			}
		}()
	}
	wait.Wait()
	if consumed != 1 || len(consumeErrors) != 0 {
		t.Fatalf("concurrent actual request accounting overspent or failed unexpectedly: consumed=%d errors=%v", consumed, consumeErrors)
	}
	stored, err := database.GetAgentActionRun(ctx, program.ID, run.ID)
	if err != nil || stored.ActionsReserved != 1 || stored.RequestsReserved != 1 || stored.RequestsConsumed != 1 {
		t.Fatalf("atomic run budget counters exceeded their caps: run=%+v err=%v", stored, err)
	}
	reservations, err := database.ListAgentActionReservations(ctx, program.ID, run.ID)
	if err != nil || len(reservations) != 1 || reservations[0].RequestsConsumed != 1 {
		t.Fatalf("atomic per-action request counters exceeded their caps: reservations=%+v err=%v", reservations, err)
	}
}

func ledgerReservationInput(run AgentActionRun, revision int64, id string, sequence, requests int, validUntil time.Time) ReserveAgentActionParams {
	return ReserveAgentActionParams{
		ID: id, ActionRunID: run.ID, ProgramID: run.ProgramID, Sequence: sequence,
		Stage: recon.StageOSINT, ActionClass: contract.ActionPassive,
		ProposalJSON: ledgerGrantJSONBytes(nil, run, revision, requests, validUntil),
		ScopeHash:    run.ScopeHash, PolicyRevision: revision, RequestBudget: requests, TargetCount: 1,
		Limits: recon.DefaultStageLimits(recon.StageOSINT), GrantValidUntil: validUntil,
	}
}

func createLedgerProgram(t *testing.T, database *Store, now time.Time, name string) assessment.Program {
	t.Helper()
	ctx := context.Background()
	program, err := database.CreateProgram(ctx, CreateProgramParams{
		Name: name, AuthorizationReference: "internal:agent-action-ledger-test",
		ExpiresAt: now.Add(24 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "example.com"}}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageOSINT, "* * * * *", "UTC", true, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, now); err != nil {
		t.Fatal(err)
	}
	return program
}

func ledgerGrantJSONBytes(t *testing.T, run AgentActionRun, revision int64, requests int, validUntil time.Time) []byte {
	if t != nil {
		t.Helper()
	}
	grant := ledgerGrantJSON{
		ProgramID: run.ProgramID, ScopeHash: run.ScopeHash, PolicyRevision: revision,
		Stage: recon.StageOSINT, Class: contract.ActionPassive, Targets: []string{"example.com"},
		RequestBudget: requests, Limits: recon.DefaultStageLimits(recon.StageOSINT), ValidUntil: validUntil,
	}
	grant.Proposal.Stage = recon.StageOSINT
	grant.Proposal.ScopeHash = run.ScopeHash
	grant.Proposal.EstimatedCalls = requests
	encoded, err := json.Marshal(grant)
	if err != nil && t != nil {
		t.Fatal(err)
	}
	return encoded
}
