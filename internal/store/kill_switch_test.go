package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func TestKillSwitchStateIsAuditableAndIdempotent(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.November, 24, 9, 0, 0, 0, time.UTC)

	state, err := database.GetKillSwitch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Engaged || state.Revision != 1 || state.Reason != "" || state.ChangedBy != "" || !state.ChangedAt.IsZero() {
		t.Fatalf("kill switch did not start released: %+v", state)
	}
	if _, err := database.SetKillSwitch(ctx, true, "", "operator halt", now); err == nil {
		t.Fatal("engaging without an operator was accepted")
	}
	if _, err := database.SetKillSwitch(ctx, true, "ops", "line\nbreak", now); err == nil {
		t.Fatal("engaging with a non-printable reason was accepted")
	}
	if _, err := database.SetKillSwitch(ctx, true, "ops", strings.Repeat("x", MaxKillSwitchReasonBytes+1), now); err == nil {
		t.Fatal("engaging with an oversized reason was accepted")
	}

	engaged, err := database.SetKillSwitch(ctx, true, "ops-oncall", "unexpected egress from the daemon", now)
	if err != nil {
		t.Fatal(err)
	}
	if !engaged.Engaged || engaged.Reason != "unexpected egress from the daemon" || engaged.ChangedBy != "ops-oncall" ||
		engaged.Revision != 2 || !engaged.ChangedAt.Equal(now) {
		t.Fatalf("engage transition is not auditable: %+v", engaged)
	}
	repeated, err := database.SetKillSwitch(ctx, true, "ops-oncall", "second engagement", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Revision != engaged.Revision || repeated.Reason != engaged.Reason {
		t.Fatalf("repeating the current state created a new revision: %+v", repeated)
	}
	stored, err := database.GetKillSwitch(ctx)
	if err != nil || stored != engaged {
		t.Fatalf("engaged state was not persisted: state=%+v err=%v", stored, err)
	}

	released, err := database.SetKillSwitch(ctx, false, "ops-oncall", "root cause reviewed", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if released.Engaged || released.Revision != 3 || released.ChangedBy != "ops-oncall" {
		t.Fatalf("release transition is not auditable: %+v", released)
	}
	if _, err := database.SetKillSwitch(ctx, false, "", "no operator", now); err == nil {
		t.Fatal("releasing without an operator was accepted")
	}
}

func TestKillSwitchBlocksAgentExecutionAndScheduling(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.November, 24, 10, 0, 0, 0, time.UTC)
	program := createLedgerProgram(t, database, start, "Kill switch program")
	policy, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageOSINT}, AllowedClasses: []contract.ActionClass{contract.ActionPassive},
		MaxActionsPerRun: 2, MaxRequestsPerRun: 3, MaxRequestsPerAction: 2, MaxTargetsPerAction: 3,
	}, start.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now := start.Add(2 * time.Second)
	run, err := database.CreateAgentActionRun(ctx, uuid.NewString(), program.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	reservation, created, err := database.ReserveAgentAction(ctx, ledgerReservationInput(run, policy.Revision, uuid.NewString(), 1, 1, now.Add(time.Minute)), now)
	if err != nil || !created {
		t.Fatalf("pre-engagement reservation failed: reservation=%+v created=%t err=%v", reservation, created, err)
	}
	if _, err := database.SetKillSwitch(ctx, true, "ops-oncall", "halt all execution", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err := database.CreateAgentActionRun(ctx, uuid.NewString(), program.ID, now); !errors.Is(err, ErrKillSwitchEngaged) {
		t.Fatalf("new action run was allowed while engaged: %v", err)
	}
	second := ledgerReservationInput(run, policy.Revision, uuid.NewString(), 2, 1, now.Add(time.Minute))
	if _, _, err := database.ReserveAgentAction(ctx, second, now); !errors.Is(err, ErrKillSwitchEngaged) {
		t.Fatalf("reservation was allowed while engaged: %v", err)
	}
	if _, err := database.StartAgentAction(ctx, program.ID, run.ID, reservation.ID, time.Minute, now); !errors.Is(err, ErrKillSwitchEngaged) {
		t.Fatalf("reserved action started while engaged: %v", err)
	}
	if err := database.ConsumeAgentActionRequest(ctx, program.ID, run.ID, reservation.ID, now); !errors.Is(err, ErrKillSwitchEngaged) {
		t.Fatalf("request accounting was allowed while engaged: %v", err)
	}
	if jobs, err := database.ClaimDueSchedules(ctx, now, time.Hour); err != nil || len(jobs) != 0 {
		t.Fatalf("scheduled recon was claimed while engaged: jobs=%+v err=%v", jobs, err)
	}
	if leases, err := database.ClaimAgentCycleJobs(ctx, now, time.Minute, 1); err != nil || len(leases) != 0 {
		t.Fatalf("adaptive cycle was claimed while engaged: leases=%+v err=%v", leases, err)
	}

	if _, err := database.SetKillSwitch(ctx, false, "ops-oncall", "halt lifted", now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	started, err := database.StartAgentAction(ctx, program.ID, run.ID, reservation.ID, time.Minute, now.Add(5*time.Second))
	if err != nil || started.Status != "running" {
		t.Fatalf("action did not resume after release: action=%+v err=%v", started, err)
	}
	if err := database.ConsumeAgentActionRequest(ctx, program.ID, run.ID, reservation.ID, now.Add(6*time.Second)); err != nil {
		t.Fatalf("request accounting did not resume after release: %v", err)
	}
}
