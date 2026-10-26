package store

import (
	"context"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func TestProgramAgentAutomationConsentIsExplicitRevisionedAndRevocable(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.October, 26, 0, 0, 0, 0, time.UTC)
	program, err := database.CreateProgram(ctx, CreateProgramParams{
		Name: "Automation consent program", AuthorizationReference: "internal:automation-consent",
		ExpiresAt: now.Add(60 * 24 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "auto.example.test", Ports: []uint16{443},
		}}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defaultConsent, err := database.GetProgramAgentAutomation(ctx, program.ID)
	if err != nil || defaultConsent.Enabled || defaultConsent.AllowModelContextEgress || defaultConsent.AllowActiveRequests {
		t.Fatalf("new program automation was not deny-by-default: consent=%+v err=%v", defaultConsent, err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", true, now); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 2, MaxRequestsPerRun: 10, MaxRequestsPerAction: 5, MaxTargetsPerAction: 4,
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(30 * 24 * time.Hour)
	input := ProgramAgentAutomation{
		Enabled: true, PlannerProvider: "openai", PlannerModel: "bounded-model",
		ContextEgressExpiresAt: &expires, AllowModelContextEgress: true, AllowActiveRequests: true,
		IncludeMemory: true, MaxCyclesPerDay: 2, MaxRequestsPerDay: 100, MaxStepsPerCycle: 2,
		ReviewedBy: "operator-a", ReviewReason: "Enable bounded native HEAD checks for this program",
	}
	saved, err := database.SetProgramAgentAutomation(ctx, program.ID, input, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Enabled || saved.Revision != 2 || saved.PlannerProvider != "openai" || saved.MaxCyclesPerDay != 2 || !saved.IncludeMemory {
		t.Fatalf("saved automation consent is unexpected: %+v", saved)
	}
	unchanged, err := database.SetProgramAgentAutomation(ctx, program.ID, input, now.Add(3*time.Second))
	if err != nil || unchanged.Revision != saved.Revision {
		t.Fatalf("identical automation consent should not create a revision: consent=%+v err=%v", unchanged, err)
	}
	if _, err := database.GetProgramAgentAutomation(ctx, "another-program"); err == nil {
		t.Fatal("automation consent was readable without a matching program")
	}

	disabled, err := database.DisableProgramAgentAutomation(ctx, program.ID, "operator-b", "Program owner revoked consent", now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled || disabled.Revision != saved.Revision+1 || disabled.ReviewedBy != "operator-b" || disabled.PlannerProvider != "openai" {
		t.Fatalf("automation revocation lost its audit history: %+v", disabled)
	}
}

func TestProgramAgentAutomationRequiresCurrentAuthorizationPolicyAndBoundedConsent(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.October, 26, 0, 0, 0, 0, time.UTC)
	program, err := database.CreateProgram(ctx, CreateProgramParams{
		Name: "Automation invalid consent program", AuthorizationReference: "internal:automation-invalid",
		ExpiresAt: now.Add(30 * 24 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "auto.example.test", Ports: []uint16{443}}}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", true, now); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, now); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(7 * 24 * time.Hour)
	input := ProgramAgentAutomation{
		Enabled: true, PlannerProvider: "openai", PlannerModel: "model", ContextEgressExpiresAt: &expires,
		AllowModelContextEgress: true, AllowActiveRequests: true, MaxCyclesPerDay: 1, MaxRequestsPerDay: 10, MaxStepsPerCycle: 1,
		ReviewedBy: "operator", ReviewReason: "test",
	}
	if _, err := database.SetProgramAgentAutomation(ctx, program.ID, input, now.Add(time.Second)); err == nil {
		t.Fatal("automation consent was accepted with the deny-all agent policy")
	}
	if _, err := database.SetProgramAgentPolicy(ctx, program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 1, MaxRequestsPerRun: 5, MaxRequestsPerAction: 5, MaxTargetsPerAction: 1,
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	tooLong := now.Add(91 * 24 * time.Hour)
	input.ContextEgressExpiresAt = &tooLong
	if _, err := database.SetProgramAgentAutomation(ctx, program.ID, input, now.Add(2*time.Second)); err == nil {
		t.Fatal("automation consent longer than 90 days was accepted")
	}
	input.ContextEgressExpiresAt = &expires
	input.MaxStepsPerCycle = 2
	if _, err := database.SetProgramAgentAutomation(ctx, program.ID, input, now.Add(2*time.Second)); err == nil {
		t.Fatal("automation step cap exceeded the program action budget")
	}
}
