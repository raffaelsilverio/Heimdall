package store

import (
	"context"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func TestProgramAgentPolicyDefaultsDenyAndIsRevisionedPerProgram(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	programA := createMemoryTestProgram(t, database, "Policy Program A", now)
	programB := createMemoryTestProgram(t, database, "Policy Program B", now)

	defaultPolicy, err := database.GetProgramAgentPolicy(ctx, programA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if defaultPolicy.Revision != 1 || len(defaultPolicy.AllowedStages) != 0 || len(defaultPolicy.AllowedClasses) != 0 {
		t.Fatalf("new program policy is not deny-all: %+v", defaultPolicy)
	}

	input := contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 3, MaxRequestsPerRun: 100, MaxRequestsPerAction: 25, MaxTargetsPerAction: 10,
	}
	saved, err := database.SetProgramAgentPolicy(ctx, programA.ID, input, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 2 || len(saved.AllowedStages) != 1 || saved.AllowedStages[0] != recon.StageWeb {
		t.Fatalf("saved program policy is unexpected: %+v", saved)
	}
	unchanged, err := database.SetProgramAgentPolicy(ctx, programA.ID, input, now.Add(2*time.Minute))
	if err != nil || unchanged.Revision != 2 {
		t.Fatalf("identical policy update should not create a revision: policy=%+v err=%v", unchanged, err)
	}
	other, err := database.GetProgramAgentPolicy(ctx, programB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if other.Revision != 1 || len(other.AllowedStages) != 0 {
		t.Fatalf("program A policy leaked into B: %+v", other)
	}

	invalid := input
	invalid.AllowedStages = []string{recon.StageFFUF}
	if _, err := database.SetProgramAgentPolicy(ctx, programA.ID, invalid, now.Add(3*time.Minute)); err == nil {
		t.Fatal("stage/action-class mismatch unexpectedly persisted")
	}
	reset, err := database.SetProgramAgentPolicy(ctx, programA.ID, contract.ProgramAgentPolicy{}, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if reset.Revision != 3 || len(reset.AllowedStages) != 0 || reset.MaxActionsPerRun != 0 {
		t.Fatalf("reset did not restore deny-all: %+v", reset)
	}
}
