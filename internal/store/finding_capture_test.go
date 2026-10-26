package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func TestCompleteNucleiRunCapturesOnlyUnverifiedFindingCandidates(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.October, 26, 0, 0, 0, 0, time.UTC)
	program, err := database.CreateProgram(ctx, CreateProgramParams{
		Name: "Finding candidate capture", AuthorizationReference: "internal:finding-capture",
		ExpiresAt: start.Add(48 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeWildcardDomain, Value: "findings.example.test"}}},
	}, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageOSINT, "0 3 * * *", "UTC", false, start); err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageNuclei, "* * * * *", "UTC", true, start.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, start); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimDueSchedules(ctx, start, time.Hour)
	if err != nil || len(jobs) != 1 || jobs[0].Stage != recon.StageNuclei {
		t.Fatalf("claim Nuclei fixture run: jobs=%+v err=%v", jobs, err)
	}
	observation := recon.Observation{
		Category: recon.CategoryVulnFinding, StableKey: "https://api.findings.example.test/path|template-x|matcher-a",
		Value:  `{"template_id":"template-x","severity":"medium","name":"Possible issue"}`,
		Source: "nuclei",
	}
	if _, err := database.CompleteRun(ctx, jobs[0].RunID, recon.Collection{Observations: []recon.Observation{observation}}, true, nil, start); err != nil {
		t.Fatal(err)
	}
	memories, err := database.ListProgramMemories(ctx, program.ID, 20, start.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var candidate ProgramMemory
	for _, memory := range memories {
		if memory.Kind == "finding_candidate" {
			candidate = memory
		}
		if memory.Kind == "finding_verified" {
			t.Fatalf("scanner output was automatically promoted to a verified finding: %+v", memory)
		}
	}
	if candidate.ID == "" || candidate.SourceKind != "run" || candidate.SourceID != jobs[0].RunID ||
		candidate.ScopeHash != program.ScopeHash || candidate.ExpiresAt == nil || !candidate.ExpiresAt.Equal(start.Add(30*24*time.Hour)) {
		t.Fatalf("candidate did not retain run/scope provenance and expiry: %+v", candidate)
	}
	var data struct {
		State     string `json:"state"`
		RunID     string `json:"run_id"`
		Notice    string `json:"notice"`
		ScopeHash string `json:"scope_hash"`
	}
	if err := json.Unmarshal([]byte(candidate.Content), &data); err != nil {
		t.Fatal(err)
	}
	if data.State != "candidate" || data.RunID != jobs[0].RunID || data.ScopeHash != program.ScopeHash ||
		data.Notice == "" || candidate.Confidence != 0.5 {
		t.Fatalf("candidate state was not clearly distinguished from validation: %+v memory=%+v", data, candidate)
	}

	partialJobs, err := database.ClaimDueSchedules(ctx, start.Add(time.Minute), time.Hour)
	if err != nil || len(partialJobs) != 1 {
		t.Fatalf("claim partial Nuclei fixture run: jobs=%+v err=%v", partialJobs, err)
	}
	if _, err := database.CompleteRun(ctx, partialJobs[0].RunID, recon.Collection{Observations: []recon.Observation{observation}}, false, nil, start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	memories, err = database.ListProgramMemories(ctx, program.ID, 20, start.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	candidates := 0
	for _, memory := range memories {
		if memory.Kind == "finding_candidate" {
			candidates++
		}
	}
	if candidates != 1 {
		t.Fatalf("partial run was captured as another candidate: %+v", memories)
	}
}
