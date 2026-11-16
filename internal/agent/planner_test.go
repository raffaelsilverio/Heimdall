package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/providers"
)

type fakePlanModel struct {
	response providers.Response
	request  providers.Request
	calls    int
}

func (m *fakePlanModel) Name() string { return "fake" }

func (m *fakePlanModel) Generate(_ context.Context, request providers.Request) (providers.Response, error) {
	m.calls++
	m.request = request
	return m.response, nil
}

func TestGenerateActionProposalsUsesBoundedContextAndStrictJSON(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	scope := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "app.example.test", Ports: []uint16{443},
	}}}
	scopeHash, err := assessment.ScopeFingerprint(scope)
	if err != nil {
		t.Fatal(err)
	}
	contextData := ActionPolicyContext{
		Program: assessment.Program{ID: "program-a", Name: "A", Status: assessment.ProgramActive,
			ExpiresAt: now.Add(time.Hour), Scope: scope, ScopeHash: scopeHash},
		EnabledSchedules: map[string]recon.StageLimits{recon.StageWeb: recon.DefaultStageLimits(recon.StageWeb)},
		Policy: ProgramAgentPolicy{
			Revision: 1, AllowedStages: []string{recon.StageWeb}, AllowedClasses: []ActionClass{ActionSafeActive},
			MaxActionsPerRun: 2, MaxRequestsPerRun: 20, MaxRequestsPerAction: 10, MaxTargetsPerAction: 5,
		},
	}
	model := &fakePlanModel{response: providers.Response{Content: `{"actions":[{"stage":"web","scope_hash":"` + scopeHash + `","targets":["https://app.example.test/login"],"estimated_calls":2,"rationale":"Check the scoped login route"}]}`}}
	memory := []PlanMemoryItem{{Kind: "fact", Title: "Login route", Content: "The login route redirected to /home.", SourceKind: "run", Confidence: 0.9}}
	proposals, err := GenerateActionProposals(context.Background(), model, "test-model", contextData, memory, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(proposals) != 1 || proposals[0].Stage != recon.StageWeb || proposals[0].EstimatedCalls != 2 {
		t.Fatalf("unexpected proposals: %+v", proposals)
	}
	if model.calls != 1 || len(model.request.Messages) != 2 || !strings.Contains(model.request.Messages[0].Content, "cannot execute tools") {
		t.Fatalf("planner prompt did not enforce proposal-only behavior: %+v", model.request)
	}
	if !strings.Contains(model.request.Messages[1].Content, scopeHash) ||
		!strings.Contains(model.request.Messages[1].Content, "The login route redirected") ||
		!strings.Contains(model.request.Messages[1].Content, `"source_kind":"run"`) ||
		strings.Contains(model.request.Messages[1].Content, "authorization-ref") {
		t.Fatalf("planner context omitted scope identity or included unrelated authorization data: %s", model.request.Messages[1].Content)
	}

	if _, err := GenerateActionProposals(context.Background(), model, "test-model", contextData, nil, now); err != nil {
		t.Fatalf("proposal generation without memory failed: %v", err)
	}
	if strings.Contains(model.request.Messages[1].Content, `"memory"`) {
		t.Fatalf("memory was included without an explicit memory context: %s", model.request.Messages[1].Content)
	}

	model.response.Content = `{"actions":[],"unexpected":true}`
	if _, err := GenerateActionProposals(context.Background(), model, "test-model", contextData, nil, now); err == nil {
		t.Fatal("planner accepted unknown JSON fields")
	}
	if model.calls != 3 {
		t.Fatalf("model called %d times, want one per proposal request", model.calls)
	}
}

func TestGenerateActionProposalsFailsClosedBeforeModelCall(t *testing.T) {
	now := time.Now().UTC()
	model := &fakePlanModel{response: providers.Response{Content: `{"actions":[]}`}}
	contextData := ActionPolicyContext{
		Program:             assessment.Program{ID: "program-a", Status: assessment.ProgramActive, ExpiresAt: now.Add(time.Hour)},
		Policy:              ProgramAgentPolicy{},
		SourceReviewPending: true,
	}
	if _, err := GenerateActionProposals(context.Background(), model, "test-model", contextData, nil, now); err == nil {
		t.Fatal("proposal generation succeeded during a pending source review")
	}
	if model.calls != 0 {
		t.Fatalf("model was called %d times despite policy preflight rejection", model.calls)
	}
}

func TestGenerateNextProposalReceivesOnlyBoundedPriorResultAndRemainingBudgets(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	policyContext.MaxProposals = 1
	policyContext.RecentResults = []PlanActionObservation{{
		Stage: recon.StageWeb, Target: "https://app.example.test/health", Outcome: "HEAD status=204",
	}}
	model := &fakePlanModel{response: providers.Response{Content: `{"actions":[{"stage":"web","scope_hash":"` +
		policyContext.Program.ScopeHash + `","targets":["https://app.example.test/next"],"estimated_calls":1}]}`}}
	proposals, err := GenerateActionProposals(context.Background(), model, "test-model", policyContext, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(proposals) != 1 {
		t.Fatalf("expected one next proposal, got %+v", proposals)
	}
	userContext := model.request.Messages[1].Content
	for _, expected := range []string{"recent_results", "HEAD status=204", "/health", `"actions_remaining":3`, `"requests_remaining":17`, `"max_actions_this_response":1`} {
		if !strings.Contains(userContext, expected) {
			t.Fatalf("adaptive prompt omitted %q: %s", expected, userContext)
		}
	}
}

func TestGeneratePlanOrdersTasksAndRecordsSummaries(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	policyContext.MaxProposals = 3
	hash := policyContext.Program.ScopeHash
	model := &fakePlanModel{response: providers.Response{Content: `{"tasks":[` +
		`{"id":"probe","objective":"Probe the login route","depends_on":["discover"],"actions":[{"stage":"web","scope_hash":"` + hash + `","targets":["https://app.example.test/login"],"estimated_calls":1}]},` +
		`{"id":"discover","objective":"Discover the login route","actions":[{"stage":"web","scope_hash":"` + hash + `","targets":["https://app.example.test/"],"estimated_calls":1}]}` +
		`]}`}}
	draft, err := GeneratePlan(context.Background(), model, "test-model", policyContext, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(draft.Actions) != 2 || draft.Actions[0].TaskID != "discover" || draft.Actions[1].TaskID != "probe" {
		t.Fatalf("task actions were not flattened in dependency order: %+v", draft.Actions)
	}
	if len(draft.Tasks) != 2 || draft.Tasks[0].ID != "discover" || draft.Tasks[1].DependsOn[0] != "discover" {
		t.Fatalf("task summaries were not recorded: %+v", draft.Tasks)
	}
	validation, err := (PolicyAwarePlanner{Policy: ScopeActionPolicy{}}).ValidatePlan(context.Background(), policyContext, draft, now)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.PolicyChecksPassed || len(validation.Tasks) != 2 || len(validation.Decisions) != 2 {
		t.Fatalf("task plan was not policy-checked as a graph: %+v", validation)
	}
	if validation.Decisions[0].Proposal.TaskID != "discover" {
		t.Fatalf("first policy decision was not the dependency: %+v", validation.Decisions[0])
	}
}

func TestGeneratePlanRejectsAmbiguousTaskEnvelopes(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "both arrays", content: `{"actions":[],"tasks":[]}`, want: "either actions or tasks"},
		{name: "no arrays", content: `{}`, want: "missing the actions or tasks array"},
		{name: "unknown field", content: `{"tasks":[{"id":"t1","objective":"x","actions":[{"stage":"web"}],"unknown":true}]}`, want: "unknown field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			model := &fakePlanModel{response: providers.Response{Content: test.content}}
			_, err := GeneratePlan(context.Background(), model, "test-model", policyContext, nil, now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("GeneratePlan error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPolicyAwarePlannerFiltersGeneratedProposalsWithoutExecuting(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	model := &fakePlanModel{response: providers.Response{Content: `{"actions":[{"stage":"web","scope_hash":"` +
		policyContext.Program.ScopeHash + `","targets":["https://outside.example.test/"],"estimated_calls":1}]}`}}
	result, err := (PolicyAwarePlanner{Policy: ScopeActionPolicy{}}).Propose(context.Background(), model, "test-model", policyContext, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyChecksPassed || result.ExecutionAvailable || result.Executed || len(result.Decisions) != 1 || result.Decisions[0].AuthorizedCandidate != nil {
		t.Fatalf("model proposal was not safely gated: %+v", result)
	}
	if model.calls != 1 {
		t.Fatalf("model called %d times, want one proposal call", model.calls)
	}
}
