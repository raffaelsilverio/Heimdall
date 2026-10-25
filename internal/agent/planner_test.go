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
