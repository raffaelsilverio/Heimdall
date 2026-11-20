package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func activePolicyContext(t *testing.T, now time.Time) ActionPolicyContext {
	t.Helper()
	scope := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeURL, Value: "https://app.example.test/",
	}}}
	scopeHash, err := assessment.ScopeFingerprint(scope)
	if err != nil {
		t.Fatal(err)
	}
	return ActionPolicyContext{
		Program: assessment.Program{
			ID: "program-a", Status: assessment.ProgramActive, ExpiresAt: now.Add(time.Hour),
			Scope: scope, ScopeHash: scopeHash,
		},
		EnabledSchedules: map[string]recon.StageLimits{recon.StageWeb: recon.DefaultStageLimits(recon.StageWeb)},
		Policy: ProgramAgentPolicy{
			Revision: 1, AllowedStages: []string{recon.StageWeb},
			AllowedClasses: []ActionClass{ActionSafeActive}, MaxActionsPerRun: 4,
			MaxRequestsPerRun: 20, MaxRequestsPerAction: 10, MaxTargetsPerAction: 5,
		},
		ActionsUsed: 1, RequestsUsed: 3,
	}
}

func TestScopeActionPolicyRequiresProgramScopedExplicitAllowlist(t *testing.T) {
	now := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	policy := ScopeActionPolicy{}
	input := activePolicyContext(t, now)
	input.Policy.AllowedStages = nil
	input.Policy.AllowedClasses = nil
	proposal := ActionProposal{
		Stage: recon.StageWeb, ScopeHash: input.Program.ScopeHash,
		Targets: []string{"https://app.example.test/login"}, EstimatedCalls: 4,
	}
	if _, err := policy.Authorize(context.Background(), input, proposal, now); err == nil {
		t.Fatal("default-empty agent policy unexpectedly authorized an action")
	}

	input.Policy.AllowedStages = []string{recon.StageWeb}
	input.Policy.AllowedClasses = []ActionClass{ActionSafeActive}
	grant, err := policy.Authorize(context.Background(), input, proposal, now)
	if err != nil {
		t.Fatalf("explicitly allowed in-scope action was denied: %v", err)
	}
	if grant.ProgramID != input.Program.ID || grant.ScopeHash != input.Program.ScopeHash || grant.RequestBudget != proposal.EstimatedCalls {
		t.Fatalf("authorization grant lost its program or budget binding: %+v", grant)
	}
	if err := policy.Revalidate(context.Background(), input, grant, now.Add(time.Second)); err != nil {
		t.Fatalf("unchanged policy rejected its grant: %v", err)
	}

	changedScope := input
	changedScope.Program.ScopeHash = strings.Repeat("b", 64)
	if err := policy.Revalidate(context.Background(), changedScope, grant, now.Add(time.Second)); err == nil {
		t.Fatal("scope change did not invalidate the prior grant")
	}
	if _, err := policy.Authorize(context.Background(), input, proposal, input.Program.ExpiresAt); err == nil {
		t.Fatal("expired authorization was accepted")
	}
	pending := input
	pending.SourceReviewPending = true
	if _, err := policy.Authorize(context.Background(), pending, proposal, now); err == nil {
		t.Fatal("pending source review did not block an action")
	}
	paused := input
	paused.Program.Status = assessment.ProgramPaused
	if _, err := policy.Authorize(context.Background(), paused, proposal, now); err == nil {
		t.Fatal("paused program was authorized")
	}
}

func TestScopeActionPolicyEnforcesScheduleTargetsAndBudgets(t *testing.T) {
	now := time.Date(2026, time.October, 2, 0, 0, 0, 0, time.UTC)
	policy := ScopeActionPolicy{}
	input := activePolicyContext(t, now)
	input.Policy.AllowedStages = []string{recon.StageWeb, recon.StageFFUF}
	input.Policy.AllowedClasses = []ActionClass{ActionSafeActive, ActionSensitive}
	input.EnabledSchedules = map[string]recon.StageLimits{recon.StageWeb: recon.DefaultStageLimits(recon.StageWeb)}
	proposal := ActionProposal{
		Stage: recon.StageWeb, ScopeHash: input.Program.ScopeHash,
		Targets: []string{"https://outside.example.test/"}, EstimatedCalls: 1,
	}
	if _, err := policy.Authorize(context.Background(), input, proposal, now); err == nil {
		t.Fatal("out-of-scope URL was authorized")
	}
	proposal.Targets = []string{"https://app.example.test/"}
	proposal.EstimatedCalls = input.Policy.MaxRequestsPerAction + 1
	if _, err := policy.Authorize(context.Background(), input, proposal, now); err == nil {
		t.Fatal("per-action request budget was exceeded without denial")
	}
	proposal.EstimatedCalls = 1
	input.RequestsUsed = input.Policy.MaxRequestsPerRun
	if _, err := policy.Authorize(context.Background(), input, proposal, now); err == nil {
		t.Fatal("per-run request budget was exceeded without denial")
	}
	input.RequestsUsed = 0
	input.EnabledSchedules = map[string]recon.StageLimits{recon.StageWeb: recon.DefaultStageLimits(recon.StageWeb)}
	proposal.Stage = recon.StageFFUF
	if _, err := policy.Authorize(context.Background(), input, proposal, now); err == nil {
		t.Fatal("sensitive stage without an enabled schedule was authorized")
	}
	input.EnabledSchedules = map[string]recon.StageLimits{recon.StageWeb: recon.DefaultStageLimits(recon.StageWeb)}
	proposal.Stage = recon.StageWeb
	proposal.ScopeHash = strings.Repeat("c", 64)
	if _, err := policy.Authorize(context.Background(), input, proposal, now); err == nil {
		t.Fatal("proposal with a stale scope hash was authorized")
	}
	proposal.ScopeHash = input.Program.ScopeHash
	proposal.Targets = []string{"https://app.example.test/?token=secret"}
	if _, err := policy.Authorize(context.Background(), input, proposal, now); err == nil {
		t.Fatal("query-bearing URL was accepted by the active action policy")
	}
}

func TestScopeActionPolicyRequiresExplicitNmapPort(t *testing.T) {
	now := time.Date(2026, time.October, 3, 0, 0, 0, 0, time.UTC)
	scope := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "host.example.test", Ports: []uint16{443},
	}}}
	scopeHash, err := assessment.ScopeFingerprint(scope)
	if err != nil {
		t.Fatal(err)
	}
	policyContext := ActionPolicyContext{
		Program: assessment.Program{ID: "program-port", Status: assessment.ProgramActive,
			ExpiresAt: now.Add(time.Hour), Scope: scope, ScopeHash: scopeHash},
		EnabledSchedules: map[string]recon.StageLimits{recon.StageNmap: recon.DefaultStageLimits(recon.StageNmap)},
		Policy: ProgramAgentPolicy{
			Revision: 1, AllowedStages: []string{recon.StageNmap},
			AllowedClasses: []ActionClass{ActionSafeActive}, MaxActionsPerRun: 1,
			MaxRequestsPerRun: 10, MaxRequestsPerAction: 10, MaxTargetsPerAction: 1,
		},
		ActionsUsed: 0, RequestsUsed: 0,
	}
	proposal := ActionProposal{Stage: recon.StageNmap, ScopeHash: scopeHash, Targets: []string{"host.example.test:443"}, EstimatedCalls: 1}
	if _, err := (ScopeActionPolicy{}).Authorize(context.Background(), policyContext, proposal, now); err != nil {
		t.Fatalf("explicitly authorized Nmap port was denied: %v", err)
	}
	proposal.Targets = []string{"host.example.test:8443"}
	if _, err := (ScopeActionPolicy{}).Authorize(context.Background(), policyContext, proposal, now); err == nil {
		t.Fatal("Nmap target with an unauthorized port was accepted")
	}
}

func TestScopeActionPolicyNormalizesTheToolIdentity(t *testing.T) {
	now := time.Date(2026, time.October, 3, 0, 0, 0, 0, time.UTC)
	policy := ScopeActionPolicy{}
	input := activePolicyContext(t, now)
	proposal := ActionProposal{
		Stage: recon.StageWeb, ScopeHash: input.Program.ScopeHash,
		Targets: []string{"https://app.example.test/login"}, EstimatedCalls: 1,
	}
	grant, err := policy.Authorize(context.Background(), input, proposal, now)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Proposal.Tool != recon.AgentHTTPProbeID {
		t.Fatalf("empty tool id = %q, want the native HTTP probe default", grant.Proposal.Tool)
	}

	proposal.Tool = recon.AgentTLSProbeID
	grant, err = policy.Authorize(context.Background(), input, proposal, now)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Proposal.Tool != recon.AgentTLSProbeID {
		t.Fatalf("explicit tool id = %q, want %q", grant.Proposal.Tool, recon.AgentTLSProbeID)
	}
	if err := policy.Revalidate(context.Background(), input, grant, now.Add(time.Second)); err != nil {
		t.Fatalf("revalidation rejected an unchanged TLS grant: %v", err)
	}

	for _, tool := range []string{"Native-TLS", "tls probe", "tls/probe", strings.Repeat("a", 65)} {
		proposal.Tool = tool
		if _, err := policy.Authorize(context.Background(), input, proposal, now); err == nil {
			t.Fatalf("invalid tool id %q was authorized", tool)
		}
	}
}
