package cmd

import (
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func planToolGrant(tool string, targets []string, budget int) *agent.AuthorizedAction {
	return &agent.AuthorizedAction{
		Stage: recon.StageWeb, Class: agent.ActionSafeActive, Targets: targets, RequestBudget: budget,
		Proposal: agent.ActionProposal{Stage: recon.StageWeb, Tool: tool, Targets: targets},
	}
}

func TestValidatePlanToolsRejectsGrantsOutsideTheRegistrySchema(t *testing.T) {
	registry := recon.NewDefaultAgentActionRegistry()
	urls := []string{"https://app.example.test/one", "https://app.example.test/two"}
	tests := []struct {
		name   string
		grant  *agent.AuthorizedAction
		want   string
		accept bool
	}{
		{name: "default http", grant: planToolGrant("", urls, 2), accept: true},
		{name: "tls probe", grant: planToolGrant(recon.AgentTLSProbeID, urls, 2), accept: true},
		{name: "unregistered", grant: planToolGrant("unregistered_probe", urls, 2), want: "not in the compiled registry"},
		{name: "too many targets", grant: planToolGrant(recon.AgentTLSProbeID, make([]string, 9), 9), want: "at most 8 targets"},
		{name: "missing budget", grant: planToolGrant(recon.AgentTLSProbeID, urls, 1), want: "must cover every target"},
		{name: "target too long", grant: planToolGrant(recon.AgentTLSProbeID, []string{"https://app.example.test/" + strings.Repeat("a", 2048)}, 1), want: "exceeds 2048 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := agent.PlanValidation{
				PolicyChecksPassed: true,
				Decisions:          []agent.PlanDecision{{PolicyPassed: true, AuthorizedCandidate: test.grant}},
			}
			validatePlanTools(registry, &result)
			if test.accept {
				if !result.PolicyChecksPassed || result.Decisions[0].AuthorizedCandidate == nil {
					t.Fatalf("valid grant was rejected: %+v", result)
				}
				return
			}
			if result.PolicyChecksPassed || result.Decisions[0].AuthorizedCandidate != nil {
				t.Fatalf("invalid grant was exposed as executable: %+v", result)
			}
			if result.Decisions[0].PolicyPassed || !strings.Contains(result.Decisions[0].Reason, test.want) {
				t.Fatalf("decision = %+v, want reason containing %q", result.Decisions[0], test.want)
			}
		})
	}
}
