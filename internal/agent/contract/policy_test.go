package contract

import (
	"reflect"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestActionClassForStage(t *testing.T) {
	tests := []struct {
		stage string
		class ActionClass
		ok    bool
	}{
		{stage: " OSINT ", class: ActionPassive, ok: true},
		{stage: "web", class: ActionSafeActive, ok: true},
		{stage: "nuclei", class: ActionSensitive, ok: true},
		{stage: "unknown", ok: false},
	}
	for _, test := range tests {
		t.Run(test.stage, func(t *testing.T) {
			class, ok := ActionClassForStage(test.stage)
			if class != test.class || ok != test.ok {
				t.Fatalf("ActionClassForStage(%q) = (%q, %t), want (%q, %t)", test.stage, class, ok, test.class, test.ok)
			}
		})
	}
}

func TestAuthorizeTargetsUsesProgramScopeAndCanonicalizes(t *testing.T) {
	scope := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude,
		Type:   assessment.ScopeDomain,
		Value:  "api.example.test",
		Ports:  []uint16{443},
	}}}

	t.Run("OSINT seeds come from scope", func(t *testing.T) {
		got, err := AuthorizeTargets(scope, "osint", nil, 5)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, []string{"api.example.test"}) {
			t.Fatalf("OSINT targets = %v, want scope-derived hostname", got)
		}
		if _, err := AuthorizeTargets(scope, "osint", []string{"attacker.example"}, 5); err == nil {
			t.Fatal("accepted an agent-supplied OSINT seed")
		}
	})

	t.Run("DNS targets are scoped, normalized, and deduplicated", func(t *testing.T) {
		got, err := AuthorizeTargets(scope, "dns", []string{"API.EXAMPLE.TEST", "api.example.test"}, 5)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, []string{"api.example.test"}) {
			t.Fatalf("DNS targets = %v, want one canonical target", got)
		}
		if _, err := AuthorizeTargets(scope, "dns", []string{"outside.example.test"}, 5); err == nil {
			t.Fatal("accepted an out-of-scope DNS target")
		}
	})

	t.Run("Nmap targets require an authorized port", func(t *testing.T) {
		got, err := AuthorizeTargets(scope, "nmap", []string{"API.EXAMPLE.TEST:443"}, 5)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, []string{"api.example.test:443"}) {
			t.Fatalf("Nmap targets = %v, want canonical host and port", got)
		}
		if _, err := AuthorizeTargets(scope, "nmap", []string{"api.example.test:444"}, 5); err == nil {
			t.Fatal("accepted an unauthorized Nmap port")
		}
	})
}

func TestNormalizeProgramAgentPolicyCanonicalizesAndRejectsClassMismatch(t *testing.T) {
	policy, err := NormalizeProgramAgentPolicy(ProgramAgentPolicy{
		AllowedStages:        []string{" WEB ", "web"},
		AllowedClasses:       []ActionClass{ActionSafeActive, ActionSafeActive},
		MaxActionsPerRun:     2,
		MaxRequestsPerRun:    10,
		MaxRequestsPerAction: 2,
		MaxTargetsPerAction:  5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(policy.AllowedStages, []string{"web"}) ||
		!reflect.DeepEqual(policy.AllowedClasses, []ActionClass{ActionSafeActive}) {
		t.Fatalf("policy was not canonicalized: %+v", policy)
	}
	policy.AllowedClasses = []ActionClass{ActionPassive}
	if _, err := NormalizeProgramAgentPolicy(policy); err == nil {
		t.Fatal("accepted a stage whose required action class is not allowed")
	}
}
