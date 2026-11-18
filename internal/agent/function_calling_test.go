package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/providers"
)

func TestPlanToolDefinitionsUsesReviewedSchema(t *testing.T) {
	registry := recon.NewDefaultAgentActionRegistry()
	definitions, err := planToolDefinitions(&registry, []planGenerationStage{{Name: recon.StageWeb, Class: ActionSafeActive}})
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 1 || definitions[0].Name != recon.AgentHTTPProbeID {
		t.Fatalf("unexpected tool definitions: %+v", definitions)
	}
	property, declared := definitions[0].Parameters.Properties["targets"]
	if !declared || property.Type != "array" || property.MaxItems != 1000 ||
		property.Items == nil || property.Items.Type != "string" || property.Items.MaxLength != 2048 {
		t.Fatalf("reviewed schema was not translated: %+v", definitions[0].Parameters)
	}
	if len(definitions[0].Parameters.Required) != 1 || definitions[0].Parameters.Required[0] != "targets" {
		t.Fatalf("required arguments were not preserved: %+v", definitions[0].Parameters.Required)
	}
}

func TestGeneratePlanConvertsNativeToolCalls(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	policyContext.MaxProposals = 2
	model := &fakePlanModel{response: providers.Response{ToolCalls: []providers.ToolCall{{
		ID: "call_1", Name: recon.AgentHTTPProbeID,
		Arguments: `{"targets":["https://app.example.test/login"]}`,
	}}}}
	draft, err := GeneratePlan(context.Background(), model, "test-model", policyContext, nil, now,
		WithToolRegistry(recon.NewDefaultAgentActionRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if draft.ToolCalls != 1 || len(draft.Actions) != 1 {
		t.Fatalf("unexpected draft: %+v", draft)
	}
	action := draft.Actions[0]
	if action.Stage != recon.StageWeb || action.ScopeHash != policyContext.Program.ScopeHash ||
		action.EstimatedCalls != 1 || len(action.Targets) != 1 ||
		action.Targets[0] != "https://app.example.test/login" || action.Rationale != "model tool call native_http_probe" {
		t.Fatalf("unexpected native action: %+v", action)
	}
	if len(model.request.Tools) != 1 || model.request.Tools[0].Name != recon.AgentHTTPProbeID {
		t.Fatalf("native tools were not advertised: %+v", model.request.Tools)
	}
	if !strings.Contains(model.request.Messages[0].Content, "Native function calling is enabled") {
		t.Fatalf("tool prompt was not added: %s", model.request.Messages[0].Content)
	}

	validation, err := (PolicyAwarePlanner{Policy: ScopeActionPolicy{}}).ValidatePlan(
		context.Background(), policyContext, draft, now)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.PolicyChecksPassed || validation.ToolCalls != 1 {
		t.Fatalf("native plan did not pass policy or lost its audit count: %+v", validation)
	}
}

func TestGeneratePlanFallsBackToTextWithoutToolCalls(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	model := &fakePlanModel{response: providers.Response{Content: `{"actions":[{"stage":"web","scope_hash":"` +
		policyContext.Program.ScopeHash + `","targets":["https://app.example.test/login"],"estimated_calls":1}]}`}}
	draft, err := GeneratePlan(context.Background(), model, "test-model", policyContext, nil, now,
		WithToolRegistry(recon.NewDefaultAgentActionRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if draft.ToolCalls != 0 || len(draft.Actions) != 1 || draft.Actions[0].Rationale != "" {
		t.Fatalf("text fallback was not preserved: %+v", draft)
	}
	if len(model.request.Tools) != 1 {
		t.Fatalf("tools were not advertised for the text fallback: %+v", model.request.Tools)
	}
}

func TestGeneratePlanRejectsUnusableNativeToolCalls(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		call    providers.ToolCall
		options []PlanOption
		want    string
	}{
		{
			name: "unregistered tool",
			call: providers.ToolCall{ID: "call_1", Name: "shell", Arguments: `{"targets":["https://app.example.test/"]}`},
			want: "unregistered tool",
		},
		{
			name: "unknown argument",
			call: providers.ToolCall{ID: "call_1", Name: recon.AgentHTTPProbeID, Arguments: `{"urls":["https://app.example.test/"]}`},
			want: "arguments",
		},
		{
			name: "empty targets",
			call: providers.ToolCall{ID: "call_1", Name: recon.AgentHTTPProbeID, Arguments: `{"targets":[]}`},
			want: "at least one target",
		},
		{
			name: "oversized target",
			call: providers.ToolCall{ID: "call_1", Name: recon.AgentHTTPProbeID,
				Arguments: `{"targets":["https://app.example.test/` + strings.Repeat("a", 2048) + `"]}`},
			want: "exceeds 2048 bytes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policyContext := activePolicyContext(t, now)
			model := &fakePlanModel{response: providers.Response{ToolCalls: []providers.ToolCall{test.call}}}
			options := test.options
			if options == nil {
				options = []PlanOption{WithToolRegistry(recon.NewDefaultAgentActionRegistry())}
			}
			_, err := GeneratePlan(context.Background(), model, "test-model", policyContext, nil, now, options...)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("GeneratePlan error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGeneratePlanRejectsToolCallsWithoutAdvertisedRegistry(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	model := &fakePlanModel{response: providers.Response{ToolCalls: []providers.ToolCall{{
		ID: "call_1", Name: recon.AgentHTTPProbeID, Arguments: `{"targets":["https://app.example.test/"]}`,
	}}}}
	if _, err := GeneratePlan(context.Background(), model, "test-model", policyContext, nil, now); err == nil ||
		!strings.Contains(err.Error(), "without an advertised tool registry") {
		t.Fatalf("GeneratePlan error = %v, want a no-registry rejection", err)
	}
}

func TestGeneratePlanRejectsToolCallsAboveTheResponseLimit(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	policyContext.MaxProposals = 1
	model := &fakePlanModel{response: providers.Response{ToolCalls: []providers.ToolCall{
		{ID: "call_1", Name: recon.AgentHTTPProbeID, Arguments: `{"targets":["https://app.example.test/"]}`},
		{ID: "call_2", Name: recon.AgentHTTPProbeID, Arguments: `{"targets":["https://app.example.test/login"]}`},
	}}}
	_, err := GeneratePlan(context.Background(), model, "test-model", policyContext, nil, now,
		WithToolRegistry(recon.NewDefaultAgentActionRegistry()))
	if err == nil || !strings.Contains(err.Error(), "remaining response limit") {
		t.Fatalf("GeneratePlan error = %v, want a response-limit rejection", err)
	}
}

func TestGeneratePlanRejectsToolRegistryOutsideThePolicy(t *testing.T) {
	now := time.Date(2026, time.October, 25, 0, 0, 0, 0, time.UTC)
	policyContext := activePolicyContext(t, now)
	policyContext.Policy.AllowedStages = []string{recon.StageDNS}
	policyContext.EnabledSchedules = map[string]recon.StageLimits{
		recon.StageDNS: recon.DefaultStageLimits(recon.StageDNS),
	}
	model := &fakePlanModel{response: providers.Response{Content: `{"actions":[]}`}}
	_, err := GeneratePlan(context.Background(), model, "test-model", policyContext, nil, now,
		WithToolRegistry(recon.NewDefaultAgentActionRegistry()))
	if err == nil || !strings.Contains(err.Error(), "no compiled agent tool matches") {
		t.Fatalf("GeneratePlan error = %v, want a policy/tool mismatch rejection", err)
	}
	if model.calls != 0 {
		t.Fatalf("model was called %d times despite an empty matching tool catalogue", model.calls)
	}
}
