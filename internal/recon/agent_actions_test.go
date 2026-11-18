package recon

import (
	"context"
	"strings"
	"testing"
)

type countingAgentAdapter struct {
	spec  AgentToolSpec
	calls int
}

func (adapter *countingAgentAdapter) Spec() AgentToolSpec { return adapter.spec }

func (adapter *countingAgentAdapter) Execute(context.Context, StageRequest) (Collection, error) {
	adapter.calls++
	return Collection{Tools: []ToolResult{{ID: adapter.spec.ID, Status: "complete"}}}, nil
}

func validAgentToolSpec() AgentToolSpec {
	return NativeHTTPProbe{}.Spec()
}

func TestDefaultAgentRegistryExposesReviewedNativeProbe(t *testing.T) {
	registry := NewDefaultAgentActionRegistry()
	specs := registry.Specs()
	if len(specs) != 1 {
		t.Fatalf("default agent registry contains %d tools, want 1: %+v", len(specs), specs)
	}
	spec := specs[0]
	if spec.ID != AgentHTTPProbeID || spec.Version != agentHTTPProbeVersion ||
		spec.Stage != StageWeb || spec.Class != AgentToolClassSafeActive ||
		spec.Origin != AgentToolOriginCompiled || !spec.AutonomousEligible() {
		t.Fatalf("native probe identity or autonomy metadata is incomplete: %+v", spec)
	}
	if spec.Accounting != AgentToolAccountingOnePerTarget ||
		spec.MaxTargets != AgentHTTPProbeMaxTargets || spec.MaxRequests != AgentHTTPProbeMaxTargets {
		t.Fatalf("native probe accounting metadata is incomplete: %+v", spec)
	}
	if len(spec.TargetTypes) != 1 || spec.TargetTypes[0] != AgentToolTargetHTTPURL ||
		spec.ScopeRule != AgentToolScopeProgramActiveURL {
		t.Fatalf("native probe target/scope metadata is incomplete: %+v", spec)
	}
	if len(spec.Arguments) != 1 || spec.Arguments[0].Name != "targets" ||
		spec.Arguments[0].Type != ToolArgumentStringList || !spec.Arguments[0].Required {
		t.Fatalf("native probe argument schema is incomplete: %+v", spec.Arguments)
	}
	lookedUp, err := registry.Lookup(AgentHTTPProbeID)
	if err != nil || lookedUp.ID != spec.ID || len(lookedUp.Arguments) != 1 {
		t.Fatalf("Lookup returned %+v, %v; want the registered native probe", lookedUp, err)
	}
	if _, err := registry.Lookup("unregistered_probe"); err == nil || !strings.Contains(err.Error(), "not in the compiled registry") {
		t.Fatalf("Lookup error = %v, want an unregistered-tool rejection", err)
	}
}

func TestAgentToolSpecAutonomousEligibility(t *testing.T) {
	spec := validAgentToolSpec()
	if !spec.AutonomousEligible() {
		t.Fatalf("reviewed native probe is not autonomy-eligible: %+v", spec)
	}
	spec.Origin = "mcp"
	if spec.AutonomousEligible() {
		t.Fatal("an MCP-origin spec must not be autonomy-eligible")
	}
	spec = validAgentToolSpec()
	spec.MaxRequests = spec.MaxTargets - 1
	if spec.AutonomousEligible() {
		t.Fatal("a spec whose max requests cannot cover every target must not be autonomy-eligible")
	}
}

func TestAgentRegistrySortsReviewedCatalog(t *testing.T) {
	first := validAgentToolSpec()
	first.ID = "b_probe"
	second := validAgentToolSpec()
	second.ID = "a_probe"
	registry, err := NewAgentActionRegistry(&countingAgentAdapter{spec: first}, &countingAgentAdapter{spec: second})
	if err != nil {
		t.Fatal(err)
	}
	specs := registry.Specs()
	if len(specs) != 2 || specs[0].ID != "a_probe" || specs[1].ID != "b_probe" {
		t.Fatalf("catalog is not sorted by id: %+v", specs)
	}
}

func TestAgentRegistryRejectsInvalidMetadata(t *testing.T) {
	mutate := func(change func(*AgentToolSpec)) AgentToolSpec {
		spec := validAgentToolSpec()
		change(&spec)
		return spec
	}
	tests := []struct {
		name    string
		adapter AgentActionAdapter
		want    string
	}{
		{name: "nil adapter", want: "nil adapter"},
		{name: "empty id", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.ID = "" })}, want: "non-empty"},
		{name: "whitespace id", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.ID = " probe " })}, want: "non-empty"},
		{name: "empty version", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Version = "" })}, want: "version"},
		{name: "invalid version", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Version = "Native HTTP" })}, want: "version"},
		{name: "unsupported stage", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Stage = StageOSINT })}, want: "unsupported stage"},
		{name: "unsupported class", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Class = "sensitive" })}, want: "unsupported action class"},
		{name: "unsupported origin", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Origin = "mcp" })}, want: "unsupported origin"},
		{name: "missing description", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Description = " " })}, want: "description"},
		{name: "no target types", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.TargetTypes = nil })}, want: "target types"},
		{name: "unsupported target type", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.TargetTypes = []string{"dns_hostname"} })}, want: "unsupported target type"},
		{name: "duplicate target type", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) {
			spec.TargetTypes = []string{AgentToolTargetHTTPURL, AgentToolTargetHTTPURL}
		})}, want: "more than once"},
		{name: "unsupported scope rule", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.ScopeRule = "program_scope" })}, want: "unsupported scope rule"},
		{name: "zero max targets", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.MaxTargets = 0 })}, want: "max targets"},
		{name: "excessive max targets", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.MaxTargets = maxAgentToolTargets + 1 })}, want: "max targets"},
		{name: "max requests below targets", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.MaxRequests = spec.MaxTargets - 1 })}, want: "max requests"},
		{name: "excessive max requests", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.MaxRequests = maxAgentToolTargets + 1 })}, want: "max requests"},
		{name: "unsupported accounting", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Accounting = "unlimited" })}, want: "unsupported accounting"},
		{name: "no arguments", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Arguments = nil })}, want: "arguments"},
		{name: "missing targets argument", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) {
			spec.Arguments = []ToolArgument{{Name: "targets", Type: ToolArgumentStringList, Required: true, MaxItems: 1, MaxLength: 8}}
			spec.Arguments[0].Name = "urls"
		})}, want: "unsupported argument"},
		{name: "optional targets", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Arguments[0].Required = false })}, want: "must be required"},
		{name: "wrong argument type", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Arguments[0].Type = "string" })}, want: "unsupported type"},
		{name: "max items above tool cap", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Arguments[0].MaxItems = spec.MaxTargets + 1 })}, want: "max items"},
		{name: "zero max length", adapter: &countingAgentAdapter{spec: mutate(func(spec *AgentToolSpec) { spec.Arguments[0].MaxLength = 0 })}, want: "max length"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.adapter == nil {
				_, err = NewAgentActionRegistry(nil)
			} else {
				_, err = NewAgentActionRegistry(test.adapter)
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewAgentActionRegistry error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAgentRegistryRejectsDuplicateIDs(t *testing.T) {
	first := validAgentToolSpec()
	second := validAgentToolSpec()
	if _, err := NewAgentActionRegistry(
		&countingAgentAdapter{spec: first}, &countingAgentAdapter{spec: second},
	); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate registration error = %v, want a duplicate-id rejection", err)
	}
}

func TestAgentRegistryValidatesRequestBeforeAdapterRuns(t *testing.T) {
	spec := validAgentToolSpec()
	spec.MaxTargets = 2
	spec.MaxRequests = 2
	spec.Arguments[0].MaxItems = 2
	spec.Arguments[0].MaxLength = 16
	adapter := &countingAgentAdapter{spec: spec}
	registry, err := NewAgentActionRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	valid := StageRequest{Stage: StageWeb, Targets: []string{"https://a.test"}, RequestBudget: 1}
	if _, err := registry.Execute(context.Background(), spec.ID, valid); err != nil {
		t.Fatalf("valid request was rejected: %v", err)
	}
	if adapter.calls != 1 {
		t.Fatalf("adapter called %d times, want 1", adapter.calls)
	}

	tests := []struct {
		name    string
		request StageRequest
		want    string
	}{
		{name: "wrong stage", request: StageRequest{Stage: StageOSINT, Targets: []string{"a"}, RequestBudget: 1}, want: "requires stage"},
		{name: "no targets", request: StageRequest{Stage: StageWeb, RequestBudget: 1}, want: "at least one target"},
		{name: "too many targets", request: StageRequest{Stage: StageWeb, Targets: []string{"a", "b", "c"}, RequestBudget: 3}, want: "at most 2 targets"},
		{name: "short budget", request: StageRequest{Stage: StageWeb, Targets: []string{"a"}, RequestBudget: 0}, want: "request budget"},
		{name: "blank target", request: StageRequest{Stage: StageWeb, Targets: []string{" "}, RequestBudget: 1}, want: "non-empty"},
		{name: "long target", request: StageRequest{Stage: StageWeb, Targets: []string{strings.Repeat("a", 17)}, RequestBudget: 1}, want: "exceeds 16 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := registry.Execute(context.Background(), spec.ID, test.request); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Execute error = %v, want %q", err, test.want)
			}
			if adapter.calls != 1 {
				t.Fatalf("invalid request reached the adapter: calls=%d", adapter.calls)
			}
		})
	}
}

func TestAgentRegistryRejectsUnknownToolBeforeExecution(t *testing.T) {
	adapter := &countingAgentAdapter{spec: validAgentToolSpec()}
	registry, err := NewAgentActionRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Execute(context.Background(), "unknown_probe", StageRequest{Stage: StageWeb, Targets: []string{"https://a.test"}, RequestBudget: 1})
	if err == nil || !strings.Contains(err.Error(), "not in the compiled registry") {
		t.Fatalf("Execute error = %v, want an unregistered-tool rejection", err)
	}
	if adapter.calls != 0 {
		t.Fatalf("unregistered tool reached an adapter: calls=%d", adapter.calls)
	}
}
