package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/providers"
)

// PlanOptions holds the optional native function-calling configuration. The
// zero value keeps proposal generation text-only.
type PlanOptions struct {
	ToolRegistry *recon.AgentActionRegistry
}

// PlanOption mutates optional plan-generation settings.
type PlanOption func(*PlanOptions)

// WithToolRegistry advertises only the reviewed tools that match the current
// policy allowlist. Every returned call is revalidated against the same
// registry before it becomes an ActionProposal.
func WithToolRegistry(registry recon.AgentActionRegistry) PlanOption {
	return func(options *PlanOptions) { options.ToolRegistry = &registry }
}

func applyPlanOptions(options []PlanOption) PlanOptions {
	var applied PlanOptions
	for _, option := range options {
		if option != nil {
			option(&applied)
		}
	}
	return applied
}

// planToolDefinitions converts reviewed specs into provider definitions,
// filtered by the stages and classes that are usable under the current policy.
func planToolDefinitions(registry *recon.AgentActionRegistry, available []planGenerationStage) ([]providers.ToolDefinition, error) {
	if registry == nil {
		return nil, nil
	}
	allowed := make(map[string]ActionClass, len(available))
	for _, stage := range available {
		allowed[stage.Name] = stage.Class
	}
	definitions := make([]providers.ToolDefinition, 0, len(available))
	for _, spec := range registry.Specs() {
		class, ok := allowed[spec.Stage]
		if !ok || string(class) != spec.Class {
			continue
		}
		definition, err := toolDefinitionFromSpec(spec)
		if err != nil {
			return nil, err
		}
		definitions = append(definitions, definition)
	}
	if len(definitions) == 0 {
		return nil, errors.New("no compiled agent tool matches the current policy allowlist")
	}
	return definitions, nil
}

func toolDefinitionFromSpec(spec recon.AgentToolSpec) (providers.ToolDefinition, error) {
	properties := make(map[string]providers.ToolProperty, len(spec.Arguments))
	required := make([]string, 0, len(spec.Arguments))
	for _, argument := range spec.Arguments {
		property, err := toolPropertyFromArgument(spec.ID, argument)
		if err != nil {
			return providers.ToolDefinition{}, err
		}
		properties[argument.Name] = property
		if argument.Required {
			required = append(required, argument.Name)
		}
	}
	return providers.ToolDefinition{
		Name:        spec.ID,
		Description: spec.Description,
		Parameters: providers.ToolSchema{
			Type: "object", Properties: properties, Required: required,
		},
	}, nil
}

func toolPropertyFromArgument(toolID string, argument recon.ToolArgument) (providers.ToolProperty, error) {
	if argument.Type != recon.ToolArgumentStringList {
		return providers.ToolProperty{}, fmt.Errorf(
			"agent tool %q argument %q has unsupported type %q", toolID, argument.Name, argument.Type,
		)
	}
	return providers.ToolProperty{
		Type:     "array",
		Items:    &providers.ToolProperty{Type: "string", MaxLength: argument.MaxLength},
		MaxItems: argument.MaxItems,
	}, nil
}

type toolCallArguments struct {
	Targets []string `json:"targets"`
}

// decodeToolCallPlan turns native function calls into the same ActionProposal
// shape used by text plans. Tool calls always form a flat action list; ordered
// task graphs remain a text-mode feature.
func decodeToolCallPlan(calls []providers.ToolCall, registry recon.AgentActionRegistry, policyContext ActionPolicyContext, maxActions int) (PlanDraft, error) {
	if len(calls) > maxActions {
		return PlanDraft{}, fmt.Errorf(
			"model returned %d tool calls, above the remaining response limit of %d", len(calls), maxActions,
		)
	}
	actions := make([]ActionProposal, 0, len(calls))
	for _, call := range calls {
		proposal, err := actionFromToolCall(call, registry, policyContext)
		if err != nil {
			return PlanDraft{}, err
		}
		actions = append(actions, proposal)
	}
	return PlanDraft{Actions: actions, ToolCalls: len(calls)}, nil
}

func actionFromToolCall(call providers.ToolCall, registry recon.AgentActionRegistry, policyContext ActionPolicyContext) (ActionProposal, error) {
	spec, err := registry.Lookup(call.Name)
	if err != nil {
		return ActionProposal{}, fmt.Errorf("model requested an unregistered tool %q: %w", call.Name, err)
	}
	targets, err := decodeToolCallTargets(call)
	if err != nil {
		return ActionProposal{}, err
	}
	request := recon.StageRequest{Stage: spec.Stage, Targets: targets, RequestBudget: len(targets)}
	if err := spec.ValidateRequest(request); err != nil {
		return ActionProposal{}, fmt.Errorf("model tool call %q failed schema validation: %w", call.Name, err)
	}
	return ActionProposal{
		Stage: spec.Stage, ScopeHash: policyContext.Program.ScopeHash,
		Targets: targets, EstimatedCalls: len(targets),
		Rationale: fmt.Sprintf("model tool call %s", spec.ID),
	}, nil
}

func decodeToolCallTargets(call providers.ToolCall) ([]string, error) {
	decoder := json.NewDecoder(strings.NewReader(call.Arguments))
	decoder.DisallowUnknownFields()
	var arguments toolCallArguments
	if err := decoder.Decode(&arguments); err != nil {
		return nil, fmt.Errorf("model tool call %q arguments: %w", call.Name, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("model tool call %q must contain exactly one JSON object", call.Name)
	}
	if len(arguments.Targets) == 0 {
		return nil, fmt.Errorf("model tool call %q requires at least one target", call.Name)
	}
	return arguments.Targets, nil
}
