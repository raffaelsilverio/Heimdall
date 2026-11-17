package recon

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

const AgentHTTPProbeID = "native_http_probe"

type AgentActionAdapter interface {
	Spec() AgentToolSpec
	Execute(context.Context, StageRequest) (Collection, error)
}

// AgentActionRegistry exposes only compiled, explicitly registered adapters.
// Its default registry contains a single native HTTP probe; it has no shell or
// arbitrary-command execution surface.
type AgentActionRegistry struct {
	Adapters []AgentActionAdapter
}

// NewAgentActionRegistry validates a caller-supplied compiled adapter list.
// Empty, duplicate, or schema-invalid specs are rejected before any execution.
func NewAgentActionRegistry(adapters ...AgentActionAdapter) (AgentActionRegistry, error) {
	registry := AgentActionRegistry{Adapters: append([]AgentActionAdapter(nil), adapters...)}
	if err := registry.validate(); err != nil {
		return AgentActionRegistry{}, err
	}
	return registry, nil
}

func NewDefaultAgentActionRegistry() AgentActionRegistry {
	registry, err := NewAgentActionRegistry(NativeHTTPProbe{})
	if err != nil {
		panic(fmt.Sprintf("invalid compiled agent action registry: %v", err))
	}
	return registry
}

func (r AgentActionRegistry) validate() error {
	seen := make(map[string]bool, len(r.Adapters))
	for _, adapter := range r.Adapters {
		if adapter == nil {
			return errors.New("agent action registry contains a nil adapter")
		}
		spec := adapter.Spec()
		if err := spec.Validate(); err != nil {
			return err
		}
		if seen[spec.ID] {
			return fmt.Errorf("agent action %q is registered more than once", spec.ID)
		}
		seen[spec.ID] = true
	}
	return nil
}

// Specs returns the reviewed catalog sorted by id for stable output.
func (r AgentActionRegistry) Specs() []AgentToolSpec {
	result := make([]AgentToolSpec, 0, len(r.Adapters))
	for _, adapter := range r.Adapters {
		if adapter != nil {
			result = append(result, adapter.Spec())
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// Lookup returns one reviewed tool spec without executing anything.
func (r AgentActionRegistry) Lookup(actionID string) (AgentToolSpec, error) {
	adapter, err := r.adapter(actionID)
	if err != nil {
		return AgentToolSpec{}, err
	}
	return adapter.Spec(), nil
}

func (r AgentActionRegistry) adapter(actionID string) (AgentActionAdapter, error) {
	if actionID == "" {
		return nil, errors.New("registered agent action id is required")
	}
	for _, adapter := range r.Adapters {
		if adapter == nil {
			continue
		}
		if adapter.Spec().ID == actionID {
			return adapter, nil
		}
	}
	return nil, fmt.Errorf("agent action %q is not in the compiled registry", actionID)
}

// Execute validates the request against the registered schema before the
// adapter runs. It is the only agent execution entry point.
func (r AgentActionRegistry) Execute(ctx context.Context, actionID string, request StageRequest) (Collection, error) {
	adapter, err := r.adapter(actionID)
	if err != nil {
		return Collection{}, err
	}
	spec := adapter.Spec()
	if err := spec.ValidateRequest(request); err != nil {
		return Collection{}, err
	}
	return adapter.Execute(ctx, request)
}
