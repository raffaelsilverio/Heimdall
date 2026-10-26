package recon

import (
	"context"
	"errors"
	"fmt"
)

const AgentHTTPProbeID = "native_http_probe"

type AgentActionAdapter interface {
	Spec() ToolSpec
	Execute(context.Context, StageRequest) (Collection, error)
}

// AgentActionRegistry exposes only compiled, explicitly registered adapters.
// Its default registry contains a single native HTTP probe; it has no shell or
// arbitrary-command execution surface.
type AgentActionRegistry struct {
	Adapters []AgentActionAdapter
}

func NewDefaultAgentActionRegistry() AgentActionRegistry {
	return AgentActionRegistry{Adapters: []AgentActionAdapter{NativeHTTPProbe{}}}
}

func (r AgentActionRegistry) Specs() []ToolSpec {
	result := make([]ToolSpec, 0, len(r.Adapters))
	for _, adapter := range r.Adapters {
		if adapter != nil {
			result = append(result, adapter.Spec())
		}
	}
	return result
}

func (r AgentActionRegistry) Execute(ctx context.Context, actionID string, request StageRequest) (Collection, error) {
	if actionID == "" {
		return Collection{}, errors.New("registered agent action id is required")
	}
	for _, adapter := range r.Adapters {
		if adapter == nil {
			continue
		}
		spec := adapter.Spec()
		if spec.ID != actionID {
			continue
		}
		if request.Stage != spec.Stage {
			return Collection{}, fmt.Errorf("agent action %q requires stage %q", actionID, spec.Stage)
		}
		return adapter.Execute(ctx, request)
	}
	return Collection{}, fmt.Errorf("agent action %q is not in the compiled registry", actionID)
}
