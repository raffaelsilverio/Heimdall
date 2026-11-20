package execution

import (
	"fmt"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

// ResolveActionToolID returns the reviewed adapter named by a grant. The policy
// normalizes empty tool ids to the native HTTP probe, but the fallback keeps
// persisted grants written before the tool field existed executable.
func ResolveActionToolID(grant agent.AuthorizedAction) string {
	if grant.Proposal.Tool != "" {
		return grant.Proposal.Tool
	}
	return recon.AgentHTTPProbeID
}

// ValidateGrant checks an authorized grant against the reviewed catalog entry
// named by its proposal. It verifies stage, class, target count, target length
// and the one-request-per-target budget without making any request.
func ValidateGrant(registry recon.AgentActionRegistry, grant agent.AuthorizedAction) (recon.AgentToolSpec, error) {
	spec, err := registry.Lookup(ResolveActionToolID(grant))
	if err != nil {
		return recon.AgentToolSpec{}, err
	}
	if grant.Stage != spec.Stage {
		return recon.AgentToolSpec{}, fmt.Errorf("agent action %q requires stage %q", spec.ID, spec.Stage)
	}
	if string(grant.Class) != spec.Class {
		return recon.AgentToolSpec{}, fmt.Errorf("agent action %q requires class %q", spec.ID, spec.Class)
	}
	if len(grant.Targets) > spec.MaxTargets {
		return recon.AgentToolSpec{}, fmt.Errorf("agent action %q accepts at most %d targets", spec.ID, spec.MaxTargets)
	}
	if grant.RequestBudget < len(grant.Targets) {
		return recon.AgentToolSpec{}, fmt.Errorf("agent action %q request budget must cover every target", spec.ID)
	}
	maxLength := spec.TargetMaxLength()
	for _, target := range grant.Targets {
		if len(target) > maxLength {
			return recon.AgentToolSpec{}, fmt.Errorf("agent action %q target exceeds %d bytes", spec.ID, maxLength)
		}
	}
	return spec, nil
}
