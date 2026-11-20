package recon

import (
	"fmt"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

// validateNativeProbeEnvelope applies the checks shared by every native probe:
// stage, durable meter, live program authorization, current scope, valid
// limits, bounded targets and a request budget covering every target. Each
// probe supplies its display name, budget wording and target validator.
func validateNativeProbeEnvelope(request StageRequest, name, budgetDetail string, validateTargets func(assessment.Scope, []string) ([]string, error)) ([]string, error) {
	if request.Stage != StageWeb {
		return nil, fmt.Errorf("%s only supports the %q stage", name, StageWeb)
	}
	if request.RequestMeter == nil {
		return nil, fmt.Errorf("%s requires a durable request meter", name)
	}
	if request.Program.ID == "" || request.Program.Status != assessment.ProgramActive || !request.Program.ExpiresAt.After(time.Now().UTC()) {
		return nil, fmt.Errorf("%s requires an active program with current authorization", name)
	}
	fingerprint, err := assessment.ScopeFingerprint(request.Program.Scope)
	if err != nil || fingerprint != request.Program.ScopeHash {
		return nil, fmt.Errorf("%s received an invalid or stale scope", name)
	}
	limits := request.Limits
	if err := limits.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s limits: %w", name, err)
	}
	if len(request.Targets) == 0 || len(request.Targets) > limits.MaxTargets {
		return nil, fmt.Errorf("%s targets are empty or exceed the configured target limit", name)
	}
	targets, err := validateTargets(request.Program.Scope, request.Targets)
	if err != nil {
		return nil, err
	}
	if request.RequestBudget < len(targets) {
		return nil, fmt.Errorf("%s request budget must cover %s", name, budgetDetail)
	}
	return targets, nil
}
