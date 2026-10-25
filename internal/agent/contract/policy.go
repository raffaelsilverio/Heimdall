package contract

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type ActionClass string

const (
	ActionPassive    ActionClass = "passive"
	ActionSafeActive ActionClass = "safe_active"
	ActionSensitive  ActionClass = "sensitive"
)

// ProgramAgentPolicy is a trusted, versioned policy snapshot. Empty allowlists
// and zero budgets are the deny-all default.
type ProgramAgentPolicy struct {
	Revision             int64
	AllowedStages        []string
	AllowedClasses       []ActionClass
	MaxActionsPerRun     int
	MaxRequestsPerRun    int
	MaxRequestsPerAction int
	MaxTargetsPerAction  int
}

func ActionClassForStage(stage string) (ActionClass, bool) {
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case "osint":
		return ActionPassive, true
	case "dns", "web", "nmap", "crawl":
		return ActionSafeActive, true
	case "ffuf", "nuclei":
		return ActionSensitive, true
	default:
		return "", false
	}
}

func NormalizeProgramAgentPolicy(policy ProgramAgentPolicy) (ProgramAgentPolicy, error) {
	stages := make([]string, 0, len(policy.AllowedStages))
	seenStages := make(map[string]struct{}, len(policy.AllowedStages))
	for _, value := range policy.AllowedStages {
		stage := strings.ToLower(strings.TrimSpace(value))
		if _, ok := ActionClassForStage(stage); !ok {
			return ProgramAgentPolicy{}, fmt.Errorf("unsupported agent stage %q", value)
		}
		if _, exists := seenStages[stage]; !exists {
			seenStages[stage] = struct{}{}
			stages = append(stages, stage)
		}
	}
	sort.Strings(stages)

	classes := make([]ActionClass, 0, len(policy.AllowedClasses))
	seenClasses := make(map[ActionClass]struct{}, len(policy.AllowedClasses))
	for _, value := range policy.AllowedClasses {
		class := ActionClass(strings.ToLower(strings.TrimSpace(string(value))))
		switch class {
		case ActionPassive, ActionSafeActive, ActionSensitive:
		default:
			return ProgramAgentPolicy{}, fmt.Errorf("unsupported agent action class %q", value)
		}
		if _, exists := seenClasses[class]; !exists {
			seenClasses[class] = struct{}{}
			classes = append(classes, class)
		}
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })

	if len(stages) == 0 {
		if len(classes) != 0 || policy.MaxActionsPerRun != 0 || policy.MaxRequestsPerRun != 0 ||
			policy.MaxRequestsPerAction != 0 || policy.MaxTargetsPerAction != 0 {
			return ProgramAgentPolicy{}, errors.New("deny-all policy must have empty allowlists and zero budgets")
		}
		policy.AllowedStages = nil
		policy.AllowedClasses = nil
		return policy, nil
	}
	if len(classes) == 0 {
		return ProgramAgentPolicy{}, errors.New("enabled agent stages require at least one allowed action class")
	}
	for _, stage := range stages {
		class, _ := ActionClassForStage(stage)
		if _, allowed := seenClasses[class]; !allowed {
			return ProgramAgentPolicy{}, fmt.Errorf("stage %q requires action class %q in the allowlist", stage, class)
		}
	}
	if policy.MaxActionsPerRun < 1 || policy.MaxActionsPerRun > 1000 {
		return ProgramAgentPolicy{}, errors.New("max actions per run must be between 1 and 1000")
	}
	if policy.MaxRequestsPerRun < 1 || policy.MaxRequestsPerRun > 1_000_000 {
		return ProgramAgentPolicy{}, errors.New("max requests per run must be between 1 and 1000000")
	}
	if policy.MaxRequestsPerAction < 1 || policy.MaxRequestsPerAction > policy.MaxRequestsPerRun {
		return ProgramAgentPolicy{}, errors.New("max requests per action must be positive and no greater than the per-run budget")
	}
	if policy.MaxTargetsPerAction < 1 || policy.MaxTargetsPerAction > 50_000 {
		return ProgramAgentPolicy{}, errors.New("max targets per action must be between 1 and 50000")
	}
	policy.AllowedStages = stages
	policy.AllowedClasses = classes
	return policy, nil
}
