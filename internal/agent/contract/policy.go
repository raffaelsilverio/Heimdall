package contract

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
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
	Revision                int64
	AllowedStages           []string
	AllowedClasses          []ActionClass
	ApprovalRequiredClasses []ActionClass
	MaxActionsPerRun        int
	MaxRequestsPerRun       int
	MaxRequestsPerAction    int
	MaxTargetsPerAction     int
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

// AuthorizeTargets normalizes and validates targets using only the program's
// current scope. OSINT seeds are always derived from scope, never model input.
func AuthorizeTargets(scope assessment.Scope, stage string, proposed []string, maximum int) ([]string, error) {
	stage = strings.ToLower(strings.TrimSpace(stage))
	if maximum < 1 {
		return nil, errors.New("target budget must be positive")
	}
	if stage == "osint" {
		if len(proposed) != 0 {
			return nil, errors.New("OSINT targets are derived from program scope; the agent cannot supply arbitrary seeds")
		}
		targets := make([]string, 0)
		for _, domain := range scope.DiscoveryDomains() {
			if scope.AllowsHost(domain) {
				targets = append(targets, domain)
			}
		}
		if len(targets) == 0 || len(targets) > maximum {
			return nil, errors.New("OSINT seeds are empty or exceed the program target budget")
		}
		return targets, nil
	}
	if len(proposed) == 0 || len(proposed) > maximum {
		return nil, errors.New("action targets are empty or exceed the program target budget")
	}
	set := make(map[string]struct{}, len(proposed))
	for _, raw := range proposed {
		target := strings.TrimSpace(raw)
		if target == "" {
			return nil, errors.New("action contains an empty target")
		}
		switch stage {
		case "dns":
			host, err := assessment.NormalizeHost(target)
			if err != nil || !scope.AllowsHost(host) {
				return nil, fmt.Errorf("DNS target %q is outside the program scope", target)
			}
			target = host
		case "web", "crawl", "ffuf", "nuclei":
			parsed, err := url.Parse(target)
			if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
				!scope.AllowsActiveURL(target) {
				return nil, fmt.Errorf("URL target %q is outside the program's active scope", target)
			}
		case "nmap":
			host, portText, err := net.SplitHostPort(target)
			if err != nil {
				return nil, fmt.Errorf("target %q for nmap must include an explicit authorized port", target)
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || port == 0 {
				return nil, fmt.Errorf("target %q for nmap has an invalid port", target)
			}
			host, err = assessment.NormalizeHost(host)
			if err != nil || !scope.AllowsActivePort(host, uint16(port)) {
				return nil, fmt.Errorf("target %q for nmap is outside the program's authorized ports", target)
			}
			target = net.JoinHostPort(host, strconv.FormatUint(port, 10))
		default:
			return nil, fmt.Errorf("stage %q has no target validator", stage)
		}
		set[target] = struct{}{}
	}
	if len(set) > maximum {
		return nil, errors.New("deduplicated action targets exceed the program target budget")
	}
	targets := make([]string, 0, len(set))
	for target := range set {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets, nil
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

	classes, err := normalizeActionClasses(policy.AllowedClasses)
	if err != nil {
		return ProgramAgentPolicy{}, err
	}
	seenClasses := make(map[ActionClass]struct{}, len(classes))
	for _, class := range classes {
		seenClasses[class] = struct{}{}
	}

	approvalClasses, err := normalizeApprovalRequiredClasses(policy.ApprovalRequiredClasses, seenClasses)
	if err != nil {
		return ProgramAgentPolicy{}, err
	}

	if len(stages) == 0 {
		if len(classes) != 0 || len(approvalClasses) != 0 || policy.MaxActionsPerRun != 0 || policy.MaxRequestsPerRun != 0 ||
			policy.MaxRequestsPerAction != 0 || policy.MaxTargetsPerAction != 0 {
			return ProgramAgentPolicy{}, errors.New("deny-all policy must have empty allowlists, no approval classes, and zero budgets")
		}
		policy.AllowedStages = nil
		policy.AllowedClasses = nil
		policy.ApprovalRequiredClasses = nil
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
	policy.ApprovalRequiredClasses = approvalClasses
	return policy, nil
}

func normalizeActionClasses(values []ActionClass) ([]ActionClass, error) {
	classes := make([]ActionClass, 0, len(values))
	seen := make(map[ActionClass]struct{}, len(values))
	for _, value := range values {
		class := ActionClass(strings.ToLower(strings.TrimSpace(string(value))))
		switch class {
		case ActionPassive, ActionSafeActive, ActionSensitive:
		default:
			return nil, fmt.Errorf("unsupported agent action class %q", value)
		}
		if _, exists := seen[class]; !exists {
			seen[class] = struct{}{}
			classes = append(classes, class)
		}
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
	return classes, nil
}

func normalizeApprovalRequiredClasses(values []ActionClass, allowed map[ActionClass]struct{}) ([]ActionClass, error) {
	classes, err := normalizeActionClasses(values)
	if err != nil {
		return nil, fmt.Errorf("invalid approval-required action classes: %w", err)
	}
	for _, class := range classes {
		if _, ok := allowed[class]; !ok {
			return nil, fmt.Errorf("approval-required class %q must also be allowlisted", class)
		}
	}
	return classes, nil
}
