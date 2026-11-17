package recon

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// AgentToolClassSafeActive is the only action class a compiled agent tool
	// may declare today. Sensitive or state-changing classes require explicit
	// policy work before they can enter the catalog.
	AgentToolClassSafeActive = "safe_active"

	// AgentToolAccountingOnePerTarget records that each authorized target costs
	// exactly one metered request.
	AgentToolAccountingOnePerTarget = "one_request_per_target"

	ToolArgumentStringList = "string_list"
)

const (
	maxAgentToolDescription = 500
	maxAgentToolTargets     = 1000
	maxAgentToolArguments   = 8
	maxAgentToolTargetLen   = 4096
)

// AgentToolSpec is the reviewed, compiled metadata for one agent action. It is
// the only catalog entry shape the agent runtime accepts; there is no dynamic
// tool loading.
type AgentToolSpec struct {
	ID          string         `json:"id"`
	Stage       string         `json:"stage"`
	Class       string         `json:"class"`
	Description string         `json:"description"`
	MaxTargets  int            `json:"max_targets"`
	Arguments   []ToolArgument `json:"arguments"`
	Accounting  string         `json:"accounting"`
}

// ToolArgument describes one bounded model-visible argument. Only explicitly
// supported argument names and types are accepted.
type ToolArgument struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Required  bool   `json:"required"`
	MaxItems  int    `json:"max_items,omitempty"`
	MaxLength int    `json:"max_length,omitempty"`
}

// Validate rejects incomplete or unsupported tool metadata at registration
// time, so an invalid adapter can never enter the executed catalog.
func (spec AgentToolSpec) Validate() error {
	if err := spec.validateIdentity(); err != nil {
		return err
	}
	if err := spec.validateCatalogLimits(); err != nil {
		return err
	}
	return spec.validateArguments()
}

func (spec AgentToolSpec) validateIdentity() error {
	if spec.ID == "" || strings.TrimSpace(spec.ID) != spec.ID {
		return errors.New("agent tool ids must be non-empty without surrounding whitespace")
	}
	if spec.Stage != StageWeb {
		return fmt.Errorf("agent tool %q has unsupported stage %q", spec.ID, spec.Stage)
	}
	if spec.Class != AgentToolClassSafeActive {
		return fmt.Errorf("agent tool %q has unsupported action class %q", spec.ID, spec.Class)
	}
	return nil
}

func (spec AgentToolSpec) validateCatalogLimits() error {
	description := strings.TrimSpace(spec.Description)
	if description == "" || len(description) > maxAgentToolDescription {
		return fmt.Errorf("agent tool %q description must contain 1-%d bytes", spec.ID, maxAgentToolDescription)
	}
	if spec.MaxTargets < 1 || spec.MaxTargets > maxAgentToolTargets {
		return fmt.Errorf("agent tool %q max targets must be between 1 and %d", spec.ID, maxAgentToolTargets)
	}
	if spec.Accounting != AgentToolAccountingOnePerTarget {
		return fmt.Errorf("agent tool %q has unsupported accounting %q", spec.ID, spec.Accounting)
	}
	return nil
}

func (spec AgentToolSpec) validateArguments() error {
	if len(spec.Arguments) == 0 || len(spec.Arguments) > maxAgentToolArguments {
		return fmt.Errorf("agent tool %q must declare 1-%d arguments", spec.ID, maxAgentToolArguments)
	}
	seen := make(map[string]bool, len(spec.Arguments))
	for _, argument := range spec.Arguments {
		if err := spec.validateArgument(argument); err != nil {
			return err
		}
		if seen[argument.Name] {
			return fmt.Errorf("agent tool %q declares argument %q more than once", spec.ID, argument.Name)
		}
		seen[argument.Name] = true
	}
	if !seen["targets"] {
		return fmt.Errorf("agent tool %q requires a targets argument", spec.ID)
	}
	return nil
}

func (spec AgentToolSpec) validateArgument(argument ToolArgument) error {
	if argument.Name != "targets" {
		return fmt.Errorf("agent tool %q declares unsupported argument %q", spec.ID, argument.Name)
	}
	if argument.Type != ToolArgumentStringList {
		return fmt.Errorf("agent tool %q argument %q has unsupported type %q", spec.ID, argument.Name, argument.Type)
	}
	if !argument.Required {
		return fmt.Errorf("agent tool %q argument %q must be required", spec.ID, argument.Name)
	}
	if argument.MaxItems < 1 || argument.MaxItems > spec.MaxTargets {
		return fmt.Errorf("agent tool %q argument %q max items must be between 1 and %d", spec.ID, argument.Name, spec.MaxTargets)
	}
	if argument.MaxLength < 1 || argument.MaxLength > maxAgentToolTargetLen {
		return fmt.Errorf("agent tool %q argument %q max length must be between 1 and %d", spec.ID, argument.Name, maxAgentToolTargetLen)
	}
	return nil
}

// ValidateRequest checks a concrete request against the tool schema before the
// adapter is allowed to run.
func (spec AgentToolSpec) ValidateRequest(request StageRequest) error {
	if request.Stage != spec.Stage {
		return fmt.Errorf("agent action %q requires stage %q", spec.ID, spec.Stage)
	}
	if len(request.Targets) == 0 {
		return fmt.Errorf("agent action %q requires at least one target", spec.ID)
	}
	if len(request.Targets) > spec.MaxTargets {
		return fmt.Errorf("agent action %q accepts at most %d targets", spec.ID, spec.MaxTargets)
	}
	if request.RequestBudget < len(request.Targets) {
		return fmt.Errorf("agent action %q request budget must cover every target", spec.ID)
	}
	maxLength := spec.targetMaxLength()
	for _, target := range request.Targets {
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("agent action %q targets must be non-empty", spec.ID)
		}
		if len(target) > maxLength {
			return fmt.Errorf("agent action %q target exceeds %d bytes", spec.ID, maxLength)
		}
	}
	return nil
}

func (spec AgentToolSpec) targetMaxLength() int {
	for _, argument := range spec.Arguments {
		if argument.Name == "targets" {
			return argument.MaxLength
		}
	}
	return 0
}
