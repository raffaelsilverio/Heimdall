package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Bounds applied to every tool catalogue and every model tool call. They keep
// the wire payload and the resulting planner output finite.
const (
	MaxToolDefinitions      = 16
	MaxToolCalls            = 20
	MaxToolArgumentsBytes   = 8 << 10
	maxToolNameBytes        = 64
	maxToolDescriptionBytes = 500
	maxToolProperties       = 8
	maxToolItems            = 10_000
	maxToolLength           = 4 << 10
)

// validateToolDefinitions rejects an unbounded or malformed outbound tool
// catalogue before any request is built.
func validateToolDefinitions(tools []ToolDefinition) error {
	if len(tools) > MaxToolDefinitions {
		return fmt.Errorf("at most %d tool definitions are allowed", MaxToolDefinitions)
	}
	names := make(map[string]bool, len(tools))
	for _, tool := range tools {
		if err := validateToolDefinition(tool); err != nil {
			return err
		}
		if names[tool.Name] {
			return fmt.Errorf("tool %q is defined more than once", tool.Name)
		}
		names[tool.Name] = true
	}
	return nil
}

func validateToolDefinition(tool ToolDefinition) error {
	if !validToolName(tool.Name) {
		return fmt.Errorf("tool name %q must contain 1-%d lowercase letters, digits, or underscores", tool.Name, maxToolNameBytes)
	}
	description := strings.TrimSpace(tool.Description)
	if description == "" || len(description) > maxToolDescriptionBytes {
		return fmt.Errorf("tool %q description must contain 1-%d bytes", tool.Name, maxToolDescriptionBytes)
	}
	if err := validateToolSchema(tool.Parameters); err != nil {
		return fmt.Errorf("tool %q parameters: %w", tool.Name, err)
	}
	return nil
}

func validateToolSchema(schema ToolSchema) error {
	if schema.Type != "object" {
		return fmt.Errorf("schema type must be object, got %q", schema.Type)
	}
	if len(schema.Properties) == 0 || len(schema.Properties) > maxToolProperties {
		return fmt.Errorf("schema must declare 1-%d properties", maxToolProperties)
	}
	if schema.AdditionalProperties {
		return errors.New("schema must not allow additional properties")
	}
	for name, property := range schema.Properties {
		if err := validateToolProperty(name, property); err != nil {
			return err
		}
	}
	required := make(map[string]bool, len(schema.Required))
	for _, name := range schema.Required {
		if required[name] {
			return fmt.Errorf("schema requires property %q more than once", name)
		}
		if _, declared := schema.Properties[name]; !declared {
			return fmt.Errorf("schema requires undeclared property %q", name)
		}
		required[name] = true
	}
	return nil
}

func validateToolProperty(name string, property ToolProperty) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("schema property names must be non-empty")
	}
	if len(property.Description) > maxToolDescriptionBytes {
		return fmt.Errorf("property %q description exceeds %d bytes", name, maxToolDescriptionBytes)
	}
	switch property.Type {
	case "string":
		if property.Items != nil || property.MaxItems != 0 {
			return fmt.Errorf("string property %q must not declare array bounds", name)
		}
		if property.MaxLength < 0 || property.MaxLength > maxToolLength {
			return fmt.Errorf("property %q max length must be between 0 and %d", name, maxToolLength)
		}
		return nil
	case "array":
		return validateToolArrayProperty(name, property)
	default:
		return fmt.Errorf("property %q has unsupported type %q", name, property.Type)
	}
}

func validateToolArrayProperty(name string, property ToolProperty) error {
	if property.MaxLength != 0 {
		return fmt.Errorf("array property %q must not declare a string max length", name)
	}
	if property.MaxItems < 1 || property.MaxItems > maxToolItems {
		return fmt.Errorf("property %q max items must be between 1 and %d", name, maxToolItems)
	}
	if property.Items == nil || property.Items.Type != "string" || property.Items.Items != nil {
		return fmt.Errorf("property %q must contain a flat string item schema", name)
	}
	if property.Items.MaxItems != 0 {
		return fmt.Errorf("property %q item schema must not declare max items", name)
	}
	if property.Items.MaxLength < 1 || property.Items.MaxLength > maxToolLength {
		return fmt.Errorf("property %q item max length must be between 1 and %d", name, maxToolLength)
	}
	return nil
}

// validateToolCalls rejects model function calls that were not advertised in
// the same request, repeat a call id, exceed the call cap, or carry arguments
// that are not a bounded JSON object.
func validateToolCalls(calls []ToolCall, tools []ToolDefinition) error {
	if len(calls) > MaxToolCalls {
		return fmt.Errorf("at most %d tool calls are allowed per response", MaxToolCalls)
	}
	declared := make(map[string]bool, len(tools))
	for _, tool := range tools {
		declared[tool.Name] = true
	}
	ids := make(map[string]bool, len(calls))
	for _, call := range calls {
		if err := validateToolCall(call, declared); err != nil {
			return err
		}
		if ids[call.ID] {
			return fmt.Errorf("tool call id %q is repeated", call.ID)
		}
		ids[call.ID] = true
	}
	return nil
}

func validateToolCall(call ToolCall, declared map[string]bool) error {
	if call.ID == "" || strings.TrimSpace(call.ID) != call.ID {
		return errors.New("tool call id is required without surrounding whitespace")
	}
	if !validToolName(call.Name) {
		return fmt.Errorf("tool call name %q is invalid", call.Name)
	}
	if !declared[call.Name] {
		return fmt.Errorf("tool %q was not declared in the request", call.Name)
	}
	if len(call.Arguments) == 0 || len(call.Arguments) > MaxToolArgumentsBytes {
		return fmt.Errorf("tool call %q arguments must contain 1-%d bytes", call.Name, MaxToolArgumentsBytes)
	}
	if !isJSONObject(call.Arguments) {
		return fmt.Errorf("tool call %q arguments must be one JSON object", call.Name)
	}
	return nil
}

func validToolName(name string) bool {
	if len(name) == 0 || len(name) > maxToolNameBytes {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func isJSONObject(value string) bool {
	decoder := json.NewDecoder(strings.NewReader(value))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}
