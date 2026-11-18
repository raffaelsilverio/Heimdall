package providers

import (
	"strings"
	"testing"
)

func boundedToolDefinition() ToolDefinition {
	return ToolDefinition{
		Name:        "native_http_probe",
		Description: "Send one bounded HEAD request per authorized target.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"targets": {
					Type:     "array",
					Items:    &ToolProperty{Type: "string", MaxLength: 2048},
					MaxItems: 1000,
				},
			},
			Required: []string{"targets"},
		},
	}
}

func TestValidateToolDefinitionsAcceptsBoundedCatalog(t *testing.T) {
	if err := validateToolDefinitions([]ToolDefinition{boundedToolDefinition()}); err != nil {
		t.Fatalf("valid tool definition was rejected: %v", err)
	}
	if err := validateToolDefinitions(nil); err != nil {
		t.Fatalf("empty tool catalogue was rejected: %v", err)
	}
}

func TestValidateToolDefinitionsRejectsInvalidCatalog(t *testing.T) {
	tests := []struct {
		name string
		tool ToolDefinition
		want string
	}{
		{name: "bad name", tool: ToolDefinition{Name: "Native Probe", Description: "x", Parameters: boundedToolDefinition().Parameters}, want: "tool name"},
		{name: "missing description", tool: ToolDefinition{Name: "probe", Parameters: boundedToolDefinition().Parameters}, want: "description"},
		{name: "non-object schema", tool: ToolDefinition{Name: "probe", Description: "x", Parameters: ToolSchema{
			Type: "array", Properties: boundedToolDefinition().Parameters.Properties, Required: []string{"targets"},
		}}, want: "schema type"},
		{name: "no properties", tool: ToolDefinition{Name: "probe", Description: "x", Parameters: ToolSchema{Type: "object"}}, want: "properties"},
		{name: "additional properties", tool: ToolDefinition{Name: "probe", Description: "x", Parameters: ToolSchema{
			Type: "object", Properties: boundedToolDefinition().Parameters.Properties, Required: []string{"targets"},
			AdditionalProperties: true,
		}}, want: "additional properties"},
		{name: "unknown required", tool: ToolDefinition{Name: "probe", Description: "x", Parameters: ToolSchema{
			Type: "object", Properties: boundedToolDefinition().Parameters.Properties, Required: []string{"urls"},
		}}, want: "undeclared property"},
		{name: "array without items", tool: ToolDefinition{Name: "probe", Description: "x", Parameters: ToolSchema{
			Type: "object", Properties: map[string]ToolProperty{"targets": {Type: "array", MaxItems: 1}},
			Required: []string{"targets"},
		}}, want: "flat string item"},
		{name: "item missing max length", tool: ToolDefinition{Name: "probe", Description: "x", Parameters: ToolSchema{
			Type: "object", Properties: map[string]ToolProperty{"targets": {Type: "array", MaxItems: 1, Items: &ToolProperty{Type: "string"}}},
			Required: []string{"targets"},
		}}, want: "item max length"},
		{name: "unsupported property type", tool: ToolDefinition{Name: "probe", Description: "x", Parameters: ToolSchema{
			Type: "object", Properties: map[string]ToolProperty{"targets": {Type: "integer"}},
		}}, want: "unsupported type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateToolDefinitions([]ToolDefinition{test.tool}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateToolDefinitions error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateToolDefinitionsRejectsDuplicateAndExcessiveTools(t *testing.T) {
	duplicate := []ToolDefinition{boundedToolDefinition(), boundedToolDefinition()}
	if err := validateToolDefinitions(duplicate); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate tool error = %v, want a duplicate rejection", err)
	}
	many := make([]ToolDefinition, MaxToolDefinitions+1)
	for index := range many {
		tool := boundedToolDefinition()
		tool.Name = "probe_" + string(rune('a'+index))
		many[index] = tool
	}
	if err := validateToolDefinitions(many); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("excessive tool error = %v, want a count rejection", err)
	}
}

func TestValidateToolCallsAcceptsDeclaredCalls(t *testing.T) {
	calls := []ToolCall{{ID: "call_1", Name: "native_http_probe", Arguments: `{"targets":["https://app.example.test"]}`}}
	if err := validateToolCalls(calls, []ToolDefinition{boundedToolDefinition()}); err != nil {
		t.Fatalf("valid tool call was rejected: %v", err)
	}
}

func TestValidateToolCallsRejectsUnreviewedCalls(t *testing.T) {
	tools := []ToolDefinition{boundedToolDefinition()}
	tests := []struct {
		name  string
		calls []ToolCall
		want  string
	}{
		{name: "undeclared tool", calls: []ToolCall{{ID: "call_1", Name: "shell", Arguments: `{}`}}, want: "was not declared"},
		{name: "undeclared with empty catalogue", calls: []ToolCall{{ID: "call_1", Name: "native_http_probe", Arguments: `{}`}}, want: "was not declared"},
		{name: "missing id", calls: []ToolCall{{Name: "native_http_probe", Arguments: `{}`}}, want: "id is required"},
		{name: "bad name", calls: []ToolCall{{ID: "call_1", Name: "Native Probe", Arguments: `{}`}}, want: "name"},
		{name: "empty arguments", calls: []ToolCall{{ID: "call_1", Name: "native_http_probe"}}, want: "arguments"},
		{name: "array arguments", calls: []ToolCall{{ID: "call_1", Name: "native_http_probe", Arguments: `["https://a"]`}}, want: "JSON object"},
		{name: "null arguments", calls: []ToolCall{{ID: "call_1", Name: "native_http_probe", Arguments: `null`}}, want: "JSON object"},
		{name: "trailing arguments", calls: []ToolCall{{ID: "call_1", Name: "native_http_probe", Arguments: `{}{}`}}, want: "JSON object"},
		{name: "duplicate id", calls: []ToolCall{
			{ID: "call_1", Name: "native_http_probe", Arguments: `{}`},
			{ID: "call_1", Name: "native_http_probe", Arguments: `{}`},
		}, want: "repeated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalogue := tools
			if test.name == "undeclared with empty catalogue" {
				catalogue = nil
			}
			if err := validateToolCalls(test.calls, catalogue); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateToolCalls error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateToolCallsRejectsExcessiveCalls(t *testing.T) {
	calls := make([]ToolCall, MaxToolCalls+1)
	for index := range calls {
		calls[index] = ToolCall{ID: "call_" + string(rune('a'+index)), Name: "native_http_probe", Arguments: `{}`}
	}
	if err := validateToolCalls(calls, []ToolDefinition{boundedToolDefinition()}); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("excessive tool call error = %v, want a count rejection", err)
	}
}
