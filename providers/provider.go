package providers

import "context"

// Message represents a single message sent to an AI model.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ToolDefinition declares one function the model may call. Only reviewed,
// compiled definitions are ever sent; the provider rejects anything outside
// this bounded shape.
type ToolDefinition struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Parameters  ToolSchema `json:"parameters"`
}

// ToolSchema is the JSON-schema subset Heimdall accepts for tool arguments. It
// is intentionally small: an object with typed properties and no additional
// properties.
type ToolSchema struct {
	Type                 string                  `json:"type"`
	Properties           map[string]ToolProperty `json:"properties"`
	Required             []string                `json:"required"`
	AdditionalProperties bool                    `json:"additionalProperties"`
}

// ToolProperty describes one bounded argument value.
type ToolProperty struct {
	Type        string        `json:"type"`
	Description string        `json:"description,omitempty"`
	Items       *ToolProperty `json:"items,omitempty"`
	MaxItems    int           `json:"maxItems,omitempty"`
	MaxLength   int           `json:"maxLength,omitempty"`
}

// ToolCall is one function-call item returned by a model. Arguments stay as a
// raw JSON string so the caller can validate them against the reviewed schema
// before any action is proposed.
type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type Request struct {
	Model    string           `json:"model"`
	Messages []Message        `json:"messages"`
	Tools    []ToolDefinition `json:"tools,omitempty"`
}

type Response struct {
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

type Provider interface {
	Name() string
	Generate(ctx context.Context, request Request) (Response, error)
}
