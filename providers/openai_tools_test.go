package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIGenerateSerializesToolsAndDecodesFunctionCalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Tools []struct {
				Type        string `json:"type"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Parameters  struct {
					Type       string `json:"type"`
					Properties map[string]struct {
						Type     string `json:"type"`
						MaxItems int    `json:"maxItems"`
						Items    struct {
							Type      string `json:"type"`
							MaxLength int    `json:"maxLength"`
						} `json:"items"`
					} `json:"properties"`
					Required             []string `json:"required"`
					AdditionalProperties bool     `json:"additionalProperties"`
				} `json:"parameters"`
			} `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if len(payload.Tools) != 1 {
			t.Fatalf("request carried %d tools, want 1", len(payload.Tools))
		}
		tool := payload.Tools[0]
		if tool.Type != "function" || tool.Name != "native_http_probe" || tool.Description == "" {
			t.Fatalf("unexpected tool definition: %+v", tool)
		}
		if tool.Parameters.Type != "object" || tool.Parameters.AdditionalProperties {
			t.Fatalf("unexpected tool schema: %+v", tool.Parameters)
		}
		targets := tool.Parameters.Properties["targets"]
		if targets.Type != "array" || targets.MaxItems != 1000 || targets.Items.Type != "string" || targets.Items.MaxLength != 2048 {
			t.Fatalf("unexpected targets schema: %+v", targets)
		}
		if len(tool.Parameters.Required) != 1 || tool.Parameters.Required[0] != "targets" {
			t.Fatalf("unexpected required properties: %+v", tool.Parameters.Required)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"output": [
				{"type": "message", "content": [{"type": "output_text", "text": "Planning."}]},
				{"type": "function_call", "id": "fc_1", "call_id": "call_1",
				 "name": "native_http_probe", "arguments": "{\"targets\":[\"https://app.example.test\"]}"}
			]
		}`))
	}))
	defer server.Close()

	provider := &OpenAI{apiKey: "test-key", httpClient: server.Client(), endpoint: server.URL}
	response, err := provider.Generate(context.Background(), Request{
		Model:    "test-model",
		Messages: []Message{{Role: "user", Content: "Plan"}},
		Tools:    []ToolDefinition{boundedToolDefinition()},
	})
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}
	if strings.TrimSpace(response.Content) != "Planning." {
		t.Fatalf("unexpected text content: %q", response.Content)
	}
	if len(response.ToolCalls) != 1 {
		t.Fatalf("decoded %d tool calls, want 1: %+v", len(response.ToolCalls), response.ToolCalls)
	}
	call := response.ToolCalls[0]
	if call.ID != "call_1" || call.Name != "native_http_probe" ||
		call.Arguments != `{"targets":["https://app.example.test"]}` {
		t.Fatalf("unexpected tool call: %+v", call)
	}
}

func TestOpenAIGenerateRejectsUnreviewedToolCalls(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		tools   []ToolDefinition
		wantErr error
		want    string
	}{
		{
			name:    "undeclared tool",
			output:  `{"output":[{"type":"function_call","call_id":"call_1","name":"shell","arguments":"{}"}]}`,
			tools:   []ToolDefinition{boundedToolDefinition()},
			wantErr: ErrInvalidToolCall, want: "was not declared",
		},
		{
			name:    "tool call without catalogue",
			output:  `{"output":[{"type":"function_call","call_id":"call_1","name":"native_http_probe","arguments":"{}"}]}`,
			wantErr: ErrInvalidToolCall, want: "was not declared",
		},
		{
			name:    "malformed arguments",
			output:  `{"output":[{"type":"function_call","call_id":"call_1","name":"native_http_probe","arguments":"not-json"}]}`,
			tools:   []ToolDefinition{boundedToolDefinition()},
			wantErr: ErrInvalidToolCall, want: "JSON object",
		},
		{
			name:    "no text or tool call",
			output:  `{"output":[]}`,
			wantErr: ErrInvalidResponse, want: "no text or tool call",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.output))
			}))
			defer server.Close()

			provider := &OpenAI{apiKey: "test-key", httpClient: server.Client(), endpoint: server.URL}
			_, err := provider.Generate(context.Background(), Request{
				Model: "test-model", Messages: []Message{{Role: "user", Content: "Plan"}}, Tools: test.tools,
			})
			if !errors.Is(err, test.wantErr) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Generate error = %v, want %v containing %q", err, test.wantErr, test.want)
			}
		})
	}
}

func TestOpenAIGenerateRejectsInvalidToolDefinitionBeforeSending(t *testing.T) {
	provider := &OpenAI{apiKey: "test-key", httpClient: &http.Client{}, endpoint: "https://provider.invalid"}
	tool := boundedToolDefinition()
	tool.Name = "Native Probe"
	_, err := provider.Generate(context.Background(), Request{
		Model: "test-model", Messages: []Message{{Role: "user", Content: "Plan"}}, Tools: []ToolDefinition{tool},
	})
	if !errors.Is(err, ErrInvalidToolDefinition) || !strings.Contains(err.Error(), "tool name") {
		t.Fatalf("Generate error = %v, want an invalid tool definition rejection", err)
	}
}

func TestOpenAIGenerateOmitsToolsWhenNoneAreDeclared(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if _, present := payload["tools"]; present {
			t.Errorf("request without tools carried a tools field: %s", payload["tools"])
		}
		_, _ = w.Write([]byte(`{"output":[{"content":[{"type":"output_text","text":"ok"}]}]}`))
	}))
	defer server.Close()

	provider := &OpenAI{apiKey: "test-key", httpClient: server.Client(), endpoint: server.URL}
	if _, err := provider.Generate(context.Background(), Request{
		Model: "test-model", Messages: []Message{{Role: "user", Content: "Hello"}},
	}); err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}
}
