package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIGenerate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("unexpected Authorization header")
		}

		var payload struct {
			Model string    `json:"model"`
			Input []Message `json:"input"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if payload.Model != "test-model" {
			t.Errorf("expected model test-model, got %q", payload.Model)
		}

		if len(payload.Input) != 1 ||
			payload.Input[0].Role != "user" ||
			payload.Input[0].Content != "Olá" {
			t.Errorf("unexpected input: %+v", payload.Input)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"output": [{
				"content": [{
					"type": "output_text",
					"text": "Olá do teste"
				}]
			}]
		}`))
	}))
	defer server.Close()

	provider := &OpenAI{
		apiKey:     "test-key",
		httpClient: server.Client(),
		endpoint:   server.URL,
	}

	response, err := provider.Generate(context.Background(), Request{
		Model: "test-model",
		Messages: []Message{
			{Role: "user", Content: "Olá"},
		},
	})

	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	if strings.TrimSpace(response.Content) != "Olá do teste" {
		t.Errorf("unexpected response: %q", response.Content)
	}
}

func TestOpenAIGenerateUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{
			"error": {
				"message": "Invalid API key"
			}
		}`))
	}))
	defer server.Close()

	provider := &OpenAI{
		apiKey:     "invalid-key",
		httpClient: server.Client(),
		endpoint:   server.URL,
	}

	_, err := provider.Generate(context.Background(), Request{
		Model: "test-model",
		Messages: []Message{
			{Role: "user", Content: "Olá"},
		},
	})

	if err == nil {
		t.Fatal("expected an error for HTTP 401")
	}

	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("expected HTTP 401 error, got: %v", err)
	}

	if !strings.Contains(err.Error(), "Invalid API key") {
		t.Errorf("expected API error message, got: %v", err)
	}
}
