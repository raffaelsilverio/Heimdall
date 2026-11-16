package providers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGenerateRejectsMissingAPIKey(t *testing.T) {
	for _, provider := range []*OpenAI{NewOpenAI(""), NewOpenCodeZen("")} {
		_, err := provider.Generate(context.Background(), Request{
			Model:    "test-model",
			Messages: []Message{{Role: "user", Content: "hello"}},
		})
		if !errors.Is(err, ErrMissingAPIKey) {
			t.Fatalf("%s Generate error = %v, want ErrMissingAPIKey", provider.Name(), err)
		}
		if !strings.Contains(err.Error(), provider.label()) {
			t.Errorf("%s error %q does not identify the provider", provider.Name(), err)
		}
	}
}

func TestGenerateRejectsMissingInput(t *testing.T) {
	provider := NewOpenAI("test-key")
	if _, err := provider.Generate(context.Background(), Request{}); !errors.Is(err, ErrMissingModel) {
		t.Fatalf("error = %v, want ErrMissingModel", err)
	}
	if _, err := provider.Generate(context.Background(), Request{Model: "test-model"}); !errors.Is(err, ErrMissingMessages) {
		t.Fatalf("error = %v, want ErrMissingMessages", err)
	}
}

func TestGenerateClassifiesHTTPErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       error
	}{
		{name: "unauthorized", statusCode: http.StatusUnauthorized, want: ErrUnauthorized},
		{name: "forbidden", statusCode: http.StatusForbidden, want: ErrUnauthorized},
		{name: "rate limited", statusCode: http.StatusTooManyRequests, want: ErrRateLimited},
		{name: "server error", statusCode: http.StatusServiceUnavailable, want: ErrServerError},
		{name: "bad request", statusCode: http.StatusBadRequest, want: ErrRequestRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.statusCode)
				_, _ = w.Write([]byte(`{"error":{"message":"provider detail"}}`))
			}))
			defer server.Close()

			provider := &OpenAI{
				apiKey:     "test-key",
				httpClient: server.Client(),
				endpoint:   server.URL,
				name:       providerOpenAI,
			}
			_, err := provider.Generate(context.Background(), Request{
				Model:    "test-model",
				Messages: []Message{{Role: "user", Content: "hello"}},
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("Generate error = %v, want %v", err, test.want)
			}
			var apiError *APIError
			if !errors.As(err, &apiError) {
				t.Fatalf("Generate error = %v, want *APIError", err)
			}
			if apiError.StatusCode != test.statusCode {
				t.Errorf("StatusCode = %d, want %d", apiError.StatusCode, test.statusCode)
			}
			if apiError.Message != "provider detail" {
				t.Errorf("Message = %q, want provider detail", apiError.Message)
			}
		})
	}
}

func TestGenerateLabelsOpenCodeErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"zen failure"}}`))
	}))
	defer server.Close()

	provider := newOpenAI("test-key", server.URL, providerOpenCode, time.Second)
	_, err := provider.Generate(context.Background(), Request{
		Model:    "test-model",
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected an error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "OpenCode Zen") {
		t.Errorf("error %q does not identify OpenCode Zen", err)
	}
	if strings.Contains(err.Error(), "OpenAI") {
		t.Errorf("error %q was mislabelled as OpenAI", err)
	}
	if !errors.Is(err, ErrServerError) {
		t.Errorf("error = %v, want ErrServerError", err)
	}
}

func TestGenerateTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = w.Write([]byte(`{"output":[]}`))
	}))
	defer server.Close()

	provider := newOpenAI("test-key", server.URL, providerOpenAI, 20*time.Millisecond)
	_, err := provider.Generate(context.Background(), Request{
		Model:    "test-model",
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Generate error = %v, want ErrTimeout", err)
	}
}

func TestGenerateRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid json", body: "not-json"},
		{name: "empty output", body: `{"output":[]}`},
		{name: "no text content", body: `{"output":[{"content":[{"type":"reasoning"}]}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			provider := &OpenAI{
				apiKey:     "test-key",
				httpClient: server.Client(),
				endpoint:   server.URL,
				name:       providerOpenAI,
			}
			_, err := provider.Generate(context.Background(), Request{
				Model:    "test-model",
				Messages: []Message{{Role: "user", Content: "hello"}},
			})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Generate error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestNewWithTimeout(t *testing.T) {
	provider, err := NewWithTimeout(" OPENCODE ", "test-key", 5*time.Second)
	if err != nil {
		t.Fatalf("NewWithTimeout returned an error: %v", err)
	}
	if provider.Name() != providerOpenCode {
		t.Errorf("Name() = %q, want %q", provider.Name(), providerOpenCode)
	}
	openAI, ok := provider.(*OpenAI)
	if !ok {
		t.Fatalf("provider type = %T, want *OpenAI", provider)
	}
	if openAI.httpClient.Timeout != 5*time.Second {
		t.Errorf("timeout = %s, want 5s", openAI.httpClient.Timeout)
	}

	if _, err := NewWithTimeout("anthropic", "test-key", time.Second); err == nil {
		t.Fatal("expected an error for an unsupported provider")
	}
	if _, err := NewWithTimeout("openai", "test-key", 0); err != nil {
		t.Fatalf("NewWithTimeout with zero timeout returned an error: %v", err)
	}
}
