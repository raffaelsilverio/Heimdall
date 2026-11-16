package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	openAIResponsesURL = "https://api.openai.com/v1/responses"

	providerOpenAI   = "openai"
	providerOpenCode = "opencode"

	// DefaultTimeout bounds a single provider request when no override is set.
	DefaultTimeout = 60 * time.Second
)

type OpenAI struct {
	apiKey     string
	httpClient *http.Client
	endpoint   string
	name       string
}

func NewOpenAI(apiKey string) *OpenAI {
	return NewOpenAIWithTimeout(apiKey, DefaultTimeout)
}

func NewOpenAIWithTimeout(apiKey string, timeout time.Duration) *OpenAI {
	return newOpenAI(apiKey, openAIResponsesURL, providerOpenAI, timeout)
}

func newOpenAI(apiKey, endpoint, name string, timeout time.Duration) *OpenAI {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &OpenAI{
		apiKey:     strings.TrimSpace(apiKey),
		httpClient: &http.Client{Timeout: timeout},
		endpoint:   endpoint,
		name:       name,
	}
}

func (provider *OpenAI) Name() string {
	return provider.name
}

func (provider *OpenAI) label() string {
	switch provider.name {
	case providerOpenCode:
		return "OpenCode Zen"
	case "", providerOpenAI:
		return "OpenAI"
	default:
		return provider.name
	}
}

type openAIRequest struct {
	Model string    `json:"model"`
	Input []Message `json:"input"`
}

type openAIResponse struct {
	Output []struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
}

type openAIError struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (provider *OpenAI) Generate(
	ctx context.Context,
	request Request,
) (response Response, err error) {
	if provider.apiKey == "" {
		return Response{}, fmt.Errorf("%s: %w", provider.label(), ErrMissingAPIKey)
	}

	if strings.TrimSpace(request.Model) == "" {
		return Response{}, fmt.Errorf("%s: %w", provider.label(), ErrMissingModel)
	}

	if len(request.Messages) == 0 {
		return Response{}, fmt.Errorf("%s: %w", provider.label(), ErrMissingMessages)
	}

	payload := openAIRequest{
		Model: request.Model,
		Input: request.Messages,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("%s: encode request: %w", provider.label(), err)
	}

	httpRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		provider.endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return Response{}, fmt.Errorf("%s: create request: %w", provider.label(), err)
	}

	httpRequest.Header.Set("Authorization", "Bearer "+provider.apiKey)
	httpRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := provider.httpClient.Do(httpRequest)
	if err != nil {
		return Response{}, provider.transportError(err)
	}
	defer closeProviderResponseBody(httpResponse.Body, &err)

	responseBody, err := io.ReadAll(
		io.LimitReader(httpResponse.Body, 4<<20),
	)
	if err != nil {
		return Response{}, fmt.Errorf("%s: read response: %w", provider.label(), err)
	}

	return provider.decodeResponse(httpResponse.StatusCode, responseBody)
}

func (provider *OpenAI) transportError(err error) error {
	var timeoutError net.Error
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return fmt.Errorf("%s: %w: %w", provider.label(), ErrTimeout, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w: %w", provider.label(), ErrTimeout, err)
	}
	return fmt.Errorf("%s: send request: %w", provider.label(), err)
}

func (provider *OpenAI) decodeResponse(statusCode int, responseBody []byte) (Response, error) {
	if statusCode < 200 || statusCode >= 300 {
		apiError := &APIError{
			Provider:   provider.label(),
			StatusCode: statusCode,
			Err:        classifyStatus(statusCode),
		}
		var errorPayload openAIError
		if json.Unmarshal(responseBody, &errorPayload) == nil {
			apiError.Message = errorPayload.Error.Message
		}
		return Response{}, apiError
	}

	var result openAIResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return Response{}, fmt.Errorf("%s: %w: %w", provider.label(), ErrInvalidResponse, err)
	}

	var text strings.Builder

	for _, item := range result.Output {
		for _, content := range item.Content {
			if content.Type == "output_text" {
				text.WriteString(content.Text)
			}
		}
	}

	if strings.TrimSpace(text.String()) == "" {
		return Response{}, fmt.Errorf("%s: %w: no text output", provider.label(), ErrInvalidResponse)
	}

	return Response{Content: text.String()}, nil
}

func closeProviderResponseBody(body io.Closer, resultErr *error) {
	if closeErr := body.Close(); closeErr != nil {
		*resultErr = errors.Join(*resultErr, fmt.Errorf("close provider response body: %w", closeErr))
	}
}
