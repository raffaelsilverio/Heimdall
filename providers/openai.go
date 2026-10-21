
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const openAIResponsesURL = "https://api.openai.com/v1/responses"

type OpenAI struct {
	apiKey     string
	httpClient *http.Client
	endpoint   string
	name       string
}

func NewOpenAI(apiKey string) *OpenAI {
	return &OpenAI{
		apiKey:     strings.TrimSpace(apiKey),
		httpClient: &http.Client{Timeout: 60 * time.Second},
		endpoint:   openAIResponsesURL,
		name:       "openai",
	}
}
func (p *OpenAI) Name() string {
	return p.name
}

type openAIRequest struct {
	Model string `json:"model"`
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

func (p *OpenAI) Generate(
	ctx context.Context,
	request Request,
) (Response, error) {
	if p.apiKey == "" {
		return Response{}, fmt.Errorf("OpenAI API key is not configured")
	}

	if strings.TrimSpace(request.Model) == "" {
		return Response{}, fmt.Errorf("model is required")
	}

	if len(request.Messages) == 0 {
		return Response{}, fmt.Errorf("at least one message is required")
	}

	payload := openAIRequest{
		Model: request.Model,
		Input: request.Messages,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("encode request: %w", err)
	}

	httpRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		p.endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return Response{}, fmt.Errorf("create request: %w", err)
	}

	httpRequest.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := p.httpClient.Do(httpRequest)
	if err != nil {
		return Response{}, fmt.Errorf("send OpenAI request: %w", err)
	}
	defer httpResponse.Body.Close()

	responseBody, err := io.ReadAll(
		io.LimitReader(httpResponse.Body, 4<<20),
	)
	if err != nil {
		return Response{}, fmt.Errorf("read response: %w", err)
	}

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		var apiError openAIError

		if json.Unmarshal(responseBody, &apiError) == nil &&
			apiError.Error.Message != "" {
			return Response{}, fmt.Errorf(
				"OpenAI API returned HTTP %d: %s",
				httpResponse.StatusCode,
				apiError.Error.Message,
			)
		}

		return Response{}, fmt.Errorf(
			"OpenAI API returned HTTP %d",
			httpResponse.StatusCode,
		)
	}

	var result openAIResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
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
		return Response{}, fmt.Errorf("OpenAI returned no text output")
	}

	return Response{Content: text.String()}, nil
}
