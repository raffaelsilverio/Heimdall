package providers

import (
	"net/http"
	"strings"
	"time"
)

const openCodeZenResponsesURL = "https://opencode.ai/zen/v1/responses"

// NewOpenCodeZen creates a provider for OpenCode Zen models
// compatible with the Responses API.
func NewOpenCodeZen(apiKey string) *OpenAI {
	return &OpenAI{
		apiKey:     strings.TrimSpace(apiKey),
		httpClient: &http.Client{Timeout: 60 * time.Second},
		endpoint:   openCodeZenResponsesURL,
		name:       "opencode",
	}
}
