package providers

import "time"

const openCodeZenResponsesURL = "https://opencode.ai/zen/v1/responses"

// NewOpenCodeZen creates a provider for OpenCode Zen models
// compatible with the Responses API.
func NewOpenCodeZen(apiKey string) *OpenAI {
	return NewOpenCodeZenWithTimeout(apiKey, DefaultTimeout)
}

func NewOpenCodeZenWithTimeout(apiKey string, timeout time.Duration) *OpenAI {
	return newOpenAI(apiKey, openCodeZenResponsesURL, providerOpenCode, timeout)
}
