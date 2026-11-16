package providers

import (
	"fmt"
	"strings"
	"time"
)

// New builds a provider with the default request timeout.
func New(name, apiKey string) (Provider, error) {
	return NewWithTimeout(name, apiKey, DefaultTimeout)
}

// NewWithTimeout builds a provider bounded by the given request timeout.
func NewWithTimeout(name, apiKey string, timeout time.Duration) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case providerOpenCode:
		return NewOpenCodeZenWithTimeout(apiKey, timeout), nil
	case providerOpenAI:
		return NewOpenAIWithTimeout(apiKey, timeout), nil
	default:
		return nil, fmt.Errorf("unsupported provider %q: use openai or opencode", name)
	}
}
