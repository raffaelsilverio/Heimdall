package providers

import (
	"fmt"
	"strings"
)

func New(name, apiKey string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "opencode":
		return NewOpenCodeZen(apiKey), nil
	case "openai":
		return NewOpenAI(apiKey), nil
	default:
		return nil, fmt.Errorf("unsupported provider %q: use openai or opencode", name)
	}
}
