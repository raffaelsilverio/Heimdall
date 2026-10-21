package providers

import (
	"fmt"
	"strings"
)

func New(name, apiKey string) (Provider, error){
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "opencode":
		return NewOpenCodeProvider(apiKey), nil
	case "openai":
		return NewOpenAIProvider(apiKey), nil
	default:
		return nil, fmt.Errorf("unsupported provider %q: user openai or opencode zen", name)
	}
}