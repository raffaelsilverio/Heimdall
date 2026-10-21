package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Provider string
	Model string
	APIKey string
}

func LoadConfig(providerOverride, modelOverride string) (Config, error) {
	provider := strings.ToLower(strings.TrimSpace(
		os.Getenv("HEIMDALL_PROVIDER"),
	))

	if providerOverride != "" {
		provider = strings.ToLower(strings.TrimSpace(providerOverride))
	}

	if provider == "" {
		provider = "opencode"
	}
	model := strings.TrimSpace(os.Getenv("HEIMDALL_MODEL"))
	if modelOverride != "" {
		model = strings.TrimSpace(modelOverride)
	}

	config := Config{
		Provider: provider,
		Model:    model,
	}
	switch provider {
	case "opencode":
		config.APIKey = strings.TrimSpace(os.Getenv("OPENCODE_API_KEY"))
	case "openai":
		config.APIKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	default:
		return Config{}, fmt.Errorf("unsupported provider %q: user openai or opencode zen", provider)
	}
	return config, nil
}