package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	ProviderOpenAI   = "openai"
	ProviderOpenCode = "opencode"

	DefaultProvider  = ProviderOpenAI
	DefaultLogLevel  = "info"
	DefaultLogFormat = "text"

	DefaultRequestTimeout = 60 * time.Second
	MinRequestTimeout     = time.Second
	MaxRequestTimeout     = 10 * time.Minute

	DefaultContextMaxBytes = 256 << 10
	MinContextMaxBytes     = 16 << 10
	MaxContextMaxBytes     = 1 << 20

	// ConfigFileName is the file looked up inside the Heimdall home directory
	// when no explicit --config path is provided.
	ConfigFileName = "config.yaml"
)

var apiKeyEnvironment = map[string]string{
	ProviderOpenAI:   "OPENAI_API_KEY",
	ProviderOpenCode: "OPENCODE_API_KEY",
}

// Config holds resolved runtime configuration. API keys are always read from
// the environment so they are never stored in the config file.
type Config struct {
	Provider        string
	Model           string
	APIKey          string
	LogLevel        string
	LogFormat       string
	RequestTimeout  time.Duration
	ContextMaxBytes int
	FilePath        string
}

// Options contains command-line overrides. Empty values fall back to the
// environment, then the config file, then defaults.
type Options struct {
	// Home is the Heimdall data directory. When empty, HEIMDALL_HOME and then
	// the user config directory are used.
	Home string
	// ConfigFile is an explicit config file path. When empty,
	// <Home>/config.yaml is loaded if it exists.
	ConfigFile string
	Provider   string
	Model      string
	LogLevel   string
	LogFormat  string
	// RequestTimeout overrides the provider request timeout when positive.
	RequestTimeout time.Duration
	// ContextMaxBytes overrides the conversation context budget when positive.
	ContextMaxBytes int
}

// Home resolves the Heimdall data directory.
func Home() string {
	if configured := strings.TrimSpace(os.Getenv("HEIMDALL_HOME")); configured != "" {
		return configured
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".", ".heimdall")
	}
	return filepath.Join(directory, "heimdall")
}

// Load resolves configuration with the precedence flag > environment >
// config file > defaults.
func Load(options Options) (Config, error) {
	filePath, err := resolveConfigFile(options)
	if err != nil {
		return Config{}, err
	}

	loader := viper.New()
	loader.SetDefault("provider", DefaultProvider)
	loader.SetDefault("log_level", DefaultLogLevel)
	loader.SetDefault("log_format", DefaultLogFormat)
	loader.SetDefault("request_timeout", DefaultRequestTimeout.String())
	loader.SetDefault("context_max_bytes", DefaultContextMaxBytes)
	loader.SetEnvPrefix("HEIMDALL")
	loader.AutomaticEnv()
	if filePath != "" {
		loader.SetConfigFile(filePath)
		if err := loader.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read config file %s: %w", filePath, err)
		}
	}

	if provider := normalize(options.Provider); provider != "" {
		loader.Set("provider", provider)
	}
	if model := strings.TrimSpace(options.Model); model != "" {
		loader.Set("model", model)
	}
	if level := normalize(options.LogLevel); level != "" {
		loader.Set("log_level", level)
	}
	if format := normalize(options.LogFormat); format != "" {
		loader.Set("log_format", format)
	}
	if options.RequestTimeout > 0 {
		loader.Set("request_timeout", options.RequestTimeout.String())
	}
	if options.ContextMaxBytes > 0 {
		loader.Set("context_max_bytes", options.ContextMaxBytes)
	}

	requestTimeout, err := parseRequestTimeout(loader.GetString("request_timeout"))
	if err != nil {
		return Config{}, err
	}

	config := Config{
		Provider:        normalize(loader.GetString("provider")),
		Model:           strings.TrimSpace(loader.GetString("model")),
		LogLevel:        normalize(loader.GetString("log_level")),
		LogFormat:       normalize(loader.GetString("log_format")),
		RequestTimeout:  requestTimeout,
		ContextMaxBytes: loader.GetInt("context_max_bytes"),
		FilePath:        filePath,
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	config.APIKey = apiKey(config.Provider)
	return config, nil
}

// WithOverrides applies command-line provider/model overrides to an already
// resolved configuration and reloads the provider's API key.
func (config Config) WithOverrides(provider, model string) (Config, error) {
	if value := normalize(provider); value != "" {
		config.Provider = value
	}
	if value := strings.TrimSpace(model); value != "" {
		config.Model = value
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	config.APIKey = apiKey(config.Provider)
	return config, nil
}

// HasAPIKey reports whether the configured provider has an API key available.
func (config Config) HasAPIKey() bool {
	return config.APIKey != ""
}

func (config Config) validate() error {
	switch config.Provider {
	case ProviderOpenAI, ProviderOpenCode:
	default:
		return fmt.Errorf("unsupported provider %q: use openai or opencode", config.Provider)
	}
	switch config.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log level %q: use debug, info, warn or error", config.LogLevel)
	}
	switch config.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("unsupported log format %q: use text or json", config.LogFormat)
	}
	if config.ContextMaxBytes < MinContextMaxBytes || config.ContextMaxBytes > MaxContextMaxBytes {
		return fmt.Errorf(
			"context max bytes %d must be between %d and %d",
			config.ContextMaxBytes, MinContextMaxBytes, MaxContextMaxBytes,
		)
	}
	return nil
}

func parseRequestTimeout(value string) (time.Duration, error) {
	timeout, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid request timeout %q: use a duration such as 60s", value)
	}
	if timeout < MinRequestTimeout || timeout > MaxRequestTimeout {
		return 0, fmt.Errorf(
			"request timeout %s must be between %s and %s",
			timeout, MinRequestTimeout, MaxRequestTimeout,
		)
	}
	return timeout, nil
}

func resolveConfigFile(options Options) (string, error) {
	explicit := strings.TrimSpace(options.ConfigFile)
	path := explicit
	if path == "" {
		home := strings.TrimSpace(options.Home)
		if home == "" {
			home = strings.TrimSpace(os.Getenv("HEIMDALL_HOME"))
		}
		if home == "" {
			return "", nil
		}
		path = filepath.Join(home, ConfigFileName)
	}

	// The path is an explicit operator choice (--config, --home or
	// HEIMDALL_HOME) and the file is only read, never written.
	info, err := os.Stat(path) // #nosec G703 -- operator-selected config path
	switch {
	case err == nil:
		if info.IsDir() {
			return "", fmt.Errorf("config file %s is a directory", path)
		}
		return path, nil
	case errors.Is(err, fs.ErrNotExist):
		if explicit != "" {
			return "", fmt.Errorf("config file %s does not exist", explicit)
		}
		return "", nil
	default:
		return "", fmt.Errorf("inspect config file %s: %w", path, err)
	}
}

func apiKey(provider string) string {
	name, ok := apiKeyEnvironment[provider]
	if !ok {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
