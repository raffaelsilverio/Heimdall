package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clearEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"HEIMDALL_PROVIDER",
		"HEIMDALL_MODEL",
		"HEIMDALL_LOG_LEVEL",
		"HEIMDALL_LOG_FORMAT",
		"HEIMDALL_REQUEST_TIMEOUT",
		"HEIMDALL_HOME",
		"OPENAI_API_KEY",
		"OPENCODE_API_KEY",
	} {
		t.Setenv(name, "")
	}
}

func writeConfig(t *testing.T, directory, content string) string {
	t.Helper()
	path := filepath.Join(directory, ConfigFileName)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	clearEnvironment(t)

	cfg, err := Load(Options{Home: t.TempDir()})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}

	if cfg.Provider != DefaultProvider {
		t.Errorf("Provider = %q, want %q", cfg.Provider, DefaultProvider)
	}
	if cfg.Model != "" {
		t.Errorf("Model = %q, want empty", cfg.Model)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}
	if cfg.LogFormat != DefaultLogFormat {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, DefaultLogFormat)
	}
	if cfg.FilePath != "" {
		t.Errorf("FilePath = %q, want empty", cfg.FilePath)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("RequestTimeout = %s, want %s", cfg.RequestTimeout, DefaultRequestTimeout)
	}
}

func TestLoadFromEnvironment(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("HEIMDALL_PROVIDER", " OPENCODE ")
	t.Setenv("HEIMDALL_MODEL", " test-model ")
	t.Setenv("HEIMDALL_LOG_LEVEL", "DEBUG")
	t.Setenv("HEIMDALL_LOG_FORMAT", "json")
	t.Setenv("HEIMDALL_REQUEST_TIMEOUT", "45s")
	t.Setenv("OPENCODE_API_KEY", " test-key ")

	cfg, err := Load(Options{Home: t.TempDir()})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}

	if cfg.Provider != ProviderOpenCode {
		t.Errorf("Provider = %q, want %q", cfg.Provider, ProviderOpenCode)
	}
	if cfg.Model != "test-model" {
		t.Errorf("Model = %q, want test-model", cfg.Model)
	}
	if cfg.APIKey != "test-key" {
		t.Errorf("APIKey = %q, want test-key", cfg.APIKey)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want json", cfg.LogFormat)
	}
	if cfg.RequestTimeout != 45*time.Second {
		t.Errorf("RequestTimeout = %s, want 45s", cfg.RequestTimeout)
	}
}

func TestLoadFromConfigFile(t *testing.T) {
	clearEnvironment(t)
	home := t.TempDir()
	path := writeConfig(t, home, `
provider: opencode
model: file-model
log_level: warn
log_format: json
request_timeout: 30s
`)

	cfg, err := Load(Options{Home: home})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}

	if cfg.Provider != ProviderOpenCode {
		t.Errorf("Provider = %q, want %q", cfg.Provider, ProviderOpenCode)
	}
	if cfg.Model != "file-model" {
		t.Errorf("Model = %q, want file-model", cfg.Model)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", cfg.LogLevel)
	}
	if cfg.RequestTimeout != 30*time.Second {
		t.Errorf("RequestTimeout = %s, want 30s", cfg.RequestTimeout)
	}
	if cfg.FilePath != path {
		t.Errorf("FilePath = %q, want %q", cfg.FilePath, path)
	}
}

func TestLoadPrecedence(t *testing.T) {
	clearEnvironment(t)
	home := t.TempDir()
	writeConfig(t, home, `
provider: openai
model: file-model
log_level: warn
request_timeout: 30s
`)
	t.Setenv("HEIMDALL_PROVIDER", "opencode")
	t.Setenv("HEIMDALL_MODEL", "environment-model")
	t.Setenv("HEIMDALL_LOG_LEVEL", "error")
	t.Setenv("HEIMDALL_REQUEST_TIMEOUT", "45s")

	cfg, err := Load(Options{
		Home:           home,
		Provider:       "openai",
		Model:          "flag-model",
		LogLevel:       "debug",
		LogFormat:      "json",
		RequestTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}

	if cfg.Provider != ProviderOpenAI {
		t.Errorf("Provider = %q, want flag override openai", cfg.Provider)
	}
	if cfg.Model != "flag-model" {
		t.Errorf("Model = %q, want flag override flag-model", cfg.Model)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want flag override debug", cfg.LogLevel)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want flag override json", cfg.LogFormat)
	}
	if cfg.RequestTimeout != 15*time.Second {
		t.Errorf("RequestTimeout = %s, want flag override 15s", cfg.RequestTimeout)
	}
}

func TestLoadExplicitConfigFile(t *testing.T) {
	clearEnvironment(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "custom.yaml")
	if err := os.WriteFile(path, []byte("model: custom-model\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(Options{Home: t.TempDir(), ConfigFile: path})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if cfg.Model != "custom-model" {
		t.Errorf("Model = %q, want custom-model", cfg.Model)
	}
}

func TestLoadMissingExplicitConfigFile(t *testing.T) {
	clearEnvironment(t)

	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := Load(Options{ConfigFile: missing}); err == nil {
		t.Fatal("expected an error for a missing explicit config file")
	}
}

func TestLoadMalformedConfigFile(t *testing.T) {
	clearEnvironment(t)
	home := t.TempDir()
	writeConfig(t, home, "provider: [unterminated\n")

	if _, err := Load(Options{Home: home}); err == nil {
		t.Fatal("expected an error for a malformed config file")
	}
}

func TestLoadRejectsUnsupportedValues(t *testing.T) {
	clearEnvironment(t)
	tests := []struct {
		name    string
		options Options
		env     map[string]string
		want    string
	}{
		{name: "provider", options: Options{Provider: "anthropic"}, want: "unsupported provider"},
		{name: "log level", options: Options{LogLevel: "verbose"}, want: "unsupported log level"},
		{name: "log format", options: Options{LogFormat: "xml"}, want: "unsupported log format"},
		{
			name:    "environment log level",
			options: Options{},
			env:     map[string]string{"HEIMDALL_LOG_LEVEL": "trace"},
			want:    "unsupported log level",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			options := test.options
			options.Home = t.TempDir()
			_, err := Load(options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadRejectsInvalidRequestTimeout(t *testing.T) {
	clearEnvironment(t)
	tests := []struct {
		name    string
		options Options
		env     map[string]string
		want    string
	}{
		{name: "not a duration", options: Options{RequestTimeout: 0}, env: map[string]string{"HEIMDALL_REQUEST_TIMEOUT": "abc"}, want: "invalid request timeout"},
		{name: "below minimum", options: Options{RequestTimeout: 500 * time.Millisecond}, want: "must be between"},
		{name: "above maximum", options: Options{RequestTimeout: 11 * time.Minute}, want: "must be between"},
		{name: "without unit", options: Options{}, env: map[string]string{"HEIMDALL_REQUEST_TIMEOUT": "30"}, want: "invalid request timeout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			options := test.options
			options.Home = t.TempDir()
			_, err := Load(options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestWithOverrides(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("OPENCODE_API_KEY", "opencode-key")
	t.Setenv("OPENAI_API_KEY", "openai-key")

	base, err := Load(Options{Home: t.TempDir()})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}

	overridden, err := base.WithOverrides(" OPENCODE ", " planner-model ")
	if err != nil {
		t.Fatalf("WithOverrides returned an error: %v", err)
	}
	if overridden.Provider != ProviderOpenCode {
		t.Errorf("Provider = %q, want %q", overridden.Provider, ProviderOpenCode)
	}
	if overridden.Model != "planner-model" {
		t.Errorf("Model = %q, want planner-model", overridden.Model)
	}
	if overridden.APIKey != "opencode-key" {
		t.Errorf("APIKey = %q, want opencode-key", overridden.APIKey)
	}

	unchanged, err := base.WithOverrides("", "")
	if err != nil {
		t.Fatalf("WithOverrides returned an error: %v", err)
	}
	if unchanged.Provider != ProviderOpenAI || unchanged.APIKey != "openai-key" {
		t.Errorf("WithOverrides with empty values changed the config: %+v", unchanged)
	}
}

func TestLoadUsesHomeEnvironmentWhenOptionIsEmpty(t *testing.T) {
	clearEnvironment(t)
	home := t.TempDir()
	writeConfig(t, home, "model: environment-home-model\n")
	t.Setenv("HEIMDALL_HOME", home)

	cfg, err := Load(Options{})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if cfg.Model != "environment-home-model" {
		t.Errorf("Model = %q, want environment-home-model", cfg.Model)
	}
}

func TestLoadWithoutHomeSkipsConfigFile(t *testing.T) {
	clearEnvironment(t)
	cfg, err := Load(Options{})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if cfg.FilePath != "" {
		t.Errorf("FilePath = %q, want empty when no home is configured", cfg.FilePath)
	}
}

func TestHomeUsesEnvironment(t *testing.T) {
	t.Setenv("HEIMDALL_HOME", " /tmp/custom-heimdall ")
	if home := Home(); home != "/tmp/custom-heimdall" {
		t.Errorf("Home() = %q, want /tmp/custom-heimdall", home)
	}
}

func TestHomeFallsBackToUserConfigDirectory(t *testing.T) {
	t.Setenv("HEIMDALL_HOME", "")
	if home := Home(); !strings.HasSuffix(home, "heimdall") {
		t.Errorf("Home() = %q, want a user config directory ending in heimdall", home)
	}
}

func TestHomeFallsBackWhenUserConfigDirectoryIsUnavailable(t *testing.T) {
	t.Setenv("HEIMDALL_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if home := Home(); home != ".heimdall" {
		t.Errorf("Home() = %q, want .heimdall", home)
	}
}

func TestHasAPIKey(t *testing.T) {
	clearEnvironment(t)
	cfg, err := Load(Options{Home: t.TempDir()})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if cfg.HasAPIKey() {
		t.Error("HasAPIKey() = true, want false without OPENAI_API_KEY")
	}

	t.Setenv("OPENAI_API_KEY", "openai-key")
	cfg, err = Load(Options{Home: t.TempDir()})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if !cfg.HasAPIKey() {
		t.Error("HasAPIKey() = false, want true with OPENAI_API_KEY")
	}

	if apiKey("unsupported") != "" {
		t.Error("apiKey for an unsupported provider should be empty")
	}
}

func TestWithOverridesRejectsUnsupportedProvider(t *testing.T) {
	clearEnvironment(t)
	base, err := Load(Options{Home: t.TempDir()})
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if _, err := base.WithOverrides("anthropic", "model"); err == nil {
		t.Fatal("expected an error for an unsupported provider override")
	}
}

func TestLoadRejectsConfigFileDirectory(t *testing.T) {
	clearEnvironment(t)
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ConfigFileName), 0o700); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	if _, err := Load(Options{Home: home}); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("Load error = %v, want config file is a directory", err)
	}
}
