package config

import "testing"

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("HEIMDALL_PROVIDER", "")
	t.Setenv("HEIMDALL_MODEL", "")
	t.Setenv("OPENAI_API_KEY", "")

	cfg, err := LoadConfig("", "")
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}

	if cfg.Provider != "openai" {
		t.Errorf("expected provider openai, got %q", cfg.Provider)
	}

	if cfg.Model != "" {
		t.Errorf("expected empty model, got %q", cfg.Model)
	}
}

func TestLoadConfigEnvironment(t *testing.T) {
	t.Setenv("HEIMDALL_PROVIDER", "openai")
	t.Setenv("HEIMDALL_MODEL", "test-model")
	t.Setenv("OPENAI_API_KEY", "test-key")

	cfg, err := LoadConfig("", "")
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}

	if cfg.Model != "test-model" {
		t.Errorf("expected model test-model, got %q", cfg.Model)
	}

	if cfg.APIKey != "test-key" {
		t.Errorf("expected configured test key, got %q", cfg.APIKey)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("HEIMDALL_PROVIDER", "openai")
	t.Setenv("HEIMDALL_MODEL", "environment-model")

	cfg, err := LoadConfig(" OPENAI ", " flag-model ")
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}

	if cfg.Provider != "openai" {
		t.Errorf("expected provider openai, got %q", cfg.Provider)
	}

	if cfg.Model != "flag-model" {
		t.Errorf("expected model flag-model, got %q", cfg.Model)
	}
}

func TestLoadConfigUnsupportedProvider(t *testing.T) {
	_, err := LoadConfig("unknown", "")
	if err == nil {
		t.Fatal("expected an error for unsupported provider")
	}
}
