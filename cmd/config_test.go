package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/config"
)

func TestRootRejectsInvalidLogLevel(t *testing.T) {
	root := NewRootCommand()
	root.SetArgs([]string{"--log-level", "verbose", "tools", "list"})

	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unsupported log level") {
		t.Fatalf("Execute error = %v, want unsupported log level", err)
	}
}

func TestRootRejectsMissingConfigFile(t *testing.T) {
	root := NewRootCommand()
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	root.SetArgs([]string{"--config", missing, "tools", "list"})

	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("Execute error = %v, want missing config file error", err)
	}
}

func TestRootReadsConfigFileFromHome(t *testing.T) {
	t.Setenv("HEIMDALL_PROVIDER", "")
	home := t.TempDir()
	content := []byte("provider: unsupported\n")
	if err := os.WriteFile(filepath.Join(home, config.ConfigFileName), content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	root := NewRootCommand()
	root.SetArgs([]string{"--home", home, "tools", "list"})

	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unsupported provider") {
		t.Fatalf("Execute error = %v, want config file provider error", err)
	}
}
