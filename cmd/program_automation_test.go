package cmd

import (
	"strings"
	"testing"
)

func TestProgramAutomationSetRequiresExplicitEgressAndRequestConsent(t *testing.T) {
	root := NewRootCommand()
	root.SetArgs([]string{"--home", t.TempDir(), "program", "automation", "set", "program-id"})
	if err := root.Execute(); err == nil ||
		(!strings.Contains(err.Error(), "allow-model-context-egress") && !strings.Contains(err.Error(), "allow-active-requests")) {
		t.Fatalf("automation set without explicit consent returned %v", err)
	}
}
