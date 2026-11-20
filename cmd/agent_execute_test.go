package cmd

import (
	"strings"
	"testing"
)

func TestAgentExecuteRequiresExplicitActiveRequestConfirmation(t *testing.T) {
	root := NewRootCommand()
	root.SetArgs([]string{
		"--home", t.TempDir(), "agent", "execute", "program-id",
		"--action-run-id", "00000000-0000-4000-8000-000000000001",
	})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "confirm-active-requests") {
		t.Fatalf("agent execute without active-request confirmation returned %v", err)
	}
}

func TestAgentExecuteRequiresIdempotencyRunID(t *testing.T) {
	root := NewRootCommand()
	root.SetArgs([]string{"--home", t.TempDir(), "agent", "execute", "program-id", "--confirm-active-requests"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "action-run-id") {
		t.Fatalf("agent execute without an idempotency key returned %v", err)
	}
}

func TestAgentExecuteRequiresOneNativeWebAction(t *testing.T) {
	root := NewRootCommand()
	root.SetIn(strings.NewReader(`{"actions":[{"stage":"dns","scope_hash":"scope","targets":["example.test"],"estimated_calls":1}]}`))
	root.SetArgs([]string{
		"--home", t.TempDir(), "agent", "execute", "program-id",
		"--action-run-id", "00000000-0000-4000-8000-000000000001", "--confirm-active-requests",
	})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "only support stage") {
		t.Fatalf("non-web agent action returned %v", err)
	}
}
