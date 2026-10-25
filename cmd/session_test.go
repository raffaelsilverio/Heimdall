package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/store"
)

func TestRunSessionPersistsUserTurnBeforeProviderFailure(t *testing.T) {
	t.Setenv("HEIMDALL_PROVIDER", "openai")
	t.Setenv("OPENAI_API_KEY", "")
	home := t.TempDir()
	database, err := store.Open(context.Background(), filepath.Join(home, "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	program, err := database.CreateProgram(context.Background(), store.CreateProgramParams{
		Name:                   "Session test",
		AuthorizationReference: "internal:session-test",
		ExpiresAt:              now.Add(24 * time.Hour),
		Scope:                  assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "example.com"}}},
		Timezone:               "UTC",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := database.CreateSession(context.Background(), program.ID, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"--home", home, "run", "--session", session.ID, "--prompt", "Olá", "--model", "test-model"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "API key is not configured") {
		t.Fatalf("run error = %v, want missing API key", err)
	}

	database, err = store.Open(context.Background(), filepath.Join(home, "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	messages, err := database.ListSessionMessages(context.Background(), session.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Role != "user" || messages[0].Content != "Olá" {
		t.Fatalf("user message was not persisted before provider call: %+v", messages)
	}
}
