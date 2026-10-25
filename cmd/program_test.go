package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func executeCommand(t *testing.T, home string, args ...string) string {
	t.Helper()
	root := NewRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"--home", home}, args...))
	if err := root.Execute(); err != nil {
		t.Fatalf("command %v failed: %v\noutput: %s", args, err, output.String())
	}
	return output.String()
}

func TestProgramCommandsCreateListAndActivate(t *testing.T) {
	home := t.TempDir()
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	created := executeCommand(t, home,
		"program", "add", "Example BBP",
		"--authorization-ref", "https://example.test/program",
		"--platform", "hackerone",
		"--program-url", "https://hackerone.com/acme",
		"--expires-at", expires,
		"--domain", "example.com",
		"--port", "80",
		"--port", "443",
		"--timezone", "UTC",
	)
	if !strings.Contains(created, "Status: draft") {
		t.Fatalf("program was not created as draft: %s", created)
	}
	const idPrefix = "ID: "
	index := strings.Index(created, idPrefix)
	if index < 0 {
		t.Fatalf("created output omitted program ID: %s", created)
	}
	id := strings.Fields(strings.TrimSpace(created[index+len(idPrefix):]))[0]

	listed := executeCommand(t, home, "program", "list")
	if !strings.Contains(listed, "Example BBP") || !strings.Contains(listed, "draft") {
		t.Fatalf("program list omitted saved program: %s", listed)
	}
	activated := executeCommand(t, home, "program", "activate", id)
	if !strings.Contains(activated, "is active") {
		t.Fatalf("activation output unexpected: %s", activated)
	}
	listed = executeCommand(t, home, "program", "list")
	if !strings.Contains(listed, "active") {
		t.Fatalf("program did not become active: %s", listed)
	}
	scheduled := executeCommand(t, home, "schedule", "set", id, "--stage", "dns", "--cron", "0 5 * * 1", "--timezone", "UTC")
	if !strings.Contains(scheduled, "dns schedule updated") {
		t.Fatalf("DNS schedule was not accepted: %s", scheduled)
	}
	webScheduled := executeCommand(t, home, "schedule", "set", id, "--stage", "web", "--cron", "0 6 * * 1", "--timezone", "UTC", "--rate-limit", "1", "--max-targets", "25")
	if !strings.Contains(webScheduled, "web schedule updated") {
		t.Fatalf("web schedule was not accepted: %s", webScheduled)
	}
	shown := executeCommand(t, home, "program", "show", id)
	if !strings.Contains(shown, "80 443") || !strings.Contains(shown, "web") || !strings.Contains(shown, "RATE/S") || !strings.Contains(shown, "https://hackerone.com/acme") {
		t.Fatalf("program show omitted port policy or stage limits: %s", shown)
	}
	createdSession := executeCommand(t, home, "session", "create", id, "--title", "Web triage")
	if !strings.Contains(createdSession, "Created session") {
		t.Fatalf("session creation output unexpected: %s", createdSession)
	}
	sessionID := strings.Fields(createdSession)[2]
	sessions := executeCommand(t, home, "session", "list", id)
	if !strings.Contains(sessions, sessionID) || !strings.Contains(sessions, "interactive") {
		t.Fatalf("session list omitted created session: %s", sessions)
	}
	shownSession := executeCommand(t, home, "session", "show", sessionID)
	if !strings.Contains(shownSession, "Web triage") || !strings.Contains(shownSession, "Scope revision hash") {
		t.Fatalf("session show output unexpected: %s", shownSession)
	}
}
