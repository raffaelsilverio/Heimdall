package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestProgramRequestProfileRoundTripAndRejectsUnsafeHeaders(t *testing.T) {
	home := t.TempDir()
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	created := executeCommand(t, home, "program", "add", "Request Profile Program",
		"--authorization-ref", "internal:request-profile", "--expires-at", expires,
		"--domain", "app.example.test", "--port", "443", "--timezone", "UTC")
	programID := extractProgramID(t, created)

	defaults := executeCommand(t, home, "program", "request-profile", "show", programID)
	if !strings.Contains(defaults, "Heimdall/1.0") || !strings.Contains(defaults, "REVISION") ||
		!strings.Contains(defaults, "HEADERS\t(none)") {
		t.Fatalf("default request profile is unexpected: %s", defaults)
	}

	saved := executeCommand(t, home, "program", "request-profile", "set", programID,
		"--user-agent", "Heimdall-Test/2.0",
		"--header", "x-program=example",
		"--header", "X-Bug-Bounty=researcher-one")
	if !strings.Contains(saved, "revision 2") || !strings.Contains(saved, "No request was sent") {
		t.Fatalf("request profile set output is unexpected: %s", saved)
	}
	shown := executeCommand(t, home, "program", "request-profile", "show", programID)
	if !strings.Contains(shown, "Heimdall-Test/2.0") || !strings.Contains(shown, "X-Bug-Bounty") ||
		!strings.Contains(shown, "researcher-one") || !strings.Contains(shown, "X-Program") {
		t.Fatalf("saved request profile was not shown: %s", shown)
	}
	program := executeCommand(t, home, "program", "show", programID)
	if !strings.Contains(program, "Request profile: revision 2") {
		t.Fatalf("program show omitted the request profile: %s", program)
	}

	root := NewRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"--home", home, "program", "request-profile", "set", programID,
		"--header", "Authorization=secret"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "managed by the request middleware") {
		t.Fatalf("unsafe request header error = %v; output=%s", err, output.String())
	}

	reset := executeCommand(t, home, "program", "request-profile", "reset", programID)
	if !strings.Contains(reset, "revision 3") {
		t.Fatalf("request profile reset output is unexpected: %s", reset)
	}
	shown = executeCommand(t, home, "program", "request-profile", "show", programID)
	if !strings.Contains(shown, "Heimdall/1.0") || !strings.Contains(shown, "HEADERS\t(none)") {
		t.Fatalf("request profile reset did not restore defaults: %s", shown)
	}
}
