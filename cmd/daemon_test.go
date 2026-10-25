package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDaemonOnceRunsSubfinderAndPersistsFirstBaseline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake Subfinder executable uses a POSIX shell")
	}
	toolDirectory := t.TempDir()
	fakeTool := filepath.Join(toolDirectory, "subfinder")
	contents := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'subfinder vtest'; exit 0; fi\nprintf '%s\\n' '{\"host\":\"www.example.com\"}'\n"
	if err := os.WriteFile(fakeTool, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fakeTool, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEIMDALL_SUBFINDER", fakeTool)
	t.Setenv("HEIMDALL_OSINT_TOOLS", "subfinder")

	home := t.TempDir()
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	created := executeCommand(t, home,
		"program", "add", "Daemon integration",
		"--authorization-ref", "internal:daemon-test",
		"--expires-at", expires,
		"--wildcard-domain", "*.example.com",
		"--timezone", "UTC",
	)
	const idPrefix = "ID: "
	index := strings.Index(created, idPrefix)
	if index < 0 {
		t.Fatalf("created output omitted program ID: %s", created)
	}
	programID := strings.Fields(strings.TrimSpace(created[index+len(idPrefix):]))[0]
	_ = executeCommand(t, home, "program", "activate", programID)

	output := executeCommand(t, home, "daemon", "--once")
	if !strings.Contains(output, "Processed 1 work item") {
		t.Fatalf("daemon did not process the initial run: %s", output)
	}
	events := executeCommand(t, home, "changes", "list", programID)
	if strings.Contains(events, "www.example.com") {
		t.Fatalf("initial baseline unexpectedly emitted a change: %s", events)
	}
}
