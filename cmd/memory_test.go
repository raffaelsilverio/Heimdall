package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMemoryCLIRequiresAndHonorsProgramScope(t *testing.T) {
	home := t.TempDir()
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	createdA := executeCommand(t, home, "program", "add", "Memory Program A",
		"--authorization-ref", "internal:memory-a", "--expires-at", expires, "--domain", "alpha.example.test")
	createdB := executeCommand(t, home, "program", "add", "Memory Program B",
		"--authorization-ref", "internal:memory-b", "--expires-at", expires, "--domain", "beta.example.test")
	programA := extractProgramID(t, createdA)
	programB := extractProgramID(t, createdB)

	root := NewRootCommand()
	var addOutput bytes.Buffer
	root.SetOut(&addOutput)
	root.SetErr(&addOutput)
	root.SetIn(strings.NewReader("Private observation from program alpha; verify the session redirect.\n"))
	root.SetArgs([]string{"--home", home, "memory", "add", programA,
		"--kind", "hypothesis", "--title", "Alpha login behavior",
		"--content-stdin", "--source-kind", "operator", "--confidence", "0.6"})
	if err := root.Execute(); err != nil {
		t.Fatalf("memory add from stdin failed: %v; output=%s", err, addOutput.String())
	}
	added := addOutput.String()
	if !strings.Contains(added, "for program "+programA) {
		t.Fatalf("memory add did not report its program scope: %s", added)
	}
	memoryID := strings.Fields(strings.TrimPrefix(strings.TrimSpace(added), "Stored hypothesis memory "))[0]

	resultsA := executeCommand(t, home, "memory", "search", programA, "session redirect")
	if !strings.Contains(resultsA, memoryID) || !strings.Contains(resultsA, "Alpha login behavior") {
		t.Fatalf("program A memory search missed its record: %s", resultsA)
	}
	resultsB := executeCommand(t, home, "memory", "search", programB, "session redirect")
	if strings.Contains(resultsB, memoryID) || strings.Contains(resultsB, "Alpha login behavior") || strings.Contains(resultsB, "Private observation") {
		t.Fatalf("program B search leaked program A memory: %s", resultsB)
	}

	wrongProgram := NewRootCommand()
	wrongProgram.SetArgs([]string{"--home", home, "memory", "show", programB, memoryID})
	if err := wrongProgram.Execute(); err == nil || !strings.Contains(err.Error(), "not found in program") {
		t.Fatalf("cross-program memory lookup returned %v", err)
	}

	archived := executeCommand(t, home, "memory", "archive", programA, memoryID)
	if !strings.Contains(archived, "Archived memory") {
		t.Fatalf("memory archive output unexpected: %s", archived)
	}
	resultsA = executeCommand(t, home, "memory", "search", programA, "session redirect")
	if strings.Contains(resultsA, memoryID) {
		t.Fatalf("archived memory remained searchable: %s", resultsA)
	}
	restored := executeCommand(t, home, "memory", "restore", programA, memoryID)
	if !strings.Contains(restored, "Restored memory") {
		t.Fatalf("memory restore output unexpected: %s", restored)
	}
	resultsA = executeCommand(t, home, "memory", "search", programA, "session redirect")
	if !strings.Contains(resultsA, memoryID) {
		t.Fatalf("restored memory did not become searchable: %s", resultsA)
	}
}

func extractProgramID(t *testing.T, output string) string {
	t.Helper()
	const marker = "ID: "
	index := strings.Index(output, marker)
	if index < 0 {
		t.Fatalf("command output omitted program id: %s", output)
	}
	return strings.Fields(strings.TrimSpace(output[index+len(marker):]))[0]
}
