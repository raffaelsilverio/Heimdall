package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/store"
)

func TestAgentPlanDryRunLoadsProgramPolicyAndNeverExecutes(t *testing.T) {
	home := t.TempDir()
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	created := executeCommand(t, home, "program", "add", "Policy Plan Program",
		"--authorization-ref", "internal:policy-plan", "--expires-at", expires,
		"--domain", "app.example.test", "--port", "443", "--timezone", "UTC")
	programID := extractProgramID(t, created)
	_ = executeCommand(t, home, "program", "activate", programID)
	_ = executeCommand(t, home, "schedule", "set", programID, "--stage", "web", "--cron", "* * * * *", "--timezone", "UTC")
	policyOutput := executeCommand(t, home, "program", "policy", "set", programID,
		"--allow-stage", "web", "--allow-class", "safe_active", "--max-actions-per-run", "2",
		"--max-requests-per-run", "20", "--max-requests-per-action", "10", "--max-targets-per-action", "5")
	if !strings.Contains(policyOutput, "revision 2") || !strings.Contains(policyOutput, "No agent actions were executed") {
		t.Fatalf("policy set output unexpected: %s", policyOutput)
	}

	database, err := store.Open(context.Background(), filepath.Join(home, "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	program, err := database.GetProgram(context.Background(), programID)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	runPlan := func(target string) string {
		t.Helper()
		planJSON, err := json.Marshal(map[string]any{"actions": []map[string]any{{
			"stage": "web", "scope_hash": program.ScopeHash, "targets": []string{target},
			"estimated_calls": 3, "rationale": "dry-run test proposal",
		}}})
		if err != nil {
			t.Fatal(err)
		}
		root := NewRootCommand()
		var output bytes.Buffer
		root.SetOut(&output)
		root.SetErr(&output)
		root.SetIn(bytes.NewReader(planJSON))
		root.SetArgs([]string{"--home", home, "agent", "plan", programID})
		if err := root.Execute(); err != nil {
			t.Fatalf("agent plan failed: %v; output=%s", err, output.String())
		}
		return output.String()
	}

	allowed := runPlan("https://app.example.test/login")
	if !strings.Contains(allowed, `"policy_checks_passed": true`) ||
		!strings.Contains(allowed, `"execution_available": false`) || !strings.Contains(allowed, `"executed": false`) {
		t.Fatalf("in-scope policy dry-run unexpected: %s", allowed)
	}
	denied := runPlan("https://out-of-scope.example.test/login")
	if !strings.Contains(denied, `"policy_checks_passed": false`) ||
		!strings.Contains(denied, "outside the program's active scope") || strings.Contains(denied, `"authorized_candidate"`) {
		t.Fatalf("out-of-scope plan was not rejected without grants: %s", denied)
	}
	reset := executeCommand(t, home, "program", "policy", "reset", programID)
	if !strings.Contains(reset, "deny-all") {
		t.Fatalf("policy reset did not report deny-all: %s", reset)
	}
	denied = runPlan("https://app.example.test/login")
	if !strings.Contains(denied, `"policy_checks_passed": false`) || strings.Contains(denied, `"authorized_candidate"`) {
		t.Fatalf("deny-all policy did not block the plan: %s", denied)
	}
}
