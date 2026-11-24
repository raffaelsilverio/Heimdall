package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func executeCommandInput(t *testing.T, home, input string, args ...string) (string, error) {
	t.Helper()
	root := NewRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetIn(strings.NewReader(input))
	root.SetArgs(append([]string{"--home", home}, args...))
	err := root.Execute()
	return output.String(), err
}

func extractScopeHash(t *testing.T, output string) string {
	t.Helper()
	const marker = "Scope hash: "
	index := strings.Index(output, marker)
	if index < 0 {
		t.Fatalf("output omitted the scope hash: %s", output)
	}
	return strings.Fields(strings.TrimSpace(output[index+len(marker):]))[0]
}

func extractApprovalID(t *testing.T, output string) string {
	t.Helper()
	const marker = "Requested approval "
	index := strings.Index(output, marker)
	if index < 0 {
		t.Fatalf("output omitted the approval id: %s", output)
	}
	return strings.Fields(strings.TrimSpace(output[index+len(marker):]))[0]
}

func TestAgentApprovalsRequestApproveDenyRoundTrip(t *testing.T) {
	home := t.TempDir()
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	created := executeCommand(t, home, "program", "add", "Approval Program",
		"--authorization-ref", "internal:approval-cli", "--expires-at", expires,
		"--url", "https://app.example.test/", "--timezone", "UTC")
	programID := extractProgramID(t, created)
	executeCommand(t, home, "program", "activate", programID)
	executeCommand(t, home, "schedule", "set", programID, "--stage", "web", "--cron", "* * * * *", "--timezone", "UTC")
	program := executeCommand(t, home, "program", "show", programID)
	scopeHash := extractScopeHash(t, program)

	executeCommand(t, home, "program", "policy", "set", programID,
		"--allow-stage", "web", "--allow-class", "safe_active", "--require-approval-class", "safe_active",
		"--max-actions-per-run", "2", "--max-requests-per-run", "4",
		"--max-requests-per-action", "1", "--max-targets-per-action", "2")
	policy := executeCommand(t, home, "program", "policy", "show", programID)
	if !strings.Contains(policy, "APPROVAL REQUIRED CLASSES") || !strings.Contains(policy, "safe_active") {
		t.Fatalf("policy output omitted the approval rule: %s", policy)
	}

	plan := func(target string) string {
		return fmt.Sprintf(`{"actions":[{"stage":"web","tool":"native_http_probe","scope_hash":%q,"targets":[%q],"estimated_calls":1}]}`,
			scopeHash, target)
	}
	requested, err := executeCommandInput(t, home, plan("https://app.example.test/login"),
		"agent", "approvals", "request", programID, "--by", "operator")
	if err != nil {
		t.Fatalf("request failed: %v\n%s", err, requested)
	}
	approvalID := extractApprovalID(t, requested)
	if !strings.Contains(requested, "expires") || !strings.Contains(requested, "fingerprint") {
		t.Fatalf("request output omitted audit details: %s", requested)
	}
	listed := executeCommand(t, home, "agent", "approvals", "list", programID)
	if !strings.Contains(listed, approvalID) || !strings.Contains(listed, "pending") {
		t.Fatalf("requested approval is not pending: %s", listed)
	}

	approved := executeCommand(t, home, "agent", "approvals", "approve", programID, approvalID, "--by", "reviewer", "--note", "reviewed")
	if !strings.Contains(approved, "is now approved") {
		t.Fatalf("approve output = %s", approved)
	}
	listed = executeCommand(t, home, "agent", "approvals", "list", programID)
	if !strings.Contains(listed, approvalID) || !strings.Contains(listed, "approved") {
		t.Fatalf("approved state was not persisted: %s", listed)
	}

	planned, err := executeCommandInput(t, home, plan("https://app.example.test/login"), "agent", "plan", programID)
	if err != nil {
		t.Fatalf("plan with an approval failed: %v\n%s", err, planned)
	}
	if !strings.Contains(planned, `"decision": "ALLOW"`) || !strings.Contains(planned, approvalID) {
		t.Fatalf("plan did not use the exact approval: %s", planned)
	}

	second, err := executeCommandInput(t, home, plan("https://app.example.test/other"),
		"agent", "approvals", "request", programID, "--by", "operator")
	if err != nil {
		t.Fatalf("second request failed: %v\n%s", err, second)
	}
	secondID := extractApprovalID(t, second)
	denied := executeCommand(t, home, "agent", "approvals", "deny", programID, secondID,
		"--by", "reviewer", "--note", "not justified")
	if !strings.Contains(denied, "is now denied") {
		t.Fatalf("deny output = %s", denied)
	}
	listed = executeCommand(t, home, "agent", "approvals", "list", programID)
	if !strings.Contains(listed, secondID) || !strings.Contains(listed, "denied") {
		t.Fatalf("denied state was not persisted: %s", listed)
	}

	executeCommand(t, home, "program", "policy", "set", programID,
		"--allow-stage", "web", "--allow-class", "safe_active",
		"--max-actions-per-run", "2", "--max-requests-per-run", "4",
		"--max-requests-per-action", "1", "--max-targets-per-action", "2")
	notNeeded, err := executeCommandInput(t, home, plan("https://app.example.test/login"),
		"agent", "approvals", "request", programID, "--by", "operator")
	if err != nil {
		t.Fatalf("request without an approval rule failed: %v\n%s", err, notNeeded)
	}
	if !strings.Contains(notNeeded, "No action requires approval") {
		t.Fatalf("approval-free request output = %s", notNeeded)
	}

	if _, err := executeCommandInput(t, home, plan("https://outside.example.test/"),
		"agent", "approvals", "request", programID, "--by", "operator"); err == nil {
		t.Fatal("out-of-scope approval request was accepted")
	}
}
