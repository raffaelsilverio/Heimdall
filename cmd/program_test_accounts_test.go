package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestProgramDataAccessAndTestAccountsRoundTrip(t *testing.T) {
	home := t.TempDir()
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	created := executeCommand(t, home, "program", "add", "Data Access Program",
		"--authorization-ref", "internal:data-access", "--expires-at", expires,
		"--domain", "app.example.test", "--port", "443", "--timezone", "UTC")
	programID := extractProgramID(t, created)

	defaults := executeCommand(t, home, "program", "data-access", "show", programID)
	if !strings.Contains(defaults, "test_accounts_only") || !strings.Contains(defaults, "OTHER USERS' DATA") ||
		!strings.Contains(defaults, "denied") || !strings.Contains(defaults, "REVISION") {
		t.Fatalf("default data access policy is unexpected: %s", defaults)
	}
	tightened := executeCommand(t, home, "program", "data-access", "set", programID,
		"--allow-owned=false", "--allow-explicitly-authorized=true")
	if !strings.Contains(tightened, "revision 2") || !strings.Contains(tightened, "No data was accessed") {
		t.Fatalf("data access set output is unexpected: %s", tightened)
	}

	owned := executeCommand(t, home, "program", "accounts", "add", programID,
		"--id", "test-user-1", "--identity", "test-user-1@example.test", "--role", "user",
		"--credential-env", "HEIMDALL_ACCOUNT_TEST_USER_1")
	if !strings.Contains(owned, "Registered test account test-user-1") || !strings.Contains(owned, "No credential value was read or stored") {
		t.Fatalf("account registration output is unexpected: %s", owned)
	}
	explicit := executeCommand(t, home, "program", "accounts", "add", programID,
		"--id", "test-admin", "--identity", "test-admin@example.test", "--role", "administrator",
		"--source", "explicitly_authorized")
	if !strings.Contains(explicit, "test-admin") {
		t.Fatalf("explicit account registration output is unexpected: %s", explicit)
	}
	listed := executeCommand(t, home, "program", "accounts", "list", programID)
	if !hasAccountRow(listed, "test-user-1", "test-user-1@example.test", "user", "owned", "authorized",
		"env:HEIMDALL_ACCOUNT_TEST_USER_1", "no") {
		t.Fatalf("owned account should be blocked by the tightened policy: %s", listed)
	}
	if !hasAccountRow(listed, "test-admin", "test-admin@example.test", "administrator", "explicitly_authorized",
		"authorized", "(none)", "yes") {
		t.Fatalf("explicit account should remain usable: %s", listed)
	}
	program := executeCommand(t, home, "program", "show", programID)
	if !strings.Contains(program, "Data access: test_accounts_only, test accounts 2 (usable 1), other users' data denied, revision 2") {
		t.Fatalf("program show omitted the data access summary: %s", program)
	}

	root := NewRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"--home", home, "program", "accounts", "add", programID,
		"--id", "unsafe", "--identity", "unsafe@example.test", "--credential-env", "Bearer secret"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "uppercase letters") {
		t.Fatalf("unsafe credential error = %v; output=%s", err, output.String())
	}

	revoked := executeCommand(t, home, "program", "accounts", "revoke", programID, "test-admin")
	if !strings.Contains(revoked, "is now revoked") {
		t.Fatalf("account revocation output is unexpected: %s", revoked)
	}
	listed = executeCommand(t, home, "program", "accounts", "list", programID)
	if !hasAccountRow(listed, "test-admin", "test-admin@example.test", "administrator", "explicitly_authorized",
		"revoked", "(none)", "no") {
		t.Fatalf("revoked account was not reflected: %s", listed)
	}
}

func hasAccountRow(output string, id string, expected ...string) bool {
	want := strings.Join(append([]string{id}, expected...), " ")
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 0 && fields[0] == id {
			return strings.Join(fields, " ") == want
		}
	}
	return false
}
