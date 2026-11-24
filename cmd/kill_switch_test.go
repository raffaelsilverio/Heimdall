package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/store"
)

func TestKillSwitchRoundTrip(t *testing.T) {
	home := t.TempDir()
	output, err := executeCommandInput(t, home, "", "kill-switch", "status")
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "Engaged: false") || !strings.Contains(output, "Revision: 1") {
		t.Fatalf("unexpected initial state: %s", output)
	}

	if _, err := executeCommandInput(t, home, "", "kill-switch", "engage", "--by", "ops"); err == nil {
		t.Fatal("engage without a reason was accepted")
	}
	output, err = executeCommandInput(t, home, "", "kill-switch", "engage", "--by", "ops-oncall", "--reason", "contain suspicious egress")
	if err != nil {
		t.Fatalf("engage failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "Kill switch engaged: true") || !strings.Contains(output, "Revision: 2") {
		t.Fatalf("unexpected engage output: %s", output)
	}

	output, err = executeCommandInput(t, home, "", "kill-switch", "status", "--json")
	if err != nil {
		t.Fatalf("status --json failed: %v\n%s", err, output)
	}
	var state store.KillSwitchState
	if err := json.Unmarshal([]byte(output), &state); err != nil {
		t.Fatalf("status --json is not valid JSON: %v\n%s", err, output)
	}
	if !state.Engaged || state.Reason != "contain suspicious egress" || state.ChangedBy != "ops-oncall" || state.Revision != 2 || state.ChangedAt.IsZero() {
		t.Fatalf("unexpected persisted state: %+v", state)
	}

	output, err = executeCommandInput(t, home, "", "kill-switch", "release", "--by", "ops-oncall", "--reason", "root cause reviewed")
	if err != nil {
		t.Fatalf("release failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "Kill switch engaged: false") || !strings.Contains(output, "Revision: 3") {
		t.Fatalf("unexpected release output: %s", output)
	}
}
