package cmd

import (
	"strings"
	"testing"
)

func TestAgentCycleRequiresSeparatePlannerAndActiveRequestConsent(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"--action-run-id", "00000000-0000-4000-8000-000000000001", "--confirm-active-requests"}, want: "send-context"},
		{args: []string{"--action-run-id", "00000000-0000-4000-8000-000000000001", "--send-context"}, want: "confirm-active-requests"},
	}
	for _, test := range tests {
		root := NewRootCommand()
		args := []string{"--home", t.TempDir(), "agent", "cycle", "program-id"}
		root.SetArgs(append(args, test.args...))
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("agent cycle without %s consent returned %v", test.want, err)
		}
	}
}
