package cmd

import (
	"strings"
	"testing"
)

func TestAgentToolsListsOnlyTheCompiledAgentCatalog(t *testing.T) {
	home := t.TempDir()
	output := executeCommand(t, home, "agent", "tools")
	for _, expected := range []string{"native_http_probe", "safe_active", "one_request_per_target", "targets:string_list required"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("agent tools output omitted %q:\n%s", expected, output)
		}
	}
	for _, unexpected := range []string{"subfinder", "nmap", "nuclei"} {
		if strings.Contains(output, unexpected) {
			t.Fatalf("agent tools exposed a subprocess recon adapter %q:\n%s", unexpected, output)
		}
	}

	jsonOutput := executeCommand(t, home, "agent", "tools", "--json")
	for _, expected := range []string{`"id": "native_http_probe"`, `"max_items": 1000`, `"description":`} {
		if !strings.Contains(jsonOutput, expected) {
			t.Fatalf("agent tools --json output omitted %q:\n%s", expected, jsonOutput)
		}
	}
}
