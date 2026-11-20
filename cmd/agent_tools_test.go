package cmd

import (
	"strings"
	"testing"
)

func TestAgentToolsListsOnlyTheCompiledAgentCatalog(t *testing.T) {
	home := t.TempDir()
	output := executeCommand(t, home, "agent", "tools")
	for _, expected := range []string{
		"native_http_probe", "native-http-v1", "native_tls_probe", "native-tls-v1",
		"safe_active", "compiled",
		"native_in_process_metered", "one_request_per_target",
		"http_url", "program_active_url", "yes", "targets:string_list required",
	} {
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
	for _, expected := range []string{
		`"id": "native_http_probe"`, `"version": "native-http-v1"`, `"origin": "compiled"`,
		`"id": "native_tls_probe"`, `"version": "native-tls-v1"`,
		`"isolation": "native_in_process_metered"`,
		`"scope_rule": "program_active_url"`, `"max_requests": 8`, `"max_items": 8`,
		`"autonomous": true`, `"description":`,
	} {
		if !strings.Contains(jsonOutput, expected) {
			t.Fatalf("agent tools --json output omitted %q:\n%s", expected, jsonOutput)
		}
	}
}
