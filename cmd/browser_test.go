package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/browser"
)

func TestBrowserHealthCommand(t *testing.T) {
	token := strings.Repeat("t", 40)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"version":"1","driver":{"name":"playwright","browser":"chromium","available":true}}`))
	}))
	t.Cleanup(server.Close)
	t.Setenv("HEIMDALL_BROWSER_TOKEN", token)

	home := t.TempDir()
	output, err := executeCommandInput(t, home, "", "browser", "health", "--url", server.URL)
	if err != nil {
		t.Fatalf("browser health failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "Worker protocol: 1") || !strings.Contains(output, "Driver: playwright (chromium)") || !strings.Contains(output, "Available: true") {
		t.Fatalf("unexpected health output: %s", output)
	}

	output, err = executeCommandInput(t, home, "", "browser", "health", "--url", server.URL, "--json")
	if err != nil {
		t.Fatalf("browser health --json failed: %v\n%s", err, output)
	}
	var health browser.Health
	if err := json.Unmarshal([]byte(output), &health); err != nil {
		t.Fatalf("health output is not JSON: %v\n%s", err, output)
	}
	if health.Version != browser.ProtocolVersion || !health.Driver.Available {
		t.Fatalf("unexpected health: %+v", health)
	}
}

func TestBrowserHealthRequiresToken(t *testing.T) {
	t.Setenv("HEIMDALL_BROWSER_TOKEN", "")
	_, err := executeCommandInput(t, t.TempDir(), "", "browser", "health")
	if err == nil || !strings.Contains(err.Error(), "HEIMDALL_BROWSER_TOKEN") {
		t.Fatalf("missing token error = %v", err)
	}
}

func TestBrowserHealthRejectsRemoteWorker(t *testing.T) {
	t.Setenv("HEIMDALL_BROWSER_TOKEN", strings.Repeat("t", 40))
	_, err := executeCommandInput(t, t.TempDir(), "", "browser", "health", "--url", "http://example.com:8090")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("remote worker error = %v", err)
	}
}
