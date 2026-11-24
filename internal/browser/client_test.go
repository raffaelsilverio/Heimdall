package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef"

var testSessionID = "11111111-1111-4111-8111-111111111111"

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(Config{BaseURL: server.URL, Token: testToken})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func requireAuthorization(t *testing.T, request *http.Request) {
	t.Helper()
	if got := request.Header.Get("Authorization"); got != "Bearer "+testToken {
		t.Errorf("Authorization header = %q, want the bearer token", got)
	}
}

func writeJSON(t *testing.T, response http.ResponseWriter, payload any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(payload); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func testSession() Session {
	return Session{
		ID:             testSessionID,
		ProgramID:      "program-1",
		TestAccountID:  "account-1",
		ScopeHash:      strings.Repeat("a", 64),
		PolicyRevision: 3,
		CreatedAt:      time.Now().UTC().Truncate(time.Second),
	}
}

func testRequest() SessionRequest {
	session := testSession()
	return SessionRequest{
		ProgramID:      session.ProgramID,
		TestAccountID:  session.TestAccountID,
		ScopeHash:      session.ScopeHash,
		PolicyRevision: session.PolicyRevision,
	}
}

func TestNewClientRejectsUnsafeConfiguration(t *testing.T) {
	cases := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{name: "valid", config: Config{BaseURL: "http://127.0.0.1:8090", Token: testToken}},
		{name: "valid ipv6", config: Config{BaseURL: "http://[::1]:8090", Token: testToken}},
		{name: "https", config: Config{BaseURL: "https://127.0.0.1:8090", Token: testToken}, wantErr: true},
		{name: "remote host", config: Config{BaseURL: "http://example.com:8090", Token: testToken}, wantErr: true},
		{name: "userinfo", config: Config{BaseURL: "http://user:pass@127.0.0.1:8090", Token: testToken}, wantErr: true},
		{name: "path", config: Config{BaseURL: "http://127.0.0.1:8090/v1", Token: testToken}, wantErr: true},
		{name: "query", config: Config{BaseURL: "http://127.0.0.1:8090?x=1", Token: testToken}, wantErr: true},
		{name: "invalid port", config: Config{BaseURL: "http://127.0.0.1:70000", Token: testToken}, wantErr: true},
		{name: "empty token", config: Config{BaseURL: "http://127.0.0.1:8090", Token: ""}, wantErr: true},
		{name: "short token", config: Config{BaseURL: "http://127.0.0.1:8090", Token: "short"}, wantErr: true},
		{name: "space token", config: Config{BaseURL: "http://127.0.0.1:8090", Token: strings.Repeat("x", 31) + " "}, wantErr: true},
		{name: "timeout too small", config: Config{BaseURL: "http://127.0.0.1:8090", Token: testToken, Timeout: 10 * time.Millisecond}, wantErr: true},
		{name: "timeout too large", config: Config{BaseURL: "http://127.0.0.1:8090", Token: testToken, Timeout: 2 * time.Minute}, wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewClient(testCase.config)
			if testCase.wantErr && err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("valid configuration was rejected: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), testCase.config.Token) && testCase.config.Token != "" {
				t.Fatal("configuration error leaked the token")
			}
		})
	}
}

func TestClientHealth(t *testing.T) {
	client := newTestClient(t, func(response http.ResponseWriter, request *http.Request) {
		requireAuthorization(t, request)
		if request.Method != http.MethodGet || request.URL.Path != "/healthz" {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		writeJSON(t, response, Health{
			Version: ProtocolVersion,
			Driver:  DriverHealth{Name: "playwright", Browser: "chromium", Available: false},
		})
	})
	health, err := client.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Version != ProtocolVersion || health.Driver.Name != "playwright" || health.Driver.Available {
		t.Fatalf("unexpected health: %+v", health)
	}
}

func TestClientRejectsWrongToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		writeJSON(t, response, map[string]any{"error": map[string]string{"code": "unauthorized"}})
	}))
	t.Cleanup(server.Close)
	otherToken := strings.Repeat("z", 40)
	client, err := NewClient(Config{BaseURL: server.URL, Token: otherToken})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Health(context.Background())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong token error = %v, want ErrUnauthorized", err)
	}
	if strings.Contains(err.Error(), otherToken) {
		t.Fatal("worker error leaked the token")
	}
}

func TestClientSessionLifecycle(t *testing.T) {
	session := testSession()
	var createdBody map[string]any
	client := newTestClient(t, func(response http.ResponseWriter, request *http.Request) {
		requireAuthorization(t, request)
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/sessions":
			if err := json.NewDecoder(request.Body).Decode(&createdBody); err != nil {
				t.Errorf("decode request body: %v", err)
			}
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, session)
		case request.Method == http.MethodGet && request.URL.Path == "/v1/sessions/"+testSessionID:
			writeJSON(t, response, session)
		case request.Method == http.MethodDelete && request.URL.Path == "/v1/sessions/"+testSessionID:
			response.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	})

	created, err := client.OpenSession(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != session.ID || created.ProgramID != session.ProgramID ||
		created.TestAccountID != session.TestAccountID || created.ScopeHash != session.ScopeHash ||
		created.PolicyRevision != session.PolicyRevision || !created.CreatedAt.Equal(session.CreatedAt) {
		t.Fatalf("created session = %+v, want %+v", created, session)
	}
	if len(createdBody) != 4 {
		t.Fatalf("request body keys = %v, want only the four identity fields", createdBody)
	}
	for _, field := range []string{"program_id", "test_account_id", "scope_hash", "policy_revision"} {
		if _, ok := createdBody[field]; !ok {
			t.Fatalf("request body omitted %s", field)
		}
	}

	fetched, err := client.Session(context.Background(), testSessionID)
	if err != nil || fetched.ID != session.ID || !fetched.CreatedAt.Equal(session.CreatedAt) {
		t.Fatalf("session = %+v, err = %v", fetched, err)
	}
	if err := client.CloseSession(context.Background(), testSessionID); err != nil {
		t.Fatal(err)
	}
}

func TestClientMapsWorkerErrors(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   error
	}{
		{status: http.StatusBadRequest, want: ErrRequestRejected},
		{status: http.StatusUnauthorized, want: ErrUnauthorized},
		{status: http.StatusForbidden, want: ErrUnauthorized},
		{status: http.StatusNotFound, want: ErrSessionNotFound},
		{status: http.StatusConflict, want: ErrSessionExists},
		{status: http.StatusTooManyRequests, want: ErrSessionLimit},
		{status: http.StatusBadGateway, want: ErrDriverFailure},
		{status: http.StatusServiceUnavailable, want: ErrDriverUnavailable},
	}
	for _, testCase := range cases {
		t.Run(fmt.Sprintf("%d", testCase.status), func(t *testing.T) {
			client := newTestClient(t, func(response http.ResponseWriter, request *http.Request) {
				requireAuthorization(t, request)
				response.WriteHeader(testCase.status)
				writeJSON(t, response, map[string]any{"error": map[string]string{"code": "worker_code"}})
			})
			_, err := client.OpenSession(context.Background(), testRequest())
			if !errors.Is(err, testCase.want) {
				t.Fatalf("status %d error = %v, want %v", testCase.status, err, testCase.want)
			}
		})
	}
}

func TestClientRejectsProtocolViolations(t *testing.T) {
	cases := []struct {
		name   string
		health bool
		body   string
	}{
		{name: "health version", health: true, body: `{"version":"2","driver":{"name":"playwright","browser":"chromium","available":false}}`},
		{name: "health unknown field", health: true, body: `{"version":"1","driver":{"name":"playwright","browser":"chromium","available":false},"extra":true}`},
		{name: "health missing driver", health: true, body: `{"version":"1"}`},
		{name: "session invalid id", body: `{"session_id":"not-a-uuid","program_id":"program-1","test_account_id":"account-1","scope_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_revision":3,"created_at":"2026-11-24T12:00:00Z"}`},
		{name: "session identity mismatch", body: `{"session_id":"11111111-1111-4111-8111-111111111111","program_id":"program-2","test_account_id":"account-1","scope_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_revision":3,"created_at":"2026-11-24T12:00:00Z"}`},
		{name: "session zero time", body: `{"session_id":"11111111-1111-4111-8111-111111111111","program_id":"program-1","test_account_id":"account-1","scope_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_revision":3,"created_at":"0001-01-01T00:00:00Z"}`},
		{name: "trailing data", health: true, body: `{"version":"1","driver":{"name":"playwright","browser":"chromium","available":false}} {}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newTestClient(t, func(response http.ResponseWriter, request *http.Request) {
				requireAuthorization(t, request)
				response.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(response, testCase.body)
			})
			var err error
			if testCase.health {
				_, err = client.Health(context.Background())
			} else {
				_, err = client.OpenSession(context.Background(), testRequest())
			}
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("protocol error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestClientRejectsOversizedResponse(t *testing.T) {
	client := newTestClient(t, func(response http.ResponseWriter, request *http.Request) {
		requireAuthorization(t, request)
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(strings.Repeat("a", MaxResponseBytes+1)))
	})
	if _, err := client.Health(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversized response error = %v, want ErrProtocol", err)
	}
}

func TestClientUnmappedErrorIsTyped(t *testing.T) {
	client := newTestClient(t, func(response http.ResponseWriter, request *http.Request) {
		requireAuthorization(t, request)
		response.WriteHeader(http.StatusInternalServerError)
		writeJSON(t, response, map[string]any{"error": map[string]string{"code": "internal_error"}})
	})
	_, err := client.Health(context.Background())
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.StatusCode != http.StatusInternalServerError || apiError.Code != "internal_error" {
		t.Fatalf("error = %v, want an APIError with status 500 and code internal_error", err)
	}
}

func TestClientValidatesRequestsBeforeNetwork(t *testing.T) {
	client := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Error("invalid request reached the worker")
	})
	invalid := []SessionRequest{
		{ProgramID: "", TestAccountID: "account-1", ScopeHash: strings.Repeat("a", 64), PolicyRevision: 1},
		{ProgramID: "program 1", TestAccountID: "account-1", ScopeHash: strings.Repeat("a", 64), PolicyRevision: 1},
		{ProgramID: "program-1", TestAccountID: "../account", ScopeHash: strings.Repeat("a", 64), PolicyRevision: 1},
		{ProgramID: "program-1", TestAccountID: "account-1", ScopeHash: strings.Repeat("A", 64), PolicyRevision: 1},
		{ProgramID: "program-1", TestAccountID: "account-1", ScopeHash: strings.Repeat("a", 64), PolicyRevision: 0},
	}
	for _, request := range invalid {
		if _, err := client.OpenSession(context.Background(), request); err == nil {
			t.Fatalf("invalid request was sent: %+v", request)
		}
	}
	for _, sessionID := range []string{"", "abc", "11111111111141118111111111111111"} {
		if _, err := client.Session(context.Background(), sessionID); err == nil {
			t.Fatalf("invalid session id %q was sent", sessionID)
		}
		if err := client.CloseSession(context.Background(), sessionID); err == nil {
			t.Fatalf("invalid session id %q was sent", sessionID)
		}
	}
}

func TestClientHonorsCancellation(t *testing.T) {
	client := newTestClient(t, func(response http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Health(ctx); err == nil {
		t.Fatal("cancelled request succeeded")
	}
}
