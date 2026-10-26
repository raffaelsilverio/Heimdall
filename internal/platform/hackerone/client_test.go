package hackerone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestFetchSnapshotUsesReadOnlyHackerEndpoints(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, token, ok := request.BasicAuth()
		if !ok || username != "api-user" || token != "test-secret" {
			t.Errorf("request credentials = (%q, %q, %t)", username, token, ok)
		}
		if request.Method != http.MethodGet {
			t.Errorf("request method = %s, want GET", request.Method)
		}
		if request.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept header = %q", request.Header.Get("Accept"))
		}
		requests = append(requests, request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/hackers/programs/acme":
			_, _ = writer.Write([]byte(`{"data":{"id":9,"type":"program","attributes":{"handle":"acme","name":"Acme","policy":"Test policy","state":"public_mode","submission_state":"open","open_scope":false,"offers_bounties":true}}}`))
		case "/v1/hackers/programs/acme/structured_scopes":
			if request.URL.Query().Get("page[number]") != "1" || request.URL.Query().Get("page[size]") != "100" {
				t.Errorf("unexpected structured-scope pagination: %s", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`{"data":[{"id":12,"type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"https://app.example.test/admin","eligible_for_submission":true,"eligible_for_bounty":false,"instruction":"Test safely","max_severity":"high"}}],"links":{}}`))
		case "/v1/hackers/programs/acme/scope_exclusions":
			if request.URL.RawQuery != "" {
				t.Errorf("scope-exclusion endpoint received undocumented query parameters: %s", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`{"data":[{"id":"ex-1","type":"scope-exclusion","attributes":{"category":"Denial of Service","details":"No load testing"}}],"links":{}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, err := NewClient("api-user", "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = server.URL
	client.http = server.Client()
	client.pageDelay = 0

	snapshot, err := client.FetchSnapshot(context.Background(), "https://hackerone.com/acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 3 {
		t.Fatalf("made %d API requests, want program, scopes, exclusions: %v", len(requests), requests)
	}
	if snapshot.SourceData.Program.Handle != "acme" || snapshot.SourceData.Program.Policy != "Test policy" {
		t.Fatalf("program metadata not captured: %+v", snapshot.SourceData.Program)
	}
	if len(snapshot.SourceData.StructuredScopes) != 1 || snapshot.SourceData.StructuredScopes[0].ID != "12" {
		t.Fatalf("unexpected structured scopes: %+v", snapshot.SourceData.StructuredScopes)
	}
	if snapshot.Scope == nil || len(snapshot.Scope.Entries) != 1 || snapshot.Scope.Entries[0].Type != assessment.ScopeURL {
		t.Fatalf("URL scope was not converted: %+v", snapshot.Scope)
	}
	if len(snapshot.SourceData.ScopeExclusions) != 1 || len(snapshot.Blockers) != 0 {
		t.Fatalf("unexpected scope-exclusion conversion: exclusions=%+v blockers=%v", snapshot.SourceData.ScopeExclusions, snapshot.Blockers)
	}
	if len(snapshot.Warnings) == 0 || !strings.Contains(snapshot.Warnings[0], "report-category") {
		t.Fatalf("scope-exclusion distinction was not documented in snapshot notes: %v", snapshot.Warnings)
	}
	if snapshot.SourceData.StructuredScopes[0].EligibleForBounty == nil || *snapshot.SourceData.StructuredScopes[0].EligibleForBounty {
		t.Fatal("bounty eligibility was not preserved")
	}
}

func TestFetchSnapshotPaginatesStructuredScopes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/hackers/programs/acme":
			_, _ = writer.Write([]byte(`{"data":{"attributes":{"handle":"acme","name":"Acme","open_scope":false}}}`))
		case "/v1/hackers/programs/acme/structured_scopes":
			if request.URL.Query().Get("page[number]") == "1" {
				records := make([]map[string]any, pageSize)
				for index := range records {
					records[index] = map[string]any{"id": index + 1, "attributes": map[string]any{
						"asset_type": "DOMAIN", "asset_identifier": fmt.Sprintf("host-%d.example.test", index), "eligible_for_submission": true,
					}}
				}
				_ = json.NewEncoder(writer).Encode(map[string]any{"data": records})
				return
			}
			_, _ = writer.Write([]byte(`{"data":[],"links":{}}`))
		case "/v1/hackers/programs/acme/scope_exclusions":
			_, _ = writer.Write([]byte(`{"data":[],"links":{}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, _ := NewClient("user", "token")
	client.baseURL = server.URL
	client.http = server.Client()
	client.pageDelay = 0
	snapshot, err := client.FetchSnapshot(context.Background(), "https://hackerone.com/acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.SourceData.StructuredScopes) != pageSize {
		t.Fatalf("fetched %d structured scopes, want %d", len(snapshot.SourceData.StructuredScopes), pageSize)
	}
	if snapshot.Scope == nil || len(snapshot.Scope.Entries) != pageSize {
		t.Fatalf("candidate has %d entries, want %d", scopeEntryCount(snapshot.Scope), pageSize)
	}
}

func TestBuildSnapshotBlocksIncompleteOrUnrepresentableScope(t *testing.T) {
	openScope := true
	eligible := true
	snapshot := buildSnapshot(SourceData{
		SchemaVersion: 1,
		Program:       ProgramSource{Handle: "acme", OpenScope: &openScope},
		StructuredScopes: []StructuredScope{
			{ID: "1", AssetType: "DOMAIN", AssetIdentifier: "example.test", EligibleForSubmission: &eligible},
			{ID: "2", AssetType: "ANDROID", AssetIdentifier: "com.example.app", EligibleForSubmission: &eligible},
		},
	})
	if snapshot.Scope == nil {
		t.Fatal("representable finite assets should still be available as a partial candidate")
	}
	if len(snapshot.Blockers) != 2 {
		t.Fatalf("blockers = %v, want open-scope and unsupported-asset blockers", snapshot.Blockers)
	}
}

func TestProgramHandleAndURLScopeRejectAmbiguousInputs(t *testing.T) {
	for _, sourceURL := range []string{
		"https://attacker.example/acme",
		"https://hackerone.com/acme/extra",
		"https://hackerone.com/acme?next=https://attacker.example",
		"https://hackerone.com:444/acme",
		"https://hackerone.com/acme?",
		"https://hackerone.com/%2Facme",
		"http://hackerone.com/acme",
	} {
		if _, err := programHandle(sourceURL); err == nil {
			t.Errorf("programHandle(%q) unexpectedly succeeded", sourceURL)
		}
	}

	for _, value := range []string{"https://example.test/admin?q=1", "example.test", "https://*.example.test"} {
		if _, _, err := mapAsset(StructuredScope{AssetType: "URL", AssetIdentifier: value}); err == nil {
			t.Errorf("mapAsset accepted ambiguous URL %q", value)
		}
	}
}

type responseCloseFailureRoundTripper struct {
	body io.ReadCloser
}

func (transport responseCloseFailureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       transport.body,
		Request:    request,
	}, nil
}

type responseCloseFailureBody struct {
	reader *strings.Reader
	err    error
}

func (body *responseCloseFailureBody) Read(data []byte) (int, error) { return body.reader.Read(data) }
func (body *responseCloseFailureBody) Close() error                  { return body.err }

func TestGetJSONReturnsResponseBodyCloseError(t *testing.T) {
	closeErr := errors.New("simulated response close failure")
	client, err := NewClient("api-user", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = "https://api.hackerone.com"
	client.http = &http.Client{Transport: responseCloseFailureRoundTripper{body: &responseCloseFailureBody{
		reader: strings.NewReader(`{"data":{}}`),
		err:    closeErr,
	}}}
	var destination map[string]any
	err = client.getJSON(context.Background(), "/v1/test", nil, &destination)
	if !errors.Is(err, closeErr) {
		t.Fatalf("getJSON error = %v, want response-body close error", err)
	}
}

func TestAPIErrorsDoNotExposeCredentialsOrResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte("response leaked test-secret"))
	}))
	defer server.Close()
	client, _ := NewClient("api-user", "test-secret")
	client.baseURL = server.URL
	client.http = server.Client()
	var response map[string]any
	err := client.getJSON(context.Background(), "/v1/hackers/programs/acme", url.Values{}, &response)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("unexpected API error: %v", err)
	}
	if strings.Contains(err.Error(), "test-secret") || strings.Contains(err.Error(), "response leaked") {
		t.Fatalf("API error leaked credentials or response body: %v", err)
	}
}

func scopeEntryCount(scope *assessment.Scope) int {
	if scope == nil {
		return 0
	}
	return len(scope.Entries)
}
