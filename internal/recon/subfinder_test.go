package recon

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

type fakeCommandRunner struct {
	outputs map[string][]byte
	args    [][]string
	inputs  [][]byte
}

func (r *fakeCommandRunner) Run(_ context.Context, executable string, args ...string) ([]byte, []byte, error) {
	r.args = append(r.args, append([]string{executable}, args...))
	return r.outputs[strings.Join(args, " ")], nil, nil
}

func (r *fakeCommandRunner) RunWithInput(ctx context.Context, executable string, input []byte, args ...string) ([]byte, []byte, error) {
	r.inputs = append(r.inputs, append([]byte(nil), input...))
	return r.Run(ctx, executable, args...)
}

func TestSubfinderAdapterParsesAndScopeFilters(t *testing.T) {
	runner := &fakeCommandRunner{outputs: map[string][]byte{
		"-d example.com -silent -oJ -cs -duc -rl 2 -max-time 20": []byte(`{"host":"www.example.com","sources":["crtsh"]}
{"host":"admin.example.com"}
{"host":"example.com.evil.test"}
		`),
	}}
	program := assessment.Program{
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{
			{Effect: assessment.ScopeInclude, Type: assessment.ScopeWildcardDomain, Value: "example.com"},
			{Effect: assessment.ScopeExclude, Type: assessment.ScopeDomain, Value: "admin.example.com"},
		}},
	}
	observations, artifacts, err := (SubfinderAdapter{}).Collect(context.Background(), program, "subfinder", runner, DefaultStageLimits(StageOSINT))
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	if len(observations) != 1 || observations[0].StableKey != "www.example.com" {
		t.Fatalf("unexpected observations: %+v", observations)
	}
	if observations[0].Source != "subfinder" {
		t.Errorf("observation source was not recorded: %q", observations[0].Source)
	}
	if len(artifacts) != 1 || !strings.Contains(string(artifacts[0].Data), "crtsh") {
		t.Errorf("sanitized artifact did not preserve source provenance: %+v", artifacts)
	}
}

func TestParseSubfinderOutputRejectsMalformedJSON(t *testing.T) {
	_, _, err := parseSubfinderOutput([]byte("not-json\n"), assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "example.com",
	}}})
	if err == nil {
		t.Fatal("expected malformed JSON output to fail")
	}
}

func TestSafeToolEnvironmentDoesNotInheritAPIKeys(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "must-not-leak")
	environment := strings.Join(safeToolEnvironment(), "\n")
	if strings.Contains(environment, "OPENAI_API_KEY") || strings.Contains(environment, "must-not-leak") {
		t.Fatal("tool environment inherited an API secret")
	}
	if home, err := os.UserHomeDir(); err == nil && !strings.Contains(environment, "HOME="+home) {
		t.Error("tool environment should include HOME for user-managed tool configuration")
	}
}

func TestLimitedBufferCapsMemoryWithoutBreakingWriterContract(t *testing.T) {
	buffer := &limitedBuffer{limit: 3}
	written, err := buffer.Write([]byte("excess"))
	if err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}
	if written != len("excess") {
		t.Fatalf("Write reported %d bytes, want %d", written, len("excess"))
	}
	if string(buffer.Bytes()) != "exc" || !buffer.exceeded {
		t.Fatalf("output was not safely capped: %q, exceeded=%t", buffer.Bytes(), buffer.exceeded)
	}
}

func TestAmassOutputIsPassiveScopeFilteredAndSanitized(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{
		{Type: assessment.ScopeWildcardDomain, Value: "*.example.com"},
		{Effect: assessment.ScopeExclude, Type: assessment.ScopeDomain, Value: "admin.example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	output := []byte("www.example.com (FQDN) --> node\nadmin.example.com (FQDN) --> node\nevil.example.net (FQDN) --> node\n")
	observations, artifact, err := parseAmassOutput(output, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].StableKey != "www.example.com" {
		t.Fatalf("unexpected observations: %+v", observations)
	}
	if strings.Contains(string(artifact), "admin.example.com") || strings.Contains(string(artifact), "evil.example.net") {
		t.Fatalf("artifact retained out-of-scope results: %s", artifact)
	}
}

func TestGauOutputRemovesQuerySecretsAndAppliesURLPathScope(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{{
		Type: assessment.ScopeURL, Value: "https://example.com/app",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	output := []byte("https://example.com/app?token=secret\nhttps://example.com/application\nhttps://out-of-scope.test/app\n")
	observations, artifact, err := parseGauOutput(output, scope, make(map[string]struct{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Value != "https://example.com/app" {
		t.Fatalf("unexpected observations: %+v", observations)
	}
	if strings.Contains(string(artifact), "secret") || strings.Contains(string(artifact), "out-of-scope") {
		t.Fatalf("artifact retained query secrets or out-of-scope URL: %s", artifact)
	}
}

func TestRegistrySkipsMissingToolsAndVersionsTheProfile(t *testing.T) {
	t.Setenv("HEIMDALL_SUBFINDER", "")
	t.Setenv("HEIMDALL_GAU", "")
	program := assessment.Program{Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "example.com",
	}}}}
	runner := &fakeCommandRunner{outputs: map[string][]byte{
		"-version": []byte("subfinder vtest"),
		"-d example.com -silent -oJ -cs -duc -rl 2 -max-time 20": []byte(`{"host":"example.com"}` + "\n"),
	}}
	registry := Registry{
		Adapters: []ToolAdapter{SubfinderAdapter{}, GauAdapter{}},
		Runner:   runner,
		Resolve: func(binary string) (string, error) {
			if binary == "subfinder" {
				return "/tools/subfinder", nil
			}
			return "", errors.New("not installed")
		},
		Enabled: map[string]bool{"subfinder": true, "gau": true},
	}
	collection, err := registry.Collect(context.Background(), program)
	if err != nil {
		t.Fatal(err)
	}
	if collection.ProfileVersion == ProfileOSINTVersion || !strings.Contains(collection.ProfileVersion, "osint-v2") {
		t.Fatalf("profile version did not include the installed tool set: %q", collection.ProfileVersion)
	}
	if len(collection.Tools) != 2 || collection.Tools[0].Status != "missing" || collection.Tools[1].Status != "complete" {
		t.Fatalf("unexpected tool results: %+v", collection.Tools)
	}
	if len(collection.Observations) != 1 || collection.Observations[0].ToolVersion != "subfinder vtest" {
		t.Fatalf("tool version was not attached to observations: %+v", collection.Observations)
	}
}
