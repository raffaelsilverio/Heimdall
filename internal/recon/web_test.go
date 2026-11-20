package recon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

type webFakeRunner struct{ *fakeCommandRunner }

func (r *webFakeRunner) Run(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	return r.fakeCommandRunner.Run(ctx, executable, stripConfigArg(args)...)
}

func (r *webFakeRunner) RunWithInput(ctx context.Context, executable string, input []byte, args ...string) ([]byte, []byte, error) {
	r.inputs = append(r.inputs, append([]byte(nil), input...))
	return r.Run(ctx, executable, args...)
}

func stripConfigArg(args []string) []string {
	result := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		if args[index] == "-config" {
			index++
			continue
		}
		result = append(result, args[index])
	}
	return result
}

func TestWebCollectorRestrictsHTTPAndTLSInputsToAuthorizedURLs(t *testing.T) {
	t.Setenv("HEIMDALL_HTTPX", "")
	t.Setenv("HEIMDALL_TLSX", "")
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{{
		Type: assessment.ScopeWildcardDomain, Value: "*.example.com", Ports: []uint16{80, 443},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	const httpArgs = "-silent -json -status-code -title -tech-detect -web-server -ip -cname -ob -nfs -duc -no-color -threads 2 -rate-limit 2 -timeout 10 -H User-Agent: " + assessment.DefaultRequestUserAgent
	const tlsArgs = "-silent -json -san -cn -hash sha256 -tls-version -duc -c 2 -timeout 5 -delay 1s"
	runner := &webFakeRunner{fakeCommandRunner: &fakeCommandRunner{outputs: map[string][]byte{
		"-version": []byte("scanner vtest"),
		httpArgs: []byte(`{"url":"https://api.example.com","input":"https://api.example.com","status_code":200,"title":"API","webserver":"nginx","tech":["nginx"]}
{"url":"http://api.example.com","input":"http://api.example.com","status_code":301}
{"url":"https://outside.test","input":"https://outside.test","status_code":200}
`),
		tlsArgs: []byte(`{"host":"api.example.com","port":"443","probe_status":true,"subject_cn":"api.example.com","subject_an":["api.example.com","outside.test"],"issuer_dn":"Example CA","not_after":"2030-01-01T00:00:00Z","tls_version":"tls13","fingerprint_hash":{"sha256":"abc123"}}
`),
	}}}
	collector := WebCollector{
		Runner: runner,
		Resolve: func(binary string) (string, error) {
			if binary == "httpx" || binary == "tlsx" {
				return "/tools/" + binary, nil
			}
			return "", errors.New("missing")
		},
	}
	collection, err := collector.Collect(context.Background(), StageRequest{
		Program: assessment.Program{Scope: scope},
		Targets: []string{"api.example.com"},
		Limits:  DefaultStageLimits(StageWeb),
	})
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	if len(collection.Observations) != 3 {
		t.Fatalf("unexpected observations: %+v", collection.Observations)
	}
	for _, observation := range collection.Observations {
		if strings.Contains(observation.StableKey, "outside.test") || strings.Contains(observation.Value, "outside.test") {
			t.Fatalf("out-of-scope data was retained: %+v", observation)
		}
	}
	if len(collection.Tools) != 2 || collection.Tools[0].Status != "complete" || collection.Tools[1].Status != "complete" {
		t.Fatalf("tool provenance missing: %+v", collection.Tools)
	}
	if len(runner.inputs) != 2 || strings.Contains(string(runner.inputs[0]), "outside.test") || !strings.Contains(string(runner.inputs[1]), "https://api.example.com") {
		t.Fatalf("unexpected HTTP/TLS input targets: %q", runner.inputs)
	}
	if strings.Contains(string(collection.Artifacts[1].Data), "outside.test") {
		t.Fatalf("TLS artifact retained out-of-scope SAN: %s", collection.Artifacts[1].Data)
	}
}

func TestWebCollectorRejectsDomainsWithoutAuthorizedPorts(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{{
		Type: assessment.ScopeWildcardDomain, Value: "*.example.com",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	collector := WebCollector{}
	_, err = collector.Collect(context.Background(), StageRequest{
		Program: assessment.Program{Scope: scope},
		Targets: []string{"api.example.com"},
		Limits:  DefaultStageLimits(StageWeb),
	})
	if err == nil || !strings.Contains(err.Error(), "explicit ports") {
		t.Fatalf("expected active-target policy error, got %v", err)
	}
}
