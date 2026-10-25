package recon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestDNSCollectorFiltersBeforeResolvingAndNormalizesRecords(t *testing.T) {
	t.Setenv("HEIMDALL_ALTERX", "")
	t.Setenv("HEIMDALL_DNSX", "")
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{
		{Type: assessment.ScopeWildcardDomain, Value: "*.example.com"},
		{Effect: assessment.ScopeExclude, Type: assessment.ScopeDomain, Value: "admin.example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const alterxArgs = "-enrich -limit 5000 -silent -duc"
	const dnsxArgs = "-silent -json -omit-raw -a -aaaa -cname -rcode noerror,nxdomain -rl 10 -t 10 -timeout 3s -duc"
	runner := &fakeCommandRunner{outputs: map[string][]byte{
		"-version": []byte("tool vtest"),
		alterxArgs: []byte("api.example.com\nadmin.example.com\noutside.example.net\n"),
		dnsxArgs: []byte(`{"host":"api.example.com","status_code":"NOERROR","a":["192.0.2.10"],"aaaa":["2001:db8::10"]}
{"host":"outside.example.net","status_code":"NOERROR","a":["192.0.2.99"]}
`),
	}}
	collector := DNSCollector{
		Runner: runner,
		Resolve: func(binary string) (string, error) {
			if binary == "alterx" || binary == "dnsx" {
				return "/tools/" + binary, nil
			}
			return "", errors.New("missing")
		},
	}
	program := assessment.Program{Scope: scope}
	collection, err := collector.Collect(context.Background(), program)
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	if len(runner.inputs) != 2 || string(runner.inputs[1]) != "api.example.com\n" {
		t.Fatalf("dnsx received out-of-scope candidates: %#v", runner.inputs)
	}
	if len(collection.Observations) != 3 {
		t.Fatalf("unexpected observations: %+v", collection.Observations)
	}
	if collection.Observations[0].Category != CategoryHostname || collection.Observations[0].StableKey != "api.example.com" {
		t.Fatalf("hostname fact missing: %+v", collection.Observations)
	}
	if !strings.Contains(collection.ProfileVersion, ProfileDNSVersion) || len(collection.Tools) != 2 || len(collection.Artifacts) != 2 {
		t.Fatalf("DNS tool provenance/profile/artifacts missing: %+v", collection)
	}
	if strings.Contains(string(collection.Artifacts[1].Data), "outside.example.net") {
		t.Fatalf("DNS artifact retained out-of-scope data: %s", collection.Artifacts[1].Data)
	}
}

func TestParseAlterxOutputRejectsOutOfScopeOnlyByFiltering(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{{
		Type: assessment.ScopeDomain, Value: "example.com",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := parseAlterxOutput([]byte("example.com\nwww.example.com\noutside.test\n"), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0] != "example.com" {
		t.Fatalf("unexpected in-scope candidates: %+v", candidates)
	}
}
