package recon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestNmapCollectorUsesOnlyAuthorizedPortsWithConnectScan(t *testing.T) {
	t.Setenv("HEIMDALL_NMAP", "")
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{
		{Type: assessment.ScopeWildcardDomain, Value: "*.example.com", Ports: []uint16{443}},
		{Effect: assessment.ScopeExclude, Type: assessment.ScopeDomain, Value: "admin.example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const scanArgs = "-sT -Pn --max-retries 1 --max-rate 5 --max-parallelism 1 --host-timeout 120s -p 443 -oX - api.example.com"
	runner := &fakeCommandRunner{outputs: map[string][]byte{
		"--version": []byte("Nmap version 7.test"),
		scanArgs: []byte(`<?xml version="1.0"?>
<nmaprun><host><status state="up"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host></nmaprun>`),
	}}
	collector := NmapCollector{
		Runner: runner,
		Resolve: func(binary string) (string, error) {
			if binary == "nmap" {
				return "/tools/nmap", nil
			}
			return "", errors.New("missing")
		},
	}
	collection, err := collector.Collect(context.Background(), StageRequest{
		Program: assessment.Program{Scope: scope},
		Targets: []string{"api.example.com", "admin.example.com", "outside.test"},
		Limits:  DefaultStageLimits(StageNmap),
	})
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	if len(runner.args) != 2 {
		t.Fatalf("Nmap tool call count = %d, want version + scan", len(runner.args))
	}
	args := strings.Join(runner.args[1], " ")
	if !strings.Contains(args, "-sT") || strings.Contains(args, "-sS") || strings.Contains(args, "-sV") || strings.Contains(args, "--script") {
		t.Fatalf("Nmap did not use an unprivileged connect scan: %+v", runner.args)
	}
	if !strings.Contains(args, "-p 443") || strings.Contains(args, "admin.example.com") {
		t.Fatalf("Nmap received unauthorized targets or ports: %+v", runner.args)
	}
	if len(collection.Observations) != 1 || collection.Observations[0].Category != "service" || collection.Observations[0].StableKey != "api.example.com|tcp|443" {
		t.Fatalf("unexpected service observations: %+v", collection.Observations)
	}
}

func TestBuildNmapTargetsEnforcesPortsAndTargetCap(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{
		{Type: assessment.ScopeCIDR, Value: "192.0.2.0/30", Ports: []uint16{22}},
		{Effect: assessment.ScopeExclude, Type: assessment.ScopeIP, Value: "192.0.2.2", Ports: []uint16{22}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	targets, err := buildNmapTargets(scope, nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("got %d targets, want 3 after the exclusion: %+v", len(targets), targets)
	}
	if _, err := buildNmapTargets(scope, nil, 2); err == nil {
		t.Fatal("expected target cap to reject the CIDR")
	}
}
