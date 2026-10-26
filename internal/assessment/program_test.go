package assessment

import (
	"strings"
	"testing"
)

func TestScopeAllowsHostAndExclusionsWin(t *testing.T) {
	scope, err := NormalizeScope(Scope{Entries: []ScopeEntry{
		{Effect: ScopeInclude, Type: ScopeWildcardDomain, Value: "*.example.com"},
		{Effect: ScopeExclude, Type: ScopeDomain, Value: "admin.example.com"},
	}})
	if err != nil {
		t.Fatalf("NormalizeScope returned an error: %v", err)
	}

	tests := []struct {
		host string
		want bool
	}{
		{host: "www.example.com", want: true},
		{host: "example.com", want: false},
		{host: "admin.example.com", want: false},
		{host: "notexample.com", want: false},
	}
	for _, test := range tests {
		if got := scope.AllowsHost(test.host); got != test.want {
			t.Errorf("AllowsHost(%q) = %t, want %t", test.host, got, test.want)
		}
	}
}

func TestNormalizeScopeCanonicalizesAndDeduplicates(t *testing.T) {
	scope, err := NormalizeScope(Scope{Entries: []ScopeEntry{
		{Type: ScopeDomain, Value: "Example.COM."},
		{Type: ScopeDomain, Value: "example.com"},
		{Effect: ScopeExclude, Type: ScopeCIDR, Value: "192.0.2.7/24"},
	}})
	if err != nil {
		t.Fatalf("NormalizeScope returned an error: %v", err)
	}
	if got, want := len(scope.Entries), 2; got != want {
		t.Fatalf("got %d entries, want %d", got, want)
	}
	if scope.Entries[0].Value != "192.0.2.0/24" {
		t.Errorf("CIDR was not masked: %q", scope.Entries[0].Value)
	}
	if scope.Entries[1].Value != "example.com" {
		t.Errorf("domain was not normalized: %q", scope.Entries[1].Value)
	}
}

func TestScopeFingerprintIsOrderIndependent(t *testing.T) {
	first := Scope{Entries: []ScopeEntry{
		{Type: ScopeDomain, Value: "example.com"},
		{Type: ScopeWildcardDomain, Value: "*.example.com"},
	}}
	second := Scope{Entries: []ScopeEntry{
		{Type: ScopeWildcardDomain, Value: "example.com"},
		{Type: ScopeDomain, Value: "EXAMPLE.COM."},
	}}
	firstHash, err := ScopeFingerprint(first)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := ScopeFingerprint(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatalf("scope fingerprint changed with ordering: %s != %s", firstHash, secondHash)
	}
}

func TestNormalizeScopeRequiresInclusion(t *testing.T) {
	_, err := NormalizeScope(Scope{Entries: []ScopeEntry{{Effect: ScopeExclude, Type: ScopeDomain, Value: "example.com"}}})
	if err == nil {
		t.Fatal("expected an error for a scope without inclusions")
	}
}

func TestNormalizeScopeRejectsInvalidDNSLabels(t *testing.T) {
	invalidDomains := []string{
		"-leading.example",
		"trailing-.example",
		"under_score.example",
		strings.Repeat("a", 64) + ".example",
	}
	for _, domain := range invalidDomains {
		t.Run(domain, func(t *testing.T) {
			_, err := NormalizeScope(Scope{Entries: []ScopeEntry{{
				Effect: ScopeInclude, Type: ScopeDomain, Value: domain,
			}}})
			if err == nil {
				t.Fatalf("NormalizeScope accepted invalid DNS name %q", domain)
			}
		})
	}
}

func TestAllowsURLHonorsPathPortAndExclusions(t *testing.T) {
	scope, err := NormalizeScope(Scope{Entries: []ScopeEntry{
		{Type: ScopeURL, Value: "https://example.com/app", Ports: []uint16{443}},
		{Effect: ScopeExclude, Type: ScopeURL, Value: "https://example.com/app/private"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.com/app", true},
		{"https://example.com/app/v1?token=ignored", true},
		{"https://example.com/application", false},
		{"https://example.com/app/private/key", false},
		{"https://example.com:8443/app", false},
		{"http://example.com/app", false},
	}
	for _, test := range tests {
		if got := scope.AllowsURL(test.url); got != test.want {
			t.Errorf("AllowsURL(%q) = %t, want %t", test.url, got, test.want)
		}
	}
}

func TestActiveURLsRequireExplicitPortsForDomainScopes(t *testing.T) {
	noPorts, err := NormalizeScope(Scope{Entries: []ScopeEntry{{Type: ScopeWildcardDomain, Value: "*.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if noPorts.AllowsActiveURL("https://api.example.com") {
		t.Fatal("domain scope without explicit ports authorized active HTTP")
	}
	if targets := noPorts.ActiveURLsForHost("api.example.com"); len(targets) != 0 {
		t.Fatalf("domain without ports produced active targets: %+v", targets)
	}

	withPorts, err := NormalizeScope(Scope{Entries: []ScopeEntry{{Type: ScopeWildcardDomain, Value: "*.example.com", Ports: []uint16{80, 443}}}})
	if err != nil {
		t.Fatal(err)
	}
	targets := withPorts.ActiveURLsForHost("api.example.com")
	if len(targets) != 2 || targets[0] != "http://api.example.com" || targets[1] != "https://api.example.com" {
		t.Fatalf("unexpected authorized active URLs: %+v", targets)
	}
}
