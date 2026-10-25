package recon

import (
	"regexp"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestKatanaScopePatternsKeepCrawlerWithinURLPath(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{
		{Type: assessment.ScopeURL, Value: "https://example.com/app"},
		{Effect: assessment.ScopeExclude, Type: assessment.ScopeURL, Value: "https://example.com/app/private"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	targets, includePatterns, excludePatterns := katanaTargets(scope, []string{"https://example.com/app?token=secret"})
	if len(targets) != 1 || len(includePatterns) != 1 || len(excludePatterns) != 1 {
		t.Fatalf("unexpected crawl plan: targets=%v include=%v exclude=%v", targets, includePatterns, excludePatterns)
	}
	include := regexp.MustCompile(includePatterns[0])
	exclude := regexp.MustCompile(excludePatterns[0])
	if !include.MatchString("https://example.com/app/users") {
		t.Fatal("crawler scope rejected an authorized path")
	}
	if include.MatchString("https://example.com/application") {
		t.Fatal("crawler scope escaped the authorized path boundary")
	}
	if !exclude.MatchString("https://example.com/app/private/token") {
		t.Fatal("crawler out-of-scope rule did not match excluded path")
	}
}

func TestKatanaOutputIsScopeFilteredAndQueryRedacted(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{{
		Type: assessment.ScopeURL, Value: "https://example.com/app",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	output := []byte("{\"request\":{\"endpoint\":\"https://example.com/app/users?token=secret\"}}\n" +
		"{\"request\":{\"endpoint\":\"https://outside.test/app\"}}\n")
	observations, artifact, err := parseKatanaOutput(output, scope, "katana-test", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].StableKey != "https://example.com/app/users" {
		t.Fatalf("unexpected observations: %+v", observations)
	}
	if strings.Contains(string(artifact), "secret") || strings.Contains(string(artifact), "outside.test") {
		t.Fatalf("sanitized artifact retained query or out-of-scope data: %s", artifact)
	}
}
