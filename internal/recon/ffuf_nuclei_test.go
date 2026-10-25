package recon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestFFUFResultParserFiltersScopeAndRedactsQuery(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{{
		Type: assessment.ScopeURL, Value: "https://example.com/app",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	output := []byte(`{"url":"https://example.com/app/FUZZ?token=secret","status":200,"length":42,"words":5,"lines":2}
{"url":"https://outside.test/app/FUZZ","status":200,"length":1}
`)
	observations, artifact, err := parseFFUFOutput(output, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || !strings.Contains(observations[0].StableKey, "/app/FUZZ") {
		t.Fatalf("unexpected ffuf observations: %+v", observations)
	}
	if strings.Contains(string(artifact), "secret") || strings.Contains(string(artifact), "outside.test") {
		t.Fatalf("ffuf artifact retained query or out-of-scope data: %s", artifact)
	}
}

func TestPrepareFFUFWordlistCapsAndFingerprintsSelectedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte("admin\napi\nprivate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tempPath, digest, count, cleanup, err := prepareFFUFWordlist(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(tempPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "admin\napi\n" || count != 2 || digest == "" {
		t.Fatalf("unexpected bounded wordlist: %q count=%d digest=%q", data, count, digest)
	}
}

func TestFFUFWordlistExcludesOutOfScopePaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte("private\nusers\n../admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{
		{Type: assessment.ScopeURL, Value: "https://example.com/app"},
		{Effect: assessment.ScopeExclude, Type: assessment.ScopeURL, Value: "https://example.com/app/private"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := fuzzURL("https://example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	wordlist, _, count, cleanup, err := prepareFFUFWordlistForTarget(path, 10, target, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(wordlist)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || string(data) != "users\n" {
		t.Fatalf("out-of-scope or unsafe fuzz paths were retained: count=%d words=%q", count, data)
	}
}

func TestNucleiParserRetainsOnlyInScopeFindings(t *testing.T) {
	scope, err := assessment.NormalizeScope(assessment.Scope{Entries: []assessment.ScopeEntry{{
		Type: assessment.ScopeWildcardDomain, Value: "*.example.com", Ports: []uint16{443},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	output := []byte(`{"template-id":"http.test","matched-at":"https://api.example.com/path?token=secret","type":"http","matcher-name":"header","info":{"name":"Test Finding","severity":"medium","tags":["misconfig"]}}
{"template-id":"http.other","matched-at":"https://outside.test/","type":"http","info":{"name":"Out","severity":"low"}}
`)
	observations, artifact, err := parseNucleiOutput(output, scope, "nuclei-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Category != CategoryVulnFinding || !strings.Contains(observations[0].StableKey, "api.example.com/path") {
		t.Fatalf("unexpected Nuclei findings: %+v", observations)
	}
	if strings.Contains(string(artifact), "secret") || strings.Contains(string(artifact), "outside.test") {
		t.Fatalf("Nuclei artifact retained query or out-of-scope data: %s", artifact)
	}
}

func TestTemplateFingerprintRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "template.yaml")
	if err := os.WriteFile(template, []byte("id: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, count, err := fingerprintTemplateDirectory(root); err != nil || count != 1 {
		t.Fatalf("fingerprint template directory: count=%d err=%v", count, err)
	}
	target := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(target, []byte("id: outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked.yaml")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := fingerprintTemplateDirectory(root); err == nil {
		t.Fatal("template symlink was accepted")
	}
}
