package recon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func stubBinaryResolver(string) (string, error) {
	return "/usr/bin/true", nil
}

func requestProfileStageProgram(t *testing.T, scope assessment.Scope) assessment.Program {
	t.Helper()
	normalized, err := assessment.NormalizeScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	return assessment.Program{Scope: normalized}
}

func TestHTTPStageCollectorsApplyTheProgramRequestProfile(t *testing.T) {
	profile := assessment.RequestProfile{
		UserAgent: "Heimdall-Stage/2.0",
		Headers:   []assessment.RequestHeader{{Name: "X-Bug-Bounty", Value: "researcher-one"}},
	}
	t.Run("crawl", func(t *testing.T) {
		runner := &fakeCommandRunner{outputs: map[string][]byte{"-version": []byte("katana 1.0\n")}}
		request := StageRequest{
			Program: requestProfileStageProgram(t, assessment.Scope{Entries: []assessment.ScopeEntry{{
				Type: assessment.ScopeURL, Value: "https://example.com/app",
			}}}),
			Targets: []string{"https://example.com/app"}, Limits: DefaultStageLimits(StageCrawl),
			RequestProfile: profile,
		}
		collection, err := (KatanaCollector{Runner: runner, Resolve: stubBinaryResolver}).Collect(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(collection.ProfileVersion, ProfileCrawlVersion) {
			t.Fatalf("crawl profile version is unexpected: %q", collection.ProfileVersion)
		}
		assertStageProfileArgs(t, runner, "crawl")
	})
	t.Run("ffuf", func(t *testing.T) {
		wordlist := filepath.Join(t.TempDir(), "words.txt")
		if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HEIMDALL_FFUF_WORDLIST", wordlist)
		runner := &fakeCommandRunner{outputs: map[string][]byte{"-V": []byte("ffuf 2.1\n")}}
		request := StageRequest{
			Program: requestProfileStageProgram(t, assessment.Scope{Entries: []assessment.ScopeEntry{{
				Type: assessment.ScopeURL, Value: "https://example.com/app",
			}}}),
			Targets: []string{"https://example.com/app"}, Limits: DefaultStageLimits(StageFFUF),
			RequestProfile: profile,
		}
		if _, err := (FFUFCollector{Runner: runner, Resolve: stubBinaryResolver}).Collect(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		assertStageProfileArgs(t, runner, "ffuf")
	})
	t.Run("nuclei", func(t *testing.T) {
		templates := t.TempDir()
		if err := os.WriteFile(filepath.Join(templates, "safe.yaml"), []byte("id: safe\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HEIMDALL_NUCLEI_TEMPLATES", templates)
		runner := &fakeCommandRunner{outputs: map[string][]byte{"-version": []byte("nuclei 3.0\n")}}
		request := StageRequest{
			Program: requestProfileStageProgram(t, assessment.Scope{Entries: []assessment.ScopeEntry{{
				Type: assessment.ScopeDomain, Value: "example.com", Ports: []uint16{443},
			}}}),
			Targets: []string{"https://example.com"}, Limits: DefaultStageLimits(StageNuclei),
			RequestProfile: profile,
		}
		if _, err := (NucleiCollector{Runner: runner, Resolve: stubBinaryResolver}).Collect(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		assertStageProfileArgs(t, runner, "nuclei")
	})
}

func assertStageProfileArgs(t *testing.T, runner *fakeCommandRunner, stage string) {
	t.Helper()
	want := []string{"-H", "User-Agent: Heimdall-Stage/2.0", "-H", "X-Bug-Bounty: researcher-one"}
	for _, args := range runner.args {
		joined := strings.Join(args, "\x00")
		if strings.Contains(joined, strings.Join(want, "\x00")) {
			return
		}
	}
	t.Fatalf("%s stage did not receive the request profile args: %v", stage, runner.args)
}

func TestHTTPStageCollectorsRejectAnInvalidProfileBeforeRunningATool(t *testing.T) {
	invalid := assessment.RequestProfile{Headers: []assessment.RequestHeader{{Name: "Authorization", Value: "secret"}}}
	tests := []struct {
		name    string
		collect func(CommandRunner) error
	}{
		{name: "crawl", collect: func(runner CommandRunner) error {
			_, err := (KatanaCollector{Runner: runner, Resolve: stubBinaryResolver}).Collect(context.Background(), StageRequest{
				Program: requestProfileStageProgram(t, assessment.Scope{Entries: []assessment.ScopeEntry{{
					Type: assessment.ScopeURL, Value: "https://example.com/app",
				}}}),
				Targets: []string{"https://example.com/app"}, Limits: DefaultStageLimits(StageCrawl),
				RequestProfile: invalid,
			})
			return err
		}},
		{name: "ffuf", collect: func(runner CommandRunner) error {
			_, err := (FFUFCollector{Runner: runner, Resolve: stubBinaryResolver}).Collect(context.Background(), StageRequest{
				Program: requestProfileStageProgram(t, assessment.Scope{Entries: []assessment.ScopeEntry{{
					Type: assessment.ScopeURL, Value: "https://example.com/app",
				}}}),
				Targets: []string{"https://example.com/app"}, Limits: DefaultStageLimits(StageFFUF),
				RequestProfile: invalid,
			})
			return err
		}},
		{name: "nuclei", collect: func(runner CommandRunner) error {
			_, err := (NucleiCollector{Runner: runner, Resolve: stubBinaryResolver}).Collect(context.Background(), StageRequest{
				Program: requestProfileStageProgram(t, assessment.Scope{Entries: []assessment.ScopeEntry{{
					Type: assessment.ScopeDomain, Value: "example.com", Ports: []uint16{443},
				}}}),
				Targets: []string{"https://example.com"}, Limits: DefaultStageLimits(StageNuclei),
				RequestProfile: invalid,
			})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeCommandRunner{}
			err := test.collect(runner)
			if err == nil || !strings.Contains(err.Error(), "stage request profile") {
				t.Fatalf("invalid profile error = %v", err)
			}
			if len(runner.args) != 0 {
				t.Fatalf("invalid profile spawned a tool: %v", runner.args)
			}
		})
	}
}

func TestHTTPStageProfileVersionsChangeWithTheRequestProfile(t *testing.T) {
	limits := DefaultStageLimits(StageWeb)
	first, _, err := requestProfileForStage("test", assessment.RequestProfile{UserAgent: "Heimdall-A/1.0"})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := requestProfileForStage("test", assessment.RequestProfile{UserAgent: "Heimdall-B/1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if crawlProfileVersion("v1", limits, first) == crawlProfileVersion("v1", limits, second) {
		t.Fatal("crawl profile version ignored the request profile")
	}
	if ffufProfileVersion("v1", "hash", 1, limits, first) == ffufProfileVersion("v1", "hash", 1, limits, second) {
		t.Fatal("ffuf profile version ignored the request profile")
	}
	if nucleiProfileVersion("v1", "hash", 1, limits, first) == nucleiProfileVersion("v1", "hash", 1, limits, second) {
		t.Fatal("nuclei profile version ignored the request profile")
	}
}
