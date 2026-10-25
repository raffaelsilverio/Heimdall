package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/platform/hackerone"
	"github.com/raffaelsilverio/Heimdall/internal/store"
)

type fakeHackerOneSnapshotClient struct {
	snapshot hackerone.Snapshot
	gotURL   string
}

func (f *fakeHackerOneSnapshotClient) FetchSnapshot(_ context.Context, sourceURL string) (hackerone.Snapshot, error) {
	f.gotURL = sourceURL
	return f.snapshot, nil
}

func TestHackerOneSourceCLIReviewFlow(t *testing.T) {
	home := t.TempDir()
	database, err := store.Open(context.Background(), filepath.Join(home, "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	program, err := database.CreateProgram(context.Background(), store.CreateProgramParams{
		Name:                   "HackerOne program",
		SourcePlatform:         "hackerone",
		SourceURL:              "https://hackerone.com/acme",
		AuthorizationReference: "https://hackerone.com/acme",
		ExpiresAt:              time.Now().Add(24 * time.Hour),
		Timezone:               "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Type: assessment.ScopeDomain, Value: "old.example.test",
		}}},
	}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(context.Background(), program.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	openScope := false
	client := &fakeHackerOneSnapshotClient{snapshot: hackerone.Snapshot{
		SourceData: hackerone.SourceData{
			SchemaVersion: 1,
			Program: hackerone.ProgramSource{
				Handle: "acme", Name: "Acme", Policy: "Only test authorized assets.", OpenScope: &openScope,
			},
			StructuredScopes: []hackerone.StructuredScope{{
				ID: "1", AssetType: "DOMAIN", AssetIdentifier: "new.example.test",
			}},
		},
		Scope: &assessment.Scope{Entries: []assessment.ScopeEntry{{
			Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "new.example.test",
		}}},
	}}

	root := NewRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.AddCommand(newProgramSourceSyncCommandWithFactory(func() (hackerOneSnapshotClient, error) {
		return client, nil
	}))
	root.SetArgs([]string{"--home", home, "sync", program.ID})
	if err := root.Execute(); err != nil {
		t.Fatalf("source sync command failed: %v; output=%s", err, output.String())
	}
	if client.gotURL != "https://hackerone.com/acme" || !strings.Contains(output.String(), "Status: pending") {
		t.Fatalf("unexpected source sync result: url=%q output=%s", client.gotURL, output.String())
	}

	shown := executeCommand(t, home, "program", "source", "show", program.ID)
	if !strings.Contains(shown, "Only test authorized assets") || !strings.Contains(shown, "new.example.test") {
		t.Fatalf("source show omitted stored policy or candidate: %s", shown)
	}

	activation := NewRootCommand()
	activation.SetArgs([]string{"--home", home, "program", "activate", program.ID})
	if err := activation.Execute(); err == nil || !strings.Contains(err.Error(), "pending source review") {
		t.Fatalf("activation with pending source review returned %v", err)
	}

	approved := executeCommand(t, home, "program", "source", "approve", program.ID, "--confirm-scope", "--port", "443")
	if !strings.Contains(approved, "Candidate scope applied: true") || !strings.Contains(approved, "[443]") || !strings.Contains(approved, "remains paused") {
		t.Fatalf("source approval unexpectedly changed activation state: %s", approved)
	}
	activated := executeCommand(t, home, "program", "activate", program.ID)
	if !strings.Contains(activated, "is active") {
		t.Fatalf("explicit activation after source approval failed: %s", activated)
	}
}
