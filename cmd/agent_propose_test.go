package cmd

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/raffaelsilverio/Heimdall/internal/store"
)

func TestAgentProposeRequiresExplicitDataEgressConfirmation(t *testing.T) {
	for _, extra := range [][]string{nil, {"--include-memory"}, {"--tools"}} {
		root := NewRootCommand()
		args := []string{"--home", t.TempDir(), "agent", "propose", "program-id"}
		root.SetArgs(append(args, extra...))
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "--send-context") {
			t.Fatalf("proposal generation without egress confirmation returned %v", err)
		}
	}
}

func TestBoundedPlanMemoryFiltersProgramAndStaleRecords(t *testing.T) {
	memories := []store.ProgramMemory{
		{ProgramID: "other", Status: "active", Kind: "fact", Title: "foreign", Content: "must not cross programs", Confidence: 1},
		{ProgramID: "program-a", Status: "active", Kind: "fact", Title: "old scope", Content: "stale scope", ScopeStale: true, Confidence: 1},
		{ProgramID: "program-a", Status: "active", Kind: "fact", Title: "old source", Content: "stale source", SourceStale: true, Confidence: 1},
		{ProgramID: "program-a", Status: "active", Kind: "fact", Title: "pending", Content: "pending review", SourceReviewPending: true, Confidence: 1},
		{ProgramID: "program-a", Status: "archived", Kind: "fact", Title: "archived", Content: "not current", Confidence: 1},
		{ProgramID: "program-a", Status: "active", Kind: "fact", Title: "current", Content: "only this current note is eligible", Confidence: 0.8},
	}

	selected := boundedPlanMemory("program-a", memories)
	if len(selected) != 1 || selected[0].Title != "current" || !strings.Contains(selected[0].Content, "only this current") {
		t.Fatalf("memory selection leaked or retained stale notes: %+v", selected)
	}

	large := make([]store.ProgramMemory, 10)
	for index := range large {
		large[index] = store.ProgramMemory{
			ProgramID: "program-a", Status: "active", Kind: "fact", Title: "bounded",
			Content: strings.Repeat("é", 250), Confidence: 1,
		}
	}
	selected = boundedPlanMemory("program-a", large)
	if len(selected) != maxProposalMemoryItems {
		t.Fatalf("selected %d items, want the cap of %d", len(selected), maxProposalMemoryItems)
	}
	truncated := boundedPlanMemory("program-a", []store.ProgramMemory{{
		ProgramID: "program-a", Status: "active", Kind: "fact", Title: "unicode",
		Content: strings.Repeat("é", 1200), Confidence: 1,
	}})
	if len(truncated) != 1 || !utf8.ValidString(truncated[0].Content) || len(truncated[0].Content) > maxProposalMemoryContent {
		t.Fatalf("memory content was not safely bounded: selected=%d", len(truncated))
	}
}
