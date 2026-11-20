package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestProgramRequestProfileDefaultsAndIsRevisionedPerProgram(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.November, 20, 0, 0, 0, 0, time.UTC)
	programA := createMemoryTestProgram(t, database, "Request Profile A", now)
	programB := createMemoryTestProgram(t, database, "Request Profile B", now)

	defaultProfile, err := database.GetProgramRequestProfile(ctx, programA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if defaultProfile.Revision != 1 || defaultProfile.UserAgent != assessment.DefaultRequestUserAgent ||
		len(defaultProfile.Headers) != 0 {
		t.Fatalf("new program request profile is unexpected: %+v", defaultProfile)
	}

	input := assessment.RequestProfile{
		UserAgent: "Heimdall-Test/2.0",
		Headers: []assessment.RequestHeader{
			{Name: "x-program", Value: "example"},
			{Name: "X-Bug-Bounty", Value: "researcher-one"},
		},
	}
	saved, err := database.SetProgramRequestProfile(ctx, programA.ID, input, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 2 || saved.Headers[0].Name != "X-Bug-Bounty" || saved.Headers[1].Name != "X-Program" {
		t.Fatalf("saved request profile is unexpected: %+v", saved)
	}
	unchanged, err := database.SetProgramRequestProfile(ctx, programA.ID, input, now.Add(2*time.Minute))
	if err != nil || unchanged.Revision != 2 {
		t.Fatalf("identical request profile should not create a revision: profile=%+v err=%v", unchanged, err)
	}
	other, err := database.GetProgramRequestProfile(ctx, programB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if other.Revision != 1 || other.UserAgent != assessment.DefaultRequestUserAgent || len(other.Headers) != 0 {
		t.Fatalf("program A request profile leaked into B: %+v", other)
	}

	if _, err := database.SetProgramRequestProfile(ctx, programA.ID, assessment.RequestProfile{
		Headers: []assessment.RequestHeader{{Name: "Authorization", Value: "secret"}},
	}, now.Add(3*time.Minute)); err == nil || !strings.Contains(err.Error(), "managed by the request middleware") {
		t.Fatalf("unsafe request header error = %v", err)
	}
	reset, err := database.SetProgramRequestProfile(ctx, programA.ID, assessment.RequestProfile{}, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if reset.Revision != 3 || reset.UserAgent != assessment.DefaultRequestUserAgent || len(reset.Headers) != 0 {
		t.Fatalf("reset did not restore the built-in profile: %+v", reset)
	}
}
