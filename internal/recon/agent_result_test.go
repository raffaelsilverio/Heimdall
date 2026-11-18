package recon

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNormalizeAgentCollectionFillsMetadataAndBoundsSlices(t *testing.T) {
	now := time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC)
	collection := Collection{
		Observations: []Observation{{
			Category: CategoryHTTPProbe, StableKey: "https://app.example.test/",
			Value: "HEAD status=204", Source: AgentHTTPProbeID,
		}},
		Tools:    []ToolResult{{ID: AgentHTTPProbeID, Version: agentHTTPProbeVersion, Status: "complete"}},
		Outcomes: make([]AgentOutcome, agentResultMaxOutcomes+5),
		Logs:     make([]LogEntry, agentResultMaxLogs+5),
	}
	for index := range collection.Logs {
		collection.Logs[index] = LogEntry{Event: "request", Detail: strings.Repeat("a", agentResultMaxLogDetail+100)}
	}
	normalized := NormalizeAgentCollection(collection, now)
	observation := normalized.Observations[0]
	if observation.ToolVersion != agentHTTPProbeVersion || !observation.ObservedAt.Equal(now) {
		t.Fatalf("observation metadata was not normalized: %+v", observation)
	}
	if len(normalized.Outcomes) != agentResultMaxOutcomes || len(normalized.Logs) != agentResultMaxLogs {
		t.Fatalf("result slices were not bounded: outcomes=%d logs=%d", len(normalized.Outcomes), len(normalized.Logs))
	}
	for _, entry := range normalized.Logs {
		if len(entry.Detail) > agentResultMaxLogDetail || !entry.At.Equal(now) {
			t.Fatalf("log entry was not normalized: %+v", entry)
		}
	}
	if len(collection.Logs) != agentResultMaxLogs+5 {
		t.Fatal("normalization mutated the caller's log slice")
	}
}

func TestNormalizeAgentCollectionNormalizesOutcomeLabels(t *testing.T) {
	normalized := NormalizeAgentCollection(Collection{Outcomes: []AgentOutcome{{
		Target: "  https://app.example.test/  ", Method: "head", StatusCode: 204, Result: "  http_response  ",
	}}}, time.Now())
	outcome := normalized.Outcomes[0]
	if outcome.Target != "https://app.example.test/" || outcome.Method != "HEAD" || outcome.Result != "http_response" {
		t.Fatalf("outcome was not normalized: %+v", outcome)
	}
}

func TestNormalizeAgentCollectionKeepsTruncatedLogsValidUTF8(t *testing.T) {
	normalized := NormalizeAgentCollection(Collection{Logs: []LogEntry{{
		Event: "request", Detail: strings.Repeat("€", agentResultMaxLogDetail),
	}}}, time.Now())
	detail := normalized.Logs[0].Detail
	if len(detail) > agentResultMaxLogDetail || !utf8.ValidString(detail) {
		t.Fatalf("log detail was truncated inside a rune: bytes=%d valid=%t", len(detail), utf8.ValidString(detail))
	}
}
