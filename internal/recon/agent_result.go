package recon

import (
	"strings"
	"time"
	"unicode/utf8"
)

const (
	agentResultMaxOutcomes     = 10_000
	agentResultMaxLogs         = 2_048
	agentResultMaxLogDetail    = 512
	agentResultMaxOutcomeLabel = 128
)

// AgentOutcome is the normalized, per-target result of one agent tool run. It
// intentionally carries no response headers or bodies.
type AgentOutcome struct {
	Target     string `json:"target"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code,omitempty"`
	Result     string `json:"result"`
}

// LogEntry is one bounded, auditable event emitted while an agent tool runs. It
// never contains request bodies, response bodies, or credentials.
type LogEntry struct {
	At     time.Time `json:"at"`
	Level  string    `json:"level"`
	Event  string    `json:"event"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// NormalizeAgentCollection returns a bounded copy of a tool collection with
// deterministic observation metadata and normalized outcome/log fields. It
// never mutates the caller's slices.
func NormalizeAgentCollection(collection Collection, now time.Time) Collection {
	now = now.UTC()
	normalized := collection
	normalized.Observations = append([]Observation(nil), collection.Observations...)
	normalized.Outcomes = append([]AgentOutcome(nil), collection.Outcomes...)
	normalized.Logs = append([]LogEntry(nil), collection.Logs...)
	normalized.Tools = append([]ToolResult(nil), collection.Tools...)

	versions := make(map[string]string, len(normalized.Tools))
	for _, tool := range normalized.Tools {
		if tool.ID != "" && tool.Version != "" {
			versions[tool.ID] = tool.Version
		}
	}
	for index := range normalized.Observations {
		observation := &normalized.Observations[index]
		if observation.ToolVersion == "" {
			observation.ToolVersion = versions[observation.Source]
		}
		if observation.ObservedAt.IsZero() {
			observation.ObservedAt = now
		}
		observation.ObservedAt = observation.ObservedAt.UTC()
	}
	normalizeAgentOutcomes(&normalized)
	normalizeAgentLogs(&normalized, now)
	return normalized
}

func normalizeAgentOutcomes(collection *Collection) {
	if len(collection.Outcomes) > agentResultMaxOutcomes {
		collection.Outcomes = collection.Outcomes[:agentResultMaxOutcomes]
	}
	for index := range collection.Outcomes {
		outcome := &collection.Outcomes[index]
		outcome.Target = truncateAgentText(outcome.Target, maxAgentToolTargetLen)
		outcome.Method = strings.ToUpper(truncateAgentText(outcome.Method, 16))
		outcome.Result = truncateAgentText(outcome.Result, agentResultMaxOutcomeLabel)
	}
}

func normalizeAgentLogs(collection *Collection, now time.Time) {
	if len(collection.Logs) > agentResultMaxLogs {
		collection.Logs = collection.Logs[:agentResultMaxLogs]
	}
	for index := range collection.Logs {
		entry := &collection.Logs[index]
		entry.Level = truncateAgentText(entry.Level, 16)
		entry.Event = truncateAgentText(entry.Event, 64)
		entry.Target = truncateAgentText(entry.Target, maxAgentToolTargetLen)
		entry.Detail = truncateAgentText(entry.Detail, agentResultMaxLogDetail)
		if entry.At.IsZero() {
			entry.At = now
		}
		entry.At = entry.At.UTC()
	}
}

func truncateAgentText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if maximum <= 0 || len(value) <= maximum {
		return value
	}
	for maximum > 0 && !utf8.RuneStart(value[maximum]) {
		maximum--
	}
	return strings.TrimSpace(value[:maximum])
}
