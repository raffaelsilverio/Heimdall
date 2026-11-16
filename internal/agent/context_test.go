package agent

import (
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/providers"
)

func TestFitContextWindowKeepsMessagesUnderBudget(t *testing.T) {
	messages := []providers.Message{
		{Role: "system", Content: "policy"},
		{Role: "user", Content: "first"},
		{Role: "assistant", Content: "reply"},
	}
	total := 0
	for _, message := range messages {
		total += messageSize(message)
	}

	window, err := FitContextWindow(messages, total)
	if err != nil {
		t.Fatalf("FitContextWindow returned an error: %v", err)
	}
	if window.Truncated || window.DroppedMessages != 0 || window.DroppedBytes != 0 {
		t.Fatalf("window = %+v, want no truncation", window)
	}
	if len(window.Messages) != len(messages) || window.TotalBytes != total {
		t.Fatalf("window = %+v, want the original messages and %d bytes", window, total)
	}
}

func TestFitContextWindowDropsOldestMessagesAndInsertsMarker(t *testing.T) {
	system := providers.Message{Role: "system", Content: "policy"}
	oldest := providers.Message{Role: "user", Content: strings.Repeat("a", 100)}
	recent := providers.Message{Role: "user", Content: "recent"}
	newest := providers.Message{Role: "user", Content: "newest"}
	marker := omissionMarker(1)
	budget := messageSize(system) + messageSize(recent) + messageSize(newest) + messageSize(marker)

	window, err := FitContextWindow(
		[]providers.Message{system, oldest, recent, newest}, budget,
	)
	if err != nil {
		t.Fatalf("FitContextWindow returned an error: %v", err)
	}
	if !window.Truncated || window.DroppedMessages != 1 {
		t.Fatalf("window = %+v, want one dropped message", window)
	}
	if window.DroppedBytes != messageSize(oldest) {
		t.Errorf("DroppedBytes = %d, want %d", window.DroppedBytes, messageSize(oldest))
	}
	if window.TotalBytes != budget || window.TotalBytes > budget {
		t.Errorf("TotalBytes = %d, want at most %d", window.TotalBytes, budget)
	}
	if len(window.Messages) != 4 {
		t.Fatalf("messages = %+v, want system, marker, recent, newest", window.Messages)
	}
	if window.Messages[0] != system || window.Messages[0].Role != "system" {
		t.Errorf("first message = %+v, want the system message", window.Messages[0])
	}
	if window.Messages[1].Role != "system" || !strings.Contains(window.Messages[1].Content, "1 older message") {
		t.Errorf("second message = %+v, want the omission marker", window.Messages[1])
	}
	if window.Messages[2] != recent || window.Messages[3] != newest {
		t.Errorf("tail = %+v, want recent and newest messages", window.Messages[2:])
	}
}

func TestFitContextWindowPreservesInterleavedSystemMessages(t *testing.T) {
	firstSystem := providers.Message{Role: "system", Content: "policy one"}
	oldest := providers.Message{Role: "user", Content: strings.Repeat("x", 200)}
	secondSystem := providers.Message{Role: "system", Content: "policy two"}
	newest := providers.Message{Role: "user", Content: "newest"}
	marker := omissionMarker(1)
	budget := messageSize(firstSystem) + messageSize(secondSystem) + messageSize(newest) + messageSize(marker)

	window, err := FitContextWindow(
		[]providers.Message{firstSystem, oldest, secondSystem, newest}, budget,
	)
	if err != nil {
		t.Fatalf("FitContextWindow returned an error: %v", err)
	}
	if len(window.Messages) != 4 {
		t.Fatalf("messages = %+v, want first system, marker, second system, newest", window.Messages)
	}
	if window.Messages[0] != firstSystem || window.Messages[2] != secondSystem || window.Messages[3] != newest {
		t.Fatalf("system order or newest message changed: %+v", window.Messages)
	}
}

func TestFitContextWindowRejectsOversizedNewestMessage(t *testing.T) {
	system := providers.Message{Role: "system", Content: "policy"}
	newest := providers.Message{Role: "user", Content: strings.Repeat("a", 200)}
	budget := messageSize(system) + 10

	_, err := FitContextWindow([]providers.Message{system, newest}, budget)
	if err == nil || !strings.Contains(err.Error(), "newest message requires") {
		t.Fatalf("FitContextWindow error = %v, want oversized newest message", err)
	}
}

func TestFitContextWindowRejectsOversizedSystemMessages(t *testing.T) {
	system := providers.Message{Role: "system", Content: strings.Repeat("a", 200)}
	recent := providers.Message{Role: "user", Content: "recent"}

	_, err := FitContextWindow([]providers.Message{system, recent}, messageSize(recent)+10)
	if err == nil || !strings.Contains(err.Error(), "system messages require") {
		t.Fatalf("FitContextWindow error = %v, want oversized system messages", err)
	}
}

func TestFitContextWindowCountsMarkerInBudget(t *testing.T) {
	messages := []providers.Message{
		{Role: "user", Content: strings.Repeat("a", 50)},
		{Role: "user", Content: strings.Repeat("b", 50)},
		{Role: "user", Content: strings.Repeat("c", 50)},
	}
	for budget := messageSize(messages[2]) + messageSize(omissionMarker(1)); budget < 400; budget++ {
		window, err := FitContextWindow(messages, budget)
		if err != nil {
			continue
		}
		if window.TotalBytes > budget {
			t.Fatalf("budget %d produced %d bytes", budget, window.TotalBytes)
		}
		if window.Messages[len(window.Messages)-1] != messages[2] {
			t.Fatalf("budget %d dropped the newest message: %+v", budget, window.Messages)
		}
	}
}

func TestFitContextWindowRejectsInvalidBudget(t *testing.T) {
	if _, err := FitContextWindow(nil, 0); err == nil {
		t.Fatal("expected an error for a non-positive budget")
	}
}
