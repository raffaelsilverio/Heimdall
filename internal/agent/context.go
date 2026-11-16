package agent

import (
	"errors"
	"fmt"

	"github.com/raffaelsilverio/Heimdall/providers"
)

// ContextWindow is the result of fitting a conversation into a byte budget.
// Dropped messages are replaced by one explicit omission marker.
type ContextWindow struct {
	Messages        []providers.Message
	DroppedMessages int
	DroppedBytes    int
	TotalBytes      int
	Truncated       bool
}

const messageFramingBytes = 8

// FitContextWindow keeps every system message and the most recent messages
// that fit in maxBytes. It never silently truncates a single message: if the
// newest message or the system messages alone do not fit, it returns an error.
func FitContextWindow(messages []providers.Message, maxBytes int) (ContextWindow, error) {
	if maxBytes <= 0 {
		return ContextWindow{}, errors.New("context budget must be positive")
	}
	total := totalMessageSize(messages)
	if total <= maxBytes {
		return ContextWindow{
			Messages:   append([]providers.Message(nil), messages...),
			TotalBytes: total,
		}, nil
	}

	pinnedBytes := systemMessageSize(messages)
	if pinnedBytes > maxBytes {
		return ContextWindow{}, fmt.Errorf(
			"system messages require %d bytes but the context budget is %d", pinnedBytes, maxBytes,
		)
	}
	newest := newestNonSystemMessage(messages)
	if newest < 0 {
		return ContextWindow{}, fmt.Errorf(
			"context requires %d bytes but the budget is %d and contains no trimmable messages", total, maxBytes,
		)
	}

	keep := make([]bool, len(messages))
	used := selectRecentMessages(messages, newest, pinnedBytes, maxBytes, keep)
	if !keep[newest] {
		return ContextWindow{}, fmt.Errorf(
			"newest message requires %d bytes but only %d remain after system messages",
			messageSize(messages[newest]), maxBytes-pinnedBytes,
		)
	}
	dropped, droppedBytes := countDroppedMessages(messages, keep)
	var err error
	dropped, droppedBytes, err = reserveOmissionMarker(messages, keep, newest, used, dropped, droppedBytes, maxBytes)
	if err != nil {
		return ContextWindow{}, err
	}
	return buildContextWindow(messages, keep, dropped, droppedBytes), nil
}

func selectRecentMessages(messages []providers.Message, newest, used, maxBytes int, keep []bool) int {
	for index := newest; index >= 0; index-- {
		message := messages[index]
		if message.Role == "system" {
			continue
		}
		size := messageSize(message)
		if used+size > maxBytes {
			break
		}
		keep[index] = true
		used += size
	}
	return used
}

func reserveOmissionMarker(
	messages []providers.Message,
	keep []bool,
	newest, used, dropped, droppedBytes, maxBytes int,
) (int, int, error) {
	if dropped == 0 {
		return dropped, droppedBytes, nil
	}
	reserve := messageSize(omissionMarker(dropped))
	for used+reserve > maxBytes {
		index := oldestKeptMessage(keep, newest)
		if index < 0 {
			return dropped, droppedBytes, fmt.Errorf(
				"context cannot fit in %d bytes even after trimming older messages", maxBytes,
			)
		}
		keep[index] = false
		used -= messageSize(messages[index])
		dropped++
		droppedBytes += messageSize(messages[index])
		reserve = messageSize(omissionMarker(dropped))
	}
	return dropped, droppedBytes, nil
}

func buildContextWindow(messages []providers.Message, keep []bool, dropped, droppedBytes int) ContextWindow {
	window := ContextWindow{
		Messages:        make([]providers.Message, 0, len(messages)),
		DroppedMessages: dropped,
		DroppedBytes:    droppedBytes,
		Truncated:       dropped > 0,
	}
	markerPlaced := false
	for index, message := range messages {
		if message.Role == "system" || keep[index] {
			window.Messages = append(window.Messages, message)
			window.TotalBytes += messageSize(message)
			continue
		}
		if markerPlaced {
			continue
		}
		marker := omissionMarker(dropped)
		window.Messages = append(window.Messages, marker)
		window.TotalBytes += messageSize(marker)
		markerPlaced = true
	}
	return window
}

func countDroppedMessages(messages []providers.Message, keep []bool) (int, int) {
	dropped := 0
	droppedBytes := 0
	for index, message := range messages {
		if message.Role == "system" || keep[index] {
			continue
		}
		dropped++
		droppedBytes += messageSize(message)
	}
	return dropped, droppedBytes
}

func totalMessageSize(messages []providers.Message) int {
	total := 0
	for _, message := range messages {
		total += messageSize(message)
	}
	return total
}

func systemMessageSize(messages []providers.Message) int {
	total := 0
	for _, message := range messages {
		if message.Role == "system" {
			total += messageSize(message)
		}
	}
	return total
}

func newestNonSystemMessage(messages []providers.Message) int {
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Role != "system" {
			return index
		}
	}
	return -1
}

func oldestKeptMessage(keep []bool, newest int) int {
	for index := 0; index <= newest; index++ {
		if keep[index] && index != newest {
			return index
		}
	}
	return -1
}

func omissionMarker(dropped int) providers.Message {
	return providers.Message{
		Role: "system",
		Content: fmt.Sprintf(
			"[context trimmed: %d older message(s) omitted to stay within the context budget]", dropped,
		),
	}
}

func messageSize(message providers.Message) int {
	return len(message.Role) + len(message.Content) + messageFramingBytes
}
