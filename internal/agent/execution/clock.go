package execution

import (
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/clock"
)

func (e Executor) now() time.Time {
	return clock.Or(e.Clock).Now()
}

func (w AgentCycleWorker) now() time.Time {
	return clock.Or(w.Clock).Now()
}

// normalizeNow keeps a caller-supplied cycle timestamp and only falls back to
// the configured clock when the caller did not provide one.
func normalizeNow(now time.Time, fallback clock.Clock) time.Time {
	if now.IsZero() {
		return clock.Or(fallback).Now()
	}
	return now.UTC()
}
