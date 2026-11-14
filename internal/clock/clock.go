// Package clock provides an injectable time source for components that need a
// consistent notion of "now" without reaching for time.Now directly.
package clock

import "time"

// Clock reports the current time. Implementations must return UTC values.
type Clock interface {
	Now() time.Time
}

// System is the default clock backed by time.Now.
type System struct{}

// Now returns the current UTC wall-clock time.
func (System) Now() time.Time {
	return time.Now().UTC()
}

// Func adapts a function to a Clock. It is primarily useful in tests.
type Func func() time.Time

// Now calls the underlying function and normalizes the result to UTC.
func (f Func) Now() time.Time {
	return f().UTC()
}

// Or returns candidate when it is set, otherwise the system clock.
func Or(candidate Clock) Clock {
	if candidate == nil {
		return System{}
	}
	return candidate
}
