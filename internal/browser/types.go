// Package browser is the Go-side contract for the loopback browser worker.
//
// The worker owns isolated Chromium contexts. This package only carries session
// metadata: cookies, tokens, storage state, and credentials never cross the
// wire, and the client refuses any non-loopback endpoint.
package browser

import (
	"errors"
	"fmt"
	"time"
)

// ProtocolVersion is the only worker protocol version accepted by this client.
const ProtocolVersion = "1"

// Limits enforced on both sides of the contract.
const (
	MaxResponseBytes    = 256 << 10
	DefaultTimeout      = 5 * time.Second
	MinTimeout          = time.Second
	MaxTimeout          = 30 * time.Second
	MinTokenBytes       = 32
	MaxTokenBytes       = 256
	MaxPolicyRevision   = 1_000_000_000
	MinPolicyRevision   = 1
	LoopbackIPv4Address = "127.0.0.1"
	LoopbackIPv6Address = "::1"
)

var (
	// ErrUnauthorized reports an invalid or missing worker token.
	ErrUnauthorized = errors.New("browser worker rejected the bearer token")
	// ErrRequestRejected reports a request the worker refused as invalid.
	ErrRequestRejected = errors.New("browser worker rejected the request")
	// ErrSessionNotFound reports an unknown or already closed session.
	ErrSessionNotFound = errors.New("browser session not found")
	// ErrSessionExists reports a duplicate session for one program/account pair.
	ErrSessionExists = errors.New("browser session already exists for this program and test account")
	// ErrSessionLimit reports the worker-wide concurrent session cap.
	ErrSessionLimit = errors.New("browser worker session limit reached")
	// ErrDriverFailure reports a browser driver failure while opening/closing.
	ErrDriverFailure = errors.New("browser worker driver failed")
	// ErrDriverUnavailable reports that no reviewed browser driver is available.
	ErrDriverUnavailable = errors.New("browser worker driver is unavailable")
	// ErrProtocol reports a malformed or contradictory worker response.
	ErrProtocol = errors.New("browser worker protocol violation")
)

// APIError is an unmapped worker response. It never contains the response body.
type APIError struct {
	StatusCode int
	Code       string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("browser worker returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("browser worker returned HTTP %d (%s)", e.StatusCode, e.Code)
}

// DriverHealth describes the worker's browser driver without exposing secrets.
type DriverHealth struct {
	Name      string `json:"name"`
	Browser   string `json:"browser"`
	Available bool   `json:"available"`
}

// Health is the worker handshake and capability report.
type Health struct {
	Version string       `json:"version"`
	Driver  DriverHealth `json:"driver"`
}

// SessionRequest binds one isolated browser session to a program, test account,
// scope snapshot, and policy revision.
type SessionRequest struct {
	ProgramID      string `json:"program_id"`
	TestAccountID  string `json:"test_account_id"`
	ScopeHash      string `json:"scope_hash"`
	PolicyRevision int64  `json:"policy_revision"`
}

// Session is the metadata the worker returns. It intentionally has no cookie,
// token, or storage-state fields.
type Session struct {
	ID             string    `json:"session_id"`
	ProgramID      string    `json:"program_id"`
	TestAccountID  string    `json:"test_account_id"`
	ScopeHash      string    `json:"scope_hash"`
	PolicyRevision int64     `json:"policy_revision"`
	CreatedAt      time.Time `json:"created_at"`
}
