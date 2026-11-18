package providers

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors let callers classify provider failures without parsing text.
var (
	ErrMissingAPIKey   = errors.New("provider API key is not configured")
	ErrMissingModel    = errors.New("model is required")
	ErrMissingMessages = errors.New("at least one message is required")
	ErrUnauthorized    = errors.New("API key was rejected")
	ErrRateLimited     = errors.New("rate limit exceeded")
	ErrServerError     = errors.New("provider server error")
	ErrRequestRejected = errors.New("request rejected")
	ErrInvalidResponse = errors.New("provider returned an invalid response")
	ErrTimeout         = errors.New("provider request timed out")
	// ErrInvalidToolDefinition marks a caller-supplied tool catalogue that is
	// not a bounded, reviewed definition. Nothing is sent when it is rejected.
	ErrInvalidToolDefinition = errors.New("invalid tool definition")
	// ErrInvalidToolCall marks a model response that names an undeclared tool,
	// repeats a call id, or carries malformed arguments.
	ErrInvalidToolCall = errors.New("invalid tool call")
)

// APIError describes a non-2xx response from a provider. It unwraps to one of
// the sentinel errors above so callers can use errors.Is.
type APIError struct {
	Provider   string
	StatusCode int
	Message    string
	Err        error
}

func (apiError *APIError) Error() string {
	if message := strings.TrimSpace(apiError.Message); message != "" {
		return fmt.Sprintf("%s API returned HTTP %d: %s", apiError.Provider, apiError.StatusCode, message)
	}
	return fmt.Sprintf("%s API returned HTTP %d: %v", apiError.Provider, apiError.StatusCode, apiError.Err)
}

func (apiError *APIError) Unwrap() error {
	return apiError.Err
}

func classifyStatus(statusCode int) error {
	switch {
	case statusCode == 401 || statusCode == 403:
		return ErrUnauthorized
	case statusCode == 429:
		return ErrRateLimited
	case statusCode >= 500:
		return ErrServerError
	default:
		return ErrRequestRejected
	}
}
