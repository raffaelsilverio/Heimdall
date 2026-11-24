package browser

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config configures the worker client. The token must come from the
// environment or a secret manager and must never be persisted or logged.
type Config struct {
	BaseURL string
	Token   string
	Timeout time.Duration
}

func normalizeBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse browser worker URL: %w", err)
	}
	if err := validateWorkerURL(parsed); err != nil {
		return "", err
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed.String(), nil
}

func validateWorkerURL(parsed *url.URL) error {
	if err := validateWorkerURLShape(parsed); err != nil {
		return err
	}
	return validateWorkerPort(parsed.Port())
}

func validateWorkerURLShape(parsed *url.URL) error {
	if parsed.Scheme != "http" {
		return errors.New("browser worker URL must use plain http on loopback")
	}
	if parsed.User != nil || parsed.Opaque != "" {
		return errors.New("browser worker URL must not contain credentials or opaque data")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("browser worker URL must not contain a query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("browser worker URL must not contain a path")
	}
	host := parsed.Hostname()
	if host != LoopbackIPv4Address && host != LoopbackIPv6Address {
		return fmt.Errorf("browser worker URL must use the loopback address %s or %s", LoopbackIPv4Address, LoopbackIPv6Address)
	}
	return nil
}

func validateWorkerPort(port string) error {
	if port == "" {
		return nil
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("browser worker URL port must be between 1 and 65535")
	}
	return nil
}

func normalizeToken(token string) (string, error) {
	if len(token) < MinTokenBytes || len(token) > MaxTokenBytes {
		return "", fmt.Errorf("browser worker token must be between %d and %d bytes", MinTokenBytes, MaxTokenBytes)
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			return "", errors.New("browser worker token must use printable ASCII without spaces")
		}
	}
	return token, nil
}

func normalizeTimeout(timeout time.Duration) (time.Duration, error) {
	if timeout == 0 {
		return DefaultTimeout, nil
	}
	if timeout < MinTimeout || timeout > MaxTimeout {
		return 0, fmt.Errorf("browser worker timeout must be between %s and %s", MinTimeout, MaxTimeout)
	}
	return timeout, nil
}
