package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	scopeHashPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Client talks to a loopback browser worker. It never stores cookies and never
// logs its token.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient validates the loopback URL and token before any request is sent.
func NewClient(config Config) (*Client, error) {
	baseURL, err := normalizeBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	token, err := normalizeToken(config.Token)
	if err != nil {
		return nil, err
	}
	timeout, err := normalizeTimeout(config.Timeout)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		token:   token,
		http: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Health performs the versioned worker handshake.
func (c *Client) Health(ctx context.Context) (Health, error) {
	raw, err := c.do(ctx, http.MethodGet, "/healthz", nil)
	if err != nil {
		return Health{}, err
	}
	var health Health
	if err := decodeStrict(raw, &health); err != nil {
		return Health{}, err
	}
	if health.Version != ProtocolVersion {
		return Health{}, fmt.Errorf("%w: unsupported worker version", ErrProtocol)
	}
	if strings.TrimSpace(health.Driver.Name) == "" || strings.TrimSpace(health.Driver.Browser) == "" {
		return Health{}, fmt.Errorf("%w: incomplete driver health", ErrProtocol)
	}
	return health, nil
}

// OpenSession creates one isolated session for a program and test account.
func (c *Client) OpenSession(ctx context.Context, request SessionRequest) (Session, error) {
	if err := request.validate(); err != nil {
		return Session{}, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/v1/sessions", request)
	if err != nil {
		return Session{}, err
	}
	var session Session
	if err := decodeStrict(raw, &session); err != nil {
		return Session{}, err
	}
	if err := session.validateAgainst(request); err != nil {
		return Session{}, err
	}
	return session, nil
}

// Session returns metadata for a live session.
func (c *Client) Session(ctx context.Context, sessionID string) (Session, error) {
	if err := validateSessionID(sessionID); err != nil {
		return Session{}, err
	}
	raw, err := c.do(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(sessionID), nil)
	if err != nil {
		return Session{}, err
	}
	var session Session
	if err := decodeStrict(raw, &session); err != nil {
		return Session{}, err
	}
	if err := session.validateMetadata(); err != nil {
		return Session{}, err
	}
	if session.ID != sessionID {
		return Session{}, fmt.Errorf("%w: session id does not match the request", ErrProtocol)
	}
	return session, nil
}

// CloseSession releases a live session and its browser context.
func (c *Client) CloseSession(ctx context.Context, sessionID string) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	_, err := c.do(ctx, http.MethodDelete, "/v1/sessions/"+url.PathEscape(sessionID), nil)
	return err
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode browser worker request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build browser worker request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call browser worker: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := readLimited(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, workerError(response.StatusCode, raw)
	}
	return raw, nil
}

func readLimited(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read browser worker response: %w", err)
	}
	if len(raw) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrProtocol, MaxResponseBytes)
	}
	return raw, nil
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func workerError(status int, raw []byte) error {
	var envelope errorEnvelope
	_ = json.Unmarshal(raw, &envelope)
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUnauthorized
	case http.StatusBadRequest:
		return fmt.Errorf("%w (%s)", ErrRequestRejected, safeErrorCode(envelope.Error.Code))
	case http.StatusNotFound:
		return ErrSessionNotFound
	case http.StatusConflict:
		return ErrSessionExists
	case http.StatusTooManyRequests:
		return ErrSessionLimit
	case http.StatusBadGateway:
		return ErrDriverFailure
	case http.StatusServiceUnavailable:
		return ErrDriverUnavailable
	default:
		return &APIError{StatusCode: status, Code: safeErrorCode(envelope.Error.Code)}
	}
}

func safeErrorCode(code string) string {
	if !identifierPattern.MatchString(code) {
		return ""
	}
	return code
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: decode response", ErrProtocol)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing response data", ErrProtocol)
	}
	return nil
}

func (r SessionRequest) validate() error {
	if err := validateIdentifier(r.ProgramID, "program id"); err != nil {
		return err
	}
	if err := validateIdentifier(r.TestAccountID, "test account id"); err != nil {
		return err
	}
	if !scopeHashPattern.MatchString(r.ScopeHash) {
		return errors.New("browser session scope hash must be 64 lowercase hexadecimal characters")
	}
	if r.PolicyRevision < MinPolicyRevision || r.PolicyRevision > MaxPolicyRevision {
		return fmt.Errorf("browser session policy revision must be between %d and %d", MinPolicyRevision, MaxPolicyRevision)
	}
	return nil
}

func validateIdentifier(value, field string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("browser session %s is not a canonical identifier", field)
	}
	return nil
}

func validateSessionID(sessionID string) error {
	parsed, err := uuid.Parse(sessionID)
	if err != nil || parsed.String() != sessionID {
		return errors.New("browser session id must be a canonical UUID")
	}
	return nil
}

func (s Session) validateAgainst(request SessionRequest) error {
	if err := s.validateMetadata(); err != nil {
		return err
	}
	if s.ProgramID != request.ProgramID || s.TestAccountID != request.TestAccountID ||
		s.ScopeHash != request.ScopeHash || s.PolicyRevision != request.PolicyRevision {
		return fmt.Errorf("%w: worker session does not echo the requested identity", ErrProtocol)
	}
	return nil
}

func (s Session) validateMetadata() error {
	if err := validateSessionID(s.ID); err != nil {
		return fmt.Errorf("%w: invalid session id", ErrProtocol)
	}
	if err := validateIdentifier(s.ProgramID, "program id"); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if err := validateIdentifier(s.TestAccountID, "test account id"); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if !scopeHashPattern.MatchString(s.ScopeHash) {
		return fmt.Errorf("%w: invalid scope hash", ErrProtocol)
	}
	if s.PolicyRevision < MinPolicyRevision || s.PolicyRevision > MaxPolicyRevision {
		return fmt.Errorf("%w: invalid policy revision", ErrProtocol)
	}
	if s.CreatedAt.IsZero() || s.CreatedAt.After(time.Now().Add(5*time.Minute)) {
		return fmt.Errorf("%w: invalid session creation time", ErrProtocol)
	}
	return nil
}
