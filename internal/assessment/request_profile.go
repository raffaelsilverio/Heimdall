package assessment

import (
	"errors"
	"fmt"
	"net/textproto"
	"sort"
	"strings"
)

const (
	// DefaultRequestUserAgent is used when a program does not override it.
	DefaultRequestUserAgent = "Heimdall/1.0 (+https://github.com/raffaelsilverio/Heimdall)"
	// MaxRequestProfileHeaders bounds the operator-configured mandatory headers.
	MaxRequestProfileHeaders = 16
	// MaxRequestUserAgentBytes bounds the User-Agent value.
	MaxRequestUserAgentBytes = 256
	// MaxRequestHeaderNameBytes bounds a header name.
	MaxRequestHeaderNameBytes = 64
	// MaxRequestHeaderValueBytes bounds a header value.
	MaxRequestHeaderValueBytes = 512
)

// RequestHeader is one operator-configured mandatory HTTP header. Values are
// stored and applied verbatim, so they must never be logged.
type RequestHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RequestProfile is the per-program request policy applied to outbound HTTP
// requests. Revision changes whenever the profile changes.
type RequestProfile struct {
	UserAgent string          `json:"user_agent"`
	Headers   []RequestHeader `json:"headers"`
	Revision  int64           `json:"revision"`
}

// NormalizeRequestProfile canonicalizes header names, sorts headers for
// deterministic output and rejects framing, credential and control headers
// that the request middleware must own.
func NormalizeRequestProfile(profile RequestProfile) (RequestProfile, error) {
	userAgent := strings.TrimSpace(profile.UserAgent)
	if userAgent == "" {
		userAgent = DefaultRequestUserAgent
	}
	if err := validateRequestValue("user agent", userAgent, MaxRequestUserAgentBytes); err != nil {
		return RequestProfile{}, err
	}
	if len(profile.Headers) > MaxRequestProfileHeaders {
		return RequestProfile{}, fmt.Errorf("request profile accepts at most %d headers", MaxRequestProfileHeaders)
	}
	headers := make([]RequestHeader, 0, len(profile.Headers))
	seen := make(map[string]struct{}, len(profile.Headers))
	for _, header := range profile.Headers {
		name := strings.TrimSpace(header.Name)
		if len(name) == 0 || len(name) > MaxRequestHeaderNameBytes {
			return RequestProfile{}, fmt.Errorf("request header name must be between 1 and %d bytes", MaxRequestHeaderNameBytes)
		}
		if !validRequestHeaderName(name) {
			return RequestProfile{}, fmt.Errorf("request header name %q is not a valid HTTP token", name)
		}
		name = textproto.CanonicalMIMEHeaderKey(name)
		if name == "" {
			return RequestProfile{}, errors.New("request header name is not a valid HTTP token")
		}
		if reservedRequestHeader(name) {
			return RequestProfile{}, fmt.Errorf("request header %q is managed by the request middleware and cannot be configured", name)
		}
		if _, exists := seen[name]; exists {
			return RequestProfile{}, fmt.Errorf("request header %q is configured more than once", name)
		}
		value := strings.TrimSpace(header.Value)
		if err := validateRequestValue(fmt.Sprintf("request header %q value", name), value, MaxRequestHeaderValueBytes); err != nil {
			return RequestProfile{}, err
		}
		seen[name] = struct{}{}
		headers = append(headers, RequestHeader{Name: name, Value: value})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].Name < headers[j].Name })
	return RequestProfile{UserAgent: userAgent, Headers: headers, Revision: profile.Revision}, nil
}

// RevisionOrDefault returns the normalized revision, treating an unset
// profile as revision 1.
func (profile RequestProfile) RevisionOrDefault() int64 {
	if profile.Revision > 0 {
		return profile.Revision
	}
	return 1
}

// Equal compares two normalized profiles, including their revision.
func (profile RequestProfile) Equal(other RequestProfile) bool {
	if profile.UserAgent != other.UserAgent || profile.Revision != other.Revision || len(profile.Headers) != len(other.Headers) {
		return false
	}
	for index := range profile.Headers {
		if profile.Headers[index] != other.Headers[index] {
			return false
		}
	}
	return true
}

func validRequestHeaderName(name string) bool {
	for index := 0; index < len(name); index++ {
		if !requestTokenByte(name[index]) {
			return false
		}
	}
	return true
}

func requestTokenByte(character byte) bool {
	switch {
	case character >= 'a' && character <= 'z',
		character >= 'A' && character <= 'Z',
		character >= '0' && character <= '9':
		return true
	case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)):
		return true
	default:
		return false
	}
}

func validateRequestValue(label, value string, maximum int) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if len(value) > maximum {
		return fmt.Errorf("%s must not exceed %d bytes", label, maximum)
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return fmt.Errorf("%s must contain printable ASCII bytes only", label)
		}
	}
	return nil
}

// reservedRequestHeaders are owned by the transport or by the future
// test-account mechanism. Accepting them here would let a program rule
// override request framing or smuggle credentials into stored configuration.
func reservedRequestHeader(name string) bool {
	switch name {
	case "Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Connection",
		"Keep-Alive", "Upgrade", "Trailer", "Te", "Expect", "Authorization",
		"Proxy-Authorization", "Cookie", "Set-Cookie", "User-Agent":
		return true
	default:
		return false
	}
}
