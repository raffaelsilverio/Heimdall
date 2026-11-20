package assessment

import (
	"strings"
	"testing"
)

func TestNormalizeRequestProfileCanonicalizesAndSortsHeaders(t *testing.T) {
	profile, err := NormalizeRequestProfile(RequestProfile{
		Headers: []RequestHeader{
			{Name: "x-program", Value: " example "},
			{Name: "X-Bug-Bounty", Value: "researcher-one"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.UserAgent != DefaultRequestUserAgent || profile.Revision != 0 {
		t.Fatalf("request profile defaults are unexpected: %+v", profile)
	}
	if len(profile.Headers) != 2 || profile.Headers[0].Name != "X-Bug-Bounty" ||
		profile.Headers[1].Name != "X-Program" || profile.Headers[1].Value != "example" {
		t.Fatalf("request profile headers were not normalized: %+v", profile.Headers)
	}
	if profile.RevisionOrDefault() != 1 {
		t.Fatalf("unset revision should default to 1: %+v", profile)
	}
}

func TestNormalizeRequestProfileRejectsUnsafeHeaders(t *testing.T) {
	many := make([]RequestHeader, MaxRequestProfileHeaders+1)
	for index := range many {
		many[index] = RequestHeader{Name: "X-Test-" + string(rune('A'+index)), Value: "value"}
	}
	tests := []struct {
		name    string
		profile RequestProfile
		want    string
	}{
		{name: "empty value", profile: RequestProfile{Headers: []RequestHeader{{Name: "X-Test", Value: " "}}}, want: "must not be empty"},
		{name: "invalid name", profile: RequestProfile{Headers: []RequestHeader{{Name: "X Test", Value: "value"}}}, want: "not a valid HTTP token"},
		{name: "reserved authorization", profile: RequestProfile{Headers: []RequestHeader{{Name: "Authorization", Value: "secret"}}}, want: "managed by the request middleware"},
		{name: "reserved user agent", profile: RequestProfile{Headers: []RequestHeader{{Name: "user-agent", Value: "other"}}}, want: "managed by the request middleware"},
		{name: "duplicate", profile: RequestProfile{Headers: []RequestHeader{{Name: "X-Test", Value: "a"}, {Name: "x-test", Value: "b"}}}, want: "configured more than once"},
		{name: "newline", profile: RequestProfile{Headers: []RequestHeader{{Name: "X-Test", Value: "a\nb"}}}, want: "printable ASCII"},
		{name: "non ascii", profile: RequestProfile{Headers: []RequestHeader{{Name: "X-Test", Value: "café"}}}, want: "printable ASCII"},
		{name: "long user agent", profile: RequestProfile{UserAgent: strings.Repeat("a", MaxRequestUserAgentBytes+1)}, want: "user agent must not exceed"},
		{name: "long value", profile: RequestProfile{Headers: []RequestHeader{{Name: "X-Test", Value: strings.Repeat("a", MaxRequestHeaderValueBytes+1)}}}, want: "must not exceed"},
		{name: "too many headers", profile: RequestProfile{Headers: many}, want: "at most"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NormalizeRequestProfile(test.profile); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NormalizeRequestProfile error = %v, want %q", err, test.want)
			}
		})
	}
}
