package recon

import (
	"strings"
	"testing"
)

func TestNormalizeEndpointCanonicalizesAndValidates(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantURL   string
		wantHost  string
		wantError string
	}{
		{
			name:    "removes default port query and fragment",
			input:   "http://EXAMPLE.COM:80/path?token=private#section",
			wantURL: "http://example.com/path", wantHost: "example.com",
		},
		{
			name:    "preserves non-default port",
			input:   "https://example.com:8443/path",
			wantURL: "https://example.com:8443/path", wantHost: "example.com",
		},
		{name: "rejects non-http scheme", input: "ftp://example.com", wantError: "absolute HTTP(S)"},
		{name: "rejects URL credentials", input: "https://user:pass@example.com", wantError: "without credentials"},
		{name: "rejects zero port", input: "https://example.com:0", wantError: "port must be between"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotURL, gotHost, err := normalizeEndpoint(test.input)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("normalizeEndpoint(%q) error = %v, want substring %q", test.input, err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotURL != test.wantURL || gotHost != test.wantHost {
				t.Fatalf("normalizeEndpoint(%q) = (%q, %q), want (%q, %q)", test.input, gotURL, gotHost, test.wantURL, test.wantHost)
			}
		})
	}
}

func TestValidateEndpointPort(t *testing.T) {
	tests := []struct {
		port      string
		wantError string
	}{
		{port: ""},
		{port: "443"},
		{port: "0", wantError: "port must be between"},
		{port: "abc", wantError: "invalid port"},
		{port: "65536", wantError: "invalid port"},
	}
	for _, test := range tests {
		t.Run(test.port, func(t *testing.T) {
			err := validateEndpointPort(test.port)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateEndpointPort(%q) error = %v, want substring %q", test.port, err, test.wantError)
			}
		})
	}
}
