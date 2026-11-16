package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewFormats(t *testing.T) {
	tests := []struct {
		name   string
		format string
		check  func(t *testing.T, output string)
	}{
		{
			name:   "text",
			format: FormatText,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "msg=hello") {
					t.Errorf("text output = %q, want msg=hello", output)
				}
			},
		},
		{
			name:   "json",
			format: FormatJSON,
			check: func(t *testing.T, output string) {
				var entry map[string]any
				if err := json.Unmarshal([]byte(output), &entry); err != nil {
					t.Fatalf("json output = %q: %v", output, err)
				}
				if entry["msg"] != "hello" {
					t.Errorf("msg = %v, want hello", entry["msg"])
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			logger, err := New(&output, LevelInfo, test.format)
			if err != nil {
				t.Fatalf("New returned an error: %v", err)
			}
			logger.Info("hello")
			test.check(t, output.String())
		})
	}
}

func TestNewFiltersBelowLevel(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(&output, LevelWarn, FormatText)
	if err != nil {
		t.Fatalf("New returned an error: %v", err)
	}

	logger.Info("hidden")
	logger.Warn("visible")

	if strings.Contains(output.String(), "hidden") {
		t.Errorf("info message was not filtered: %q", output.String())
	}
	if !strings.Contains(output.String(), "visible") {
		t.Errorf("warn message was filtered: %q", output.String())
	}
}

func TestNewDefaults(t *testing.T) {
	for _, test := range []struct {
		name   string
		level  string
		format string
	}{
		{name: "empty values"},
		{name: "explicit defaults", level: LevelInfo, format: FormatText},
	} {
		t.Run(test.name, func(t *testing.T) {
			logger, err := New(&bytes.Buffer{}, test.level, test.format)
			if err != nil {
				t.Fatalf("New returned an error: %v", err)
			}
			if logger == nil {
				t.Fatal("New returned a nil logger")
			}
		})
	}
}

func TestNewRejectsInvalidValues(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, "verbose", FormatText); err == nil {
		t.Fatal("expected an error for an invalid level")
	}
	if _, err := New(&bytes.Buffer{}, LevelInfo, "xml"); err == nil {
		t.Fatal("expected an error for an invalid format")
	}
}

func TestNewDefaultsToInfo(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(&output, "", FormatText)
	if err != nil {
		t.Fatalf("New returned an error: %v", err)
	}
	logger.Debug("hidden")
	if strings.Contains(output.String(), "hidden") {
		t.Error("empty level should default to info and filter debug messages")
	}
}
