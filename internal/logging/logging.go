package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"

	FormatText = "text"
	FormatJSON = "json"
)

// New builds a structured logger for the requested level and format.
func New(writer io.Writer, level, format string) (*slog.Logger, error) {
	handlerOptions, err := handlerOptions(level)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatText:
		return slog.New(slog.NewTextHandler(writer, handlerOptions)), nil
	case FormatJSON:
		return slog.New(slog.NewJSONHandler(writer, handlerOptions)), nil
	default:
		return nil, fmt.Errorf("unsupported log format %q: use text or json", format)
	}
}

func handlerOptions(level string) (*slog.HandlerOptions, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", LevelInfo:
		return &slog.HandlerOptions{Level: slog.LevelInfo}, nil
	case LevelDebug:
		return &slog.HandlerOptions{Level: slog.LevelDebug}, nil
	case LevelWarn:
		return &slog.HandlerOptions{Level: slog.LevelWarn}, nil
	case LevelError:
		return &slog.HandlerOptions{Level: slog.LevelError}, nil
	default:
		return nil, fmt.Errorf("unsupported log level %q: use debug, info, warn or error", level)
	}
}
