package schedule

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

const (
	DefaultOSINTCron     = "0 3 * * *"
	DefaultOSINTTimezone = "UTC"
)

var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

func Validate(expression, timezone string) error {
	if _, err := parser.Parse(expression); err != nil {
		return fmt.Errorf("invalid five-field cron expression: %w", err)
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return fmt.Errorf("invalid IANA timezone %q: %w", timezone, err)
	}
	return nil
}

func Next(expression, timezone string, after time.Time) (time.Time, error) {
	if err := Validate(expression, timezone); err != nil {
		return time.Time{}, err
	}
	spec, err := parser.Parse(expression)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse schedule: %w", err)
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("load timezone: %w", err)
	}
	next := spec.Next(after.In(location))
	if next.IsZero() {
		return time.Time{}, errors.New("schedule has no next occurrence")
	}
	return next.UTC(), nil
}

// DetectTimezone returns the configured timezone, or the host's IANA timezone
// when it can be determined. UTC is the portable fallback.
func DetectTimezone() string {
	if configured := strings.TrimSpace(os.Getenv("HEIMDALL_TIMEZONE")); configured != "" {
		if _, err := time.LoadLocation(configured); err == nil {
			return configured
		}
	}
	if zone := os.Getenv("TZ"); zone != "" {
		if _, err := time.LoadLocation(zone); err == nil {
			return zone
		}
	}
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		if zone := strings.TrimSpace(string(data)); zone != "" {
			if _, err := time.LoadLocation(zone); err == nil {
				return zone
			}
		}
	}
	if target, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
		if index := strings.Index(target, "zoneinfo/"); index >= 0 {
			zone := target[index+len("zoneinfo/"):]
			if _, err := time.LoadLocation(zone); err == nil {
				return zone
			}
		}
	}
	return DefaultOSINTTimezone
}
