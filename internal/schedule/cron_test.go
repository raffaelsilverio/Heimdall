package schedule

import (
	"testing"
	"time"
)

func TestNextUsesConfiguredTimezone(t *testing.T) {
	start := time.Date(2025, time.January, 1, 2, 59, 0, 0, time.UTC)
	next, err := Next(DefaultOSINTCron, "UTC", start)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, time.January, 1, 3, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("Next() = %s, want %s", next, want)
	}
}

func TestValidateRejectsInvalidCronAndTimezone(t *testing.T) {
	if err := Validate("not cron", "UTC"); err == nil {
		t.Fatal("expected invalid cron expression to fail")
	}
	if err := Validate(DefaultOSINTCron, "Mars/Olympus"); err == nil {
		t.Fatal("expected invalid timezone to fail")
	}
}

func TestDefaultScheduleIsDaily(t *testing.T) {
	first := time.Date(2025, time.January, 1, 4, 0, 0, 0, time.UTC)
	second, err := Next(DefaultOSINTCron, "UTC", first)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sub(first) != 23*time.Hour {
		t.Fatalf("expected next daily run at 03:00 UTC, got interval %s", second.Sub(first))
	}
}
