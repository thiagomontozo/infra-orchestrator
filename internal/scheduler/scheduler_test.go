package scheduler

import (
	"testing"
	"time"
)

func TestDueTimezone(t *testing.T) {
	now := time.Date(2026, 9, 6, 1, 0, 5, 0, time.UTC)
	data := map[string]any{"enabled": true, "cron": "0 22 * * 6", "timezone": "America/Sao_Paulo"}
	at, due, e := Due(data, now)
	if e != nil || !due || at.Hour() != 1 {
		t.Fatal(at, due, e)
	}
	data["enabled"] = false
	if _, due, _ = Due(data, now); due {
		t.Fatal("disabled schedule ran")
	}
}
