package tui

import "testing"

// formatUptime is the only place the daemon's age is rendered for the console, and
// the operator reads it to decide whether the service restarted under them. Each
// branch drops the units above it, so a wrong threshold silently reports "0m 1s"
// for a box that has been up for a day.
func TestFormatUptime(t *testing.T) {
	cases := []struct {
		name string
		sec  int64
		want string
	}{
		{"zero", 0, "0m 0s"},
		{"seconds only", 45, "0m 45s"},
		{"just under a minute", 59, "0m 59s"},
		{"exactly a minute", 60, "1m 0s"},
		{"minutes and seconds", 1874, "31m 14s"},
		{"one second before an hour", 3599, "59m 59s"},
		{"exactly an hour drops seconds", 3600, "1h 0m"},
		{"hours and minutes", 7265, "2h 1m"},
		{"one second before a day", 86399, "23h 59m"},
		{"exactly a day drops seconds", 86400, "1d 0h 0m"},
		{"days hours minutes", 90061, "1d 1h 1m"},
		// The case that exposed the missing assignment: a daemon up for a week
		// reported "0m 0s" because UptimeSec was never filled in.
		{"a week", 604800, "7d 0h 0m"},

		// A clock that steps backwards must not print "-1d -1h -1m"; the field is
		// derived from time.Since on a monotonic reading, but the clamp is cheap and
		// the alternative is a garbled status line.
		{"negative clamps to zero", -1, "0m 0s"},
		{"large negative clamps to zero", -604800, "0m 0s"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := formatUptime(c.sec); got != c.want {
				t.Errorf("formatUptime(%d) = %q, want %q", c.sec, got, c.want)
			}
		})
	}
}
