package service

import (
	"testing"
)

func TestLoginAttemptTrackerResetReportsExactCount(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	tracker.RecordFailure("192.0.2.1")
	tracker.RecordFailure("192.0.2.2")

	if !tracker.Reset("192.0.2.1") {
		t.Fatal("Reset reported no removed address")
	}
	if tracker.Reset("192.0.2.1") {
		t.Fatal("second Reset reported an address that no longer exists")
	}
	if got := tracker.ResetAll(); got != 1 {
		t.Fatalf("ResetAll = %d, want 1", got)
	}
	if got := tracker.Count(); got != 0 {
		t.Fatalf("Count = %d, want 0", got)
	}
}
