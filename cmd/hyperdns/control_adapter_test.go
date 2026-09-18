package main

import (
	"testing"
	"time"

	"hyperdns/internal/control"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
)

func TestControlClientViewRedactsStoredCredentialsFromLists(t *testing.T) {
	nextReset := time.Now().UTC().Add(time.Hour)
	view := service.ClientView{
		Client: database.Client{
			ID:                    "client-1",
			UUID:                  "uuid-1",
			Name:                  "subscriber",
			AllowedIPs:            []string{"203.0.113.7"},
			Token:                 "stored-subscription-token",
			RegisterSecret:        "stored-registration-secret",
			CustomPolicies:        []string{"direct:example.test"},
			TrafficResetCycle:     "monthly",
			TrafficResetCount:     3,
			TrafficLimitGB:        25,
			TrafficUsedBytes:      1024,
			TrafficPrevCycleBytes: 512,
		},
		NextTrafficReset: &nextReset,
	}

	listed := controlClientView(view, false)
	if listed.SubscriptionToken != "" || listed.RegistrationSecret != "" {
		t.Fatalf("listed credentials = %q/%q, want redacted", listed.SubscriptionToken, listed.RegistrationSecret)
	}
	if listed.ID != view.ID || listed.Name != view.Name || listed.NextTrafficReset != view.NextTrafficReset {
		t.Fatalf("listed view lost non-secret fields: %+v", listed)
	}

	created := controlClientView(view, true)
	if created.SubscriptionToken != view.Token || created.RegistrationSecret != view.RegisterSecret {
		t.Fatalf("creation credentials = %q/%q, want one-time values", created.SubscriptionToken, created.RegistrationSecret)
	}
}

func TestDaemonControlStatusFailsWhenStatsUnavailable(t *testing.T) {
	adapter := &daemonControl{}
	if _, err := adapter.ControlStatus(); err == nil {
		t.Fatal("ControlStatus succeeded without the daemon stats service")
	}
}

func TestDaemonControlClearLockoutsUsesSharedTracker(t *testing.T) {
	tracker := service.NewLoginAttemptTracker()
	tracker.RecordFailure("203.0.113.8")
	tracker.RecordFailure("203.0.113.9")
	adapter := &daemonControl{lockouts: tracker}

	cleared, err := adapter.ControlClearLockouts(control.ClearLockoutsRequest{IP: "203.0.113.8"})
	if err != nil {
		t.Fatalf("clear one lockout: %v", err)
	}
	if cleared != 1 || tracker.Count() != 1 {
		t.Fatalf("cleared=%d remaining=%d, want 1/1", cleared, tracker.Count())
	}

	cleared, err = adapter.ControlClearLockouts(control.ClearLockoutsRequest{})
	if err != nil {
		t.Fatalf("clear all lockouts: %v", err)
	}
	if cleared != 1 || tracker.Count() != 0 {
		t.Fatalf("cleared=%d remaining=%d, want 1/0", cleared, tracker.Count())
	}
}
