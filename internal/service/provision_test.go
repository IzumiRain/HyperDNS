package service

import (
	"errors"
	"testing"
	"time"
)

// ProvisionClient is the create path the dashboard and the REST API now both use,
// and the reason it exists is atomicity: the panel used to create an account and
// then set its quota in a second step, so between the two the subscriber had a live
// account with no limit at all. These tests hold that shape — one write, or none.

func TestProvisionClientWritesTheWholePlanOnce(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	before := time.Now()
	created, err := svc.ProvisionClient(CreateClientRequest{
		Name:              "Reza",
		Days:              30,
		TrafficLimitGB:    50,
		TrafficResetCycle: TrafficCycleMonthly,
		Note:              "50GB monthly",
		CustomPolicies:    []string{"enable_riot"},
	})
	if err != nil {
		t.Fatalf("ProvisionClient: %v", err)
	}

	// Read the record back out of the database rather than trusting the returned
	// value: the point of the single write is that what the operator sees in the
	// panel on the next refresh is already complete.
	stored, err := db.GetClient(created.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.TrafficLimitGB != 50 {
		t.Errorf("stored limit is %v GB, want 50", stored.TrafficLimitGB)
	}
	if stored.TrafficResetCycle != TrafficCycleMonthly {
		t.Errorf("stored cycle is %q, want %q", stored.TrafficResetCycle, TrafficCycleMonthly)
	}
	if stored.Note != "50GB monthly" {
		t.Errorf("stored note is %q", stored.Note)
	}
	if !stored.Enabled {
		t.Error("a freshly provisioned account is disabled")
	}
	if stored.Token == "" || stored.UUID == "" {
		t.Errorf("account has no credential: token=%q uuid=%q", stored.Token, stored.UUID)
	}

	if len(stored.CustomPolicies) != 1 || stored.CustomPolicies[0] != "enable_riot" {
		t.Errorf("stored policies are %v, want [enable_riot]", stored.CustomPolicies)
	}
	if got := stored.ExpiresAt.Sub(before); got < 29*24*time.Hour || got > 31*24*time.Hour {
		t.Errorf("a 30-day account expires in %v", got)
	}

	// Anchored at creation, so the subscriber's first rollover is a whole period away
	// instead of landing on whenever the next sweep happens to run.
	if stored.TrafficResetAnchor.Before(before) {
		t.Errorf("anchor %v predates the request", stored.TrafficResetAnchor)
	}
	if stored.TrafficResetCount != 0 {
		t.Errorf("a new account has already crossed %d boundaries", stored.TrafficResetCount)
	}
	next, ok := NextTrafficReset(stored)
	if !ok {
		t.Fatal("a monthly account reports no next reset")
	}
	if want := addMonthsClamped(stored.TrafficResetAnchor, 1); !next.Equal(want) {
		t.Errorf("first reset is %v, want %v", next, want)
	}
	if !next.After(before) {
		t.Errorf("first reset %v is not in the future", next)
	}
}

func TestProvisionClientRejectsAnUnknownCycleWithoutWritingAnything(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	before, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}

	_, err = svc.ProvisionClient(CreateClientRequest{
		Name:              "Typo",
		Days:              30,
		TrafficLimitGB:    50,
		TrafficResetCycle: "fortnightly",
	})
	if !errors.Is(err, ErrInvalidTrafficCycle) {
		t.Fatalf("ProvisionClient error is %v, want ErrInvalidTrafficCycle", err)
	}

	// Validation is the first thing the function does, and this is the assertion that
	// says why: a mistyped cycle must not leave a live account behind for the operator
	// to discover later, unmetered, with a name they thought had failed to create.
	after, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("a rejected request wrote %d record(s)", len(after)-len(before))
	}
}

func TestProvisionClientRejectsABadAddressWithoutWritingAnything(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	// The address is validated after the credentials are generated but before the only
	// write, which is the same guarantee as the cycle above and worth pinning
	// separately: the two rejections are on opposite sides of that generation.
	_, err := svc.ProvisionClient(CreateClientRequest{Name: "Fat finger", Days: 30, IP: "203.0.113"})
	if !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("ProvisionClient error is %v, want ErrInvalidIP", err)
	}

	list, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	for _, c := range list {
		if c.Name == "Fat finger" {
			t.Fatalf("a rejected request left %q behind", c.Name)
		}
	}
}

func TestProvisionClientWithoutACycleLeavesTheAnchorZero(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	// Most accounts are sold with no recurring allowance at all, and those must not be
	// handed an anchor: an anchored record with an empty cycle would read as "resets
	// eventually" to anything that trusts the anchor instead of the cycle name.
	created, err := svc.ProvisionClient(CreateClientRequest{Name: "One off", Days: 7, TrafficLimitGB: 10})
	if err != nil {
		t.Fatalf("ProvisionClient: %v", err)
	}
	stored, err := db.GetClient(created.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.TrafficResetCycle != TrafficCycleNone {
		t.Errorf("stored cycle is %q, want empty", stored.TrafficResetCycle)
	}
	if !stored.TrafficResetAnchor.IsZero() {
		t.Errorf("an account with no cycle is anchored at %v", stored.TrafficResetAnchor)
	}
	if _, ok := NextTrafficReset(stored); ok {
		t.Error("an account with no cycle reports a next reset date")
	}
}

func TestProvisionClientIndexesTheInitialAddress(t *testing.T) {
	svc, _, cleanup := setupClientFixture(t)
	defer cleanup()

	// Provisioning ends in reloadCache, so the account resolves on its first query
	// rather than on the sweep after it. The address is given in the copied-from-a-log
	// form on purpose — that is what an operator pastes.
	created, err := svc.ProvisionClient(CreateClientRequest{Name: "Indexed", Days: 30, IP: "203.0.113.9:53"})
	if err != nil {
		t.Fatalf("ProvisionClient: %v", err)
	}
	if got := indexedIP(t, svc, "203.0.113.9"); got != created.ID {
		t.Errorf("resolver index maps 203.0.113.9 to %q, want %q", got, created.ID)
	}
}

// The create form's picker answers an exact moment, not a whole-day count, and a
// Days value arriving alongside it is the form's old default rather than a
// second opinion. Rounding the moment into days would move the expiry by up to a
// day in either direction, so the moment wins.
func TestProvisionClientHonoursAnAbsoluteExpiryOverDays(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	want := time.Now().Add(48*time.Hour + 90*time.Minute).Truncate(time.Second)
	created, err := svc.ProvisionClient(CreateClientRequest{
		Name:      "Exact plan",
		Days:      30,
		ExpiresAt: want,
	})
	if err != nil {
		t.Fatalf("ProvisionClient: %v", err)
	}
	stored, err := db.GetClient(created.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !stored.ExpiresAt.Equal(want) {
		t.Errorf("stored expiry is %v, want the exact %v", stored.ExpiresAt, want)
	}
}

// A lifetime plan is the zero ExpiresAt with Days 0, which is what the create
// form sends when the operator pressed Clear (Lifetime). The zero must reach the
// record as "no expiry", never as a moment in year 1.
func TestProvisionClientWithoutAnExpiryOrDaysIsLifetime(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	created, err := svc.ProvisionClient(CreateClientRequest{Name: "Forever"})
	if err != nil {
		t.Fatalf("ProvisionClient: %v", err)
	}
	stored, err := db.GetClient(created.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !stored.ExpiresAt.IsZero() {
		t.Errorf("a lifetime account expires at %v", stored.ExpiresAt)
	}
}
