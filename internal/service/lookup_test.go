package service

import (
	"errors"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// LookupByToken is the read-only half of the portal's token resolution: it exists so a
// link-preview crawler can be served the page without the fetch re-binding the
// subscription's allowed address. What it must not do is write, and what it must not
// return is a pointer into the index the resolver reads on every query.

func TestLookupByTokenRejectsAnUnknownToken(t *testing.T) {
	svc, _, cleanup := setupClientFixture(t)
	defer cleanup()

	if _, err := svc.LookupByToken("not-a-token"); !errors.Is(err, database.ErrClientNotFound) {
		t.Errorf("LookupByToken error is %v, want ErrClientNotFound", err)
	}
	// An empty token is what a request to /sub/ with nothing after it produces, and it
	// must not resolve to the account whose token happens to be the zero value.
	if _, err := svc.LookupByToken(""); !errors.Is(err, database.ErrClientNotFound) {
		t.Errorf("LookupByToken(\"\") error is %v, want ErrClientNotFound", err)
	}
}

func TestLookupByTokenReportsExpiryWithoutDisablingTheAccount(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	client, err := svc.CreateClient("Lapsed", 30, "10.0.0.9")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := svc.UpdateClient(client.ID, UpdateClientRequest{ExpiresAt: &past}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	got, err := svc.LookupByToken(client.Token)
	if !errors.Is(err, database.ErrClientExpired) {
		t.Fatalf("LookupByToken error is %v, want ErrClientExpired", err)
	}
	// The record comes back with the error so the portal can render the expiry page for
	// the right account rather than a generic "unknown link".
	if got == nil || got.ID != client.ID {
		t.Fatalf("LookupByToken returned %+v alongside the expiry error", got)
	}

	// RegisterIP disables an expired account on disk. This must not: a crawler's fetch
	// of a link is not the event that retires a subscription, and an operator renewing
	// the plan afterwards should not have to re-enable it because a bot looked at it.
	stored, err := db.GetClient(client.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !stored.Enabled {
		t.Error("a read-only lookup disabled the account")
	}
}

func TestLookupByTokenReturnsACopy(t *testing.T) {
	svc, _, cleanup := setupClientFixture(t)
	defer cleanup()

	client, err := svc.CreateClient("Shared Pointer", 30, "10.0.0.10")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	// The token index holds pointers into the cache the DNS handler reads on every
	// query, and the caller of this is a template. Handing out the pointer would let a
	// portal render mutate what the resolver matches against.
	first, err := svc.LookupByToken(client.Token)
	if err != nil {
		t.Fatalf("LookupByToken: %v", err)
	}
	first.Name = "Overwritten"
	first.TrafficLimitGB = 999

	second, err := svc.LookupByToken(client.Token)
	if err != nil {
		t.Fatalf("LookupByToken: %v", err)
	}
	if second.Name != "Shared Pointer" || second.TrafficLimitGB == 999 {
		t.Errorf("the second lookup sees the first caller's writes: name=%q limit=%v",
			second.Name, second.TrafficLimitGB)
	}
}
