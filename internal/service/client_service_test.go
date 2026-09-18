package service

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

// funcIP resolves the account's register secret and binds ip — the test stand-in
// for the out-of-band secret delivery Phase B introduced.
func funcIP(svc *ClientService, token, ip string) (*database.Client, bool, error) {
	c, err := svc.LookupByToken(token)
	if err != nil {
		return nil, false, err
	}
	return svc.RegisterIP(token, c.RegisterSecret, ip)
}

// setupClientFixture builds a throwaway encrypted database with a ClientService on
// top of it, plus a closure that closes the handle. The files live in the test's
// own temp directory, so nothing survives the run.
func setupClientFixture(t *testing.T) (*ClientService, *database.DB, func()) {
	t.Helper()

	// A per-test directory, not a fixed name in the package dir: bbolt holds an
	// exclusive lock per file, so two tests sharing one path cannot run
	// concurrently, and a test that fails before cleanup leaves the file behind to
	// be picked up — with stale contents — by the next run. t.TempDir is removed by
	// the framework even when the test panics.
	dir := t.TempDir()

	cipher, err := crypto.LoadOrGenerateMasterKey(filepath.Join(dir, "clients.key"))
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	db, err := database.Open(filepath.Join(dir, "clients.db"), cipher)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	svc := NewClientService(db, true)

	// The database handle still has to be closed explicitly; t.TempDir cannot
	// remove a file Windows considers open.
	cleanup := func() { _ = db.Close() }

	return svc, db, cleanup
}

// indexedIP reports which account currently owns an address in the resolver's
// lookup table, reading it the way IsIPAllowed does.
func indexedIP(t *testing.T, svc *ClientService, ip string) string {
	t.Helper()
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if c := svc.ipMap[ip]; c != nil {
		return c.ID
	}
	return ""
}

// The portal binds whatever address it sees to the subscription, so a subscriber
// who moves network has to stop being served at the old one immediately. This is
// the targeted index update standing in for what used to be a full rescan.
func TestRegisterIPMovesTheAddressInTheIndex(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	const token = "tok-move"
	if err := db.SaveClient(database.Client{
		ID: "m1", UUID: database.GenerateUUID(), Name: "mover", Token: token,
		AllowedIPs: []string{"203.0.113.10"}, Enabled: true, CreatedAt: time.Now(),
		RegisterSecret: "fixturesecret-move",
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	svc.reloadCache()

	if got := indexedIP(t, svc, "203.0.113.10"); got != "m1" {
		t.Fatalf("the seeded address maps to %q, want m1", got)
	}

	if _, _, err := funcIP(svc, token, "203.0.113.11"); err != nil {
		t.Fatalf("RegisterIP: %v", err)
	}

	if got := indexedIP(t, svc, "203.0.113.11"); got != "m1" {
		t.Errorf("the new address maps to %q, want m1", got)
	}
	if got := indexedIP(t, svc, "203.0.113.10"); got != "" {
		t.Errorf("the old address still maps to %q — the account is served at an address it left", got)
	}

	// The token and UUID indexes have to survive the targeted update, or the
	// subscriber's own link stops resolving after one visit.
	if _, err := svc.FindClientByUUID(mustUUID(t, svc, "m1")); err != nil {
		t.Errorf("the UUID index lost the account: %v", err)
	}
	if _, _, err := funcIP(svc, token, "203.0.113.11"); err != nil {
		t.Errorf("a second visit with the same token failed: %v", err)
	}
}

// mustUUID returns the UUID the index currently holds for an account.
func mustUUID(t *testing.T, svc *ClientService, id string) string {
	t.Helper()
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	c := svc.idMap[id]
	if c == nil {
		t.Fatalf("account %s is not indexed", id)
	}
	return c.UUID
}

// seedClient stores one account and rebuilds the indexes from disk, which is the
// state every one of these tests starts from.
func seedClient(t *testing.T, svc *ClientService, db *database.DB, c database.Client) database.Client {
	t.Helper()
	if c.UUID == "" {
		c.UUID = database.GenerateUUID()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	// Production backfills a registration secret at daemon start
	// (ensureRegisterSecrets); fixtures stand in for it here so every seeded
	// account is enrolable exactly as a real record would be.
	if c.RegisterSecret == "" {
		c.RegisterSecret = GenerateRegisterSecret()
	}
	if err := db.SaveClient(c); err != nil {
		t.Fatalf("SaveClient(%s): %v", c.ID, err)
	}
	svc.reloadCache()
	return c
}

// An expired subscription must stop being answered for while its credential still
// resolves: the portal has to be able to look the account up in order to tell the
// subscriber that it ran out, which is why only ipMap is filtered.
func TestExpiredAccountLeavesTheResolverIndexButKeepsItsCredential(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	const token = "tok-expired"
	seeded := seedClient(t, svc, db, database.Client{
		ID: "e1", Name: "expired", Token: token,
		AllowedIPs: []string{"203.0.113.20"}, Enabled: true,
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	if got := indexedIP(t, svc, "203.0.113.20"); got != "" {
		t.Errorf("the resolver index still serves the expired account (%q)", got)
	}
	if _, err := svc.FindClientByUUID(seeded.UUID); err != nil {
		t.Errorf("the portal cannot resolve the expired account by UUID: %v", err)
	}

	// The registration records the expiry — the account is disabled on disk —
	// so the index has to be refreshed even though an error came back. Called
	// directly, exactly as POST /ip/<token> reaches it: the portal page itself
	// stays read-only and never reaches this path.
	if _, _, err := svc.RegisterIP(token, seeded.RegisterSecret, "203.0.113.21"); !errors.Is(err, database.ErrClientExpired) {
		t.Fatalf("RegisterIP on an expired account = %v, want ErrClientExpired", err)
	}
	stored, err := db.GetClient("e1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.Enabled {
		t.Error("the expired account is still enabled on disk")
	}
	if got := indexedIP(t, svc, "203.0.113.21"); got != "" {
		t.Errorf("the expired account was indexed at the address it just visited from (%q)", got)
	}
	if _, err := svc.FindClientByUUID(seeded.UUID); err != nil {
		t.Errorf("the credential stopped resolving once the expiry was recorded: %v", err)
	}
}

// A disabled account is the operator's switch, and it has to work the same way an
// expiry does: no answers, but the link still resolves so the portal can explain
// itself instead of returning a 404.
func TestDisabledAccountIsNotServedButStillResolves(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	seeded := seedClient(t, svc, db, database.Client{
		ID: "d1", Name: "disabled", Token: "tok-disabled",
		AllowedIPs: []string{"203.0.113.30"}, Enabled: false,
	})

	if got := indexedIP(t, svc, "203.0.113.30"); got != "" {
		t.Errorf("the resolver index serves a disabled account (%q)", got)
	}
	if _, err := svc.FindClientByUUID(seeded.UUID); err != nil {
		t.Errorf("a disabled account stopped resolving by UUID: %v", err)
	}

	// Re-enabling through the service has to put it back in the resolver's index.
	if _, err := svc.ToggleClient("d1", true); err != nil {
		t.Fatalf("ToggleClient: %v", err)
	}
	if got := indexedIP(t, svc, "203.0.113.30"); got != "d1" {
		t.Errorf("a re-enabled account maps to %q, want d1", got)
	}
}

// Two subscriptions can pass through the same public address — a shared household
// connection, or a carrier NAT — and the second one to visit the portal claims it.
// When the first one later moves, its own de-index must not take the entry the
// second one now owns with it, or a paying account silently stops being answered
// for. This is the conditional delete in deindexLocked.
// Two subscriptions must not share one address through the portal: Phase B
// (Mantis C-04) refuses the second bind with ErrDuplicateIPConflict and leaves
// BOTH accounts intact — shared CGNAT addresses are ordinary on Iranian mobile
// networks, and auto-disabling a paying account over one is the cure killing
// the patient. The operator path (SetClientIP) deliberately has no such gate:
// a human who moves an address between accounts is an override, and the
// conditional de-index below is what keeps that move from breaking the account
// that previously held it.
func TestRegisterIPRefusesADuplicateAddressAndKeepsBothAccounts(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	const shared = "203.0.113.50"
	_ = seedClient(t, svc, db, database.Client{
		ID: "a1", Name: "first", Token: "tok-a",
		AllowedIPs: []string{shared}, Enabled: true,
	})
	seedClient(t, svc, db, database.Client{
		ID: "b1", Name: "second", Token: "tok-b",
		AllowedIPs: []string{"203.0.113.60"}, Enabled: true,
	})

	// The second account tries to claim the address the first holds: refused.
	if _, _, err := funcIP(svc, "tok-b", shared); !errors.Is(err, database.ErrDuplicateIPConflict) {
		t.Fatalf("portal bind over a bound address = %v, want ErrDuplicateIPConflict", err)
	}

	// The first account still owns the address.
	if got := indexedIP(t, svc, shared); got != "a1" {
		t.Fatalf("the shared address maps to %q after the refusal, want a1", got)
	}

	// Neither account was disabled by the refusal.
	for _, id := range []string{"a1", "b1"} {
		stored, err := db.GetClient(id)
		if err != nil {
			t.Fatalf("GetClient(%s): %v", id, err)
		}
		if !stored.Enabled {
			t.Errorf("account %s was disabled by a duplicate-address refusal", id)
		}
	}

	// The second account's own binding is untouched.
	if got := indexedIP(t, svc, "203.0.113.60"); got != "b1" {
		t.Errorf("the refused account lost its own binding (%q), want b1", got)
	}

	// The operator override still works: a human moving the address between
	// accounts is an explicit decision, and the conditional de-index must not
	// take the entry with the old owner.
	if err := svc.SetClientIP("b1", shared); err != nil {
		t.Fatalf("SetClientIP override: %v", err)
	}
	if got := indexedIP(t, svc, shared); got != "b1" {
		t.Fatalf("after the operator override the shared address maps to %q, want b1", got)
	}

	// And when the first account later moves away on its own, its de-index
	// must not take the entry the second account now owns with it.
	if _, _, err := funcIP(svc, "tok-a", "203.0.113.51"); err != nil {
		t.Fatalf("first account move: %v", err)
	}
	if got := indexedIP(t, svc, shared); got != "b1" {
		t.Errorf("the first account's move took the second account's entry with it (%q), want b1", got)
	}
}

func TestRefreshClientIndexStoresAPrivateCopy(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	const token = "tok-copy"
	seedClient(t, svc, db, database.Client{
		ID: "c1", Name: "copy", Token: token,
		AllowedIPs: []string{"203.0.113.80"}, Enabled: true,
		CustomPolicies: []string{"gaming"},
	})

	client, _, err := funcIP(svc, token, "203.0.113.81")
	if err != nil {
		t.Fatalf("RegisterIP: %v", err)
	}

	// Everything a later caller might plausibly change on its own copy.
	client.Enabled = false
	client.Name = "renamed"
	client.TrafficUsedBytes = 1 << 40
	client.AllowedIPs[0] = "203.0.113.82"
	if len(client.CustomPolicies) > 0 {
		client.CustomPolicies[0] = "unrestricted"
	}

	if got := indexedIP(t, svc, "203.0.113.81"); got != "c1" {
		t.Errorf("the registered address maps to %q, want c1", got)
	}
	if got := indexedIP(t, svc, "203.0.113.82"); got != "" {
		t.Errorf("the caller's slice mutation reached the resolver index (%q)", got)
	}

	svc.mu.RLock()
	indexed := svc.idMap["c1"]
	svc.mu.RUnlock()
	if indexed == nil {
		t.Fatal("the account is not indexed by ID")
	}
	if indexed == client {
		t.Fatal("the index holds the caller's own record, not a copy")
	}
	if !indexed.Enabled || indexed.Name != "copy" || indexed.TrafficUsedBytes != 0 {
		t.Errorf("the indexed copy followed the caller's mutations: enabled=%v name=%q used=%d",
			indexed.Enabled, indexed.Name, indexed.TrafficUsedBytes)
	}
	if len(indexed.CustomPolicies) != 1 || indexed.CustomPolicies[0] != "gaming" {
		t.Errorf("indexed CustomPolicies = %v, want [gaming]", indexed.CustomPolicies)
	}
}
