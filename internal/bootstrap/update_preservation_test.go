package bootstrap

import (
	"path/filepath"
	"testing"

	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

// TestUpdatePreservesDataAcrossReopen simulates what a binary update does to the
// data on disk: nothing. The same data.db + master.key are reopened by the
// "new" binary, boot migrations run, and every existing subscriber, the admin
// credential, and the operator's settings must still be there afterwards. This
// is the guarantee 2.2 -> 2.5 upgraders depend on (feature: data preservation on
// update) — the updater only swaps the binary and backs these files up, never
// rewrites them.
func TestUpdatePreservesDataAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	dbPath := filepath.Join(dir, "data.db")
	if _, err := crypto.LoadOrGenerateMasterKey(keyPath); err != nil {
		t.Fatalf("key: %v", err)
	}

	// --- "old install": a subscriber, an admin credential, and pre-2.2 state.
	db, err := database.Create(dbPath, mustCipher(t, keyPath))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.SaveClient(database.Client{
		ID: "sub1", Name: "Alice", Token: "tok-alice", Enabled: true,
		RegisterSecret: "s", AllowedIPs: []string{"203.0.113.5"},
	}); err != nil {
		t.Fatalf("save client: %v", err)
	}
	if err := db.SetSetting("server", map[string]any{
		"admin_username": "admin", "admin_password": "hashed-secret", "web_port": 28443,
	}); err != nil {
		t.Fatalf("save server settings: %v", err)
	}
	if err := db.SetSetting("allow_all", true); err != nil {
		t.Fatalf("allow_all: %v", err)
	}
	db.Close()

	// --- "new binary starts": reopen the SAME files and run boot migrations.
	db2, err := database.OpenExisting(dbPath, mustCipher(t, keyPath))
	if err != nil {
		t.Fatalf("reopen after update: %v", err)
	}
	defer db2.Close()
	MigrateDefaultAllowAll(db2)

	// The subscriber survived intact.
	c, err := db2.GetClient("sub1")
	if err != nil {
		t.Fatalf("subscriber lost across update: %v", err)
	}
	if c.Name != "Alice" || len(c.AllowedIPs) != 1 || c.AllowedIPs[0] != "203.0.113.5" {
		t.Fatalf("subscriber data changed across update: %+v", c)
	}

	// The admin credential survived.
	var server map[string]any
	if err := db2.GetSetting("server", &server); err != nil {
		t.Fatalf("server settings lost across update: %v", err)
	}
	if server["admin_password"] != "hashed-secret" || server["admin_username"] != "admin" {
		t.Fatalf("admin credential changed across update: %+v", server)
	}

	// And the v2.2 whitelist migration converged on the reopened DB.
	var allowAll bool
	if err := db2.GetSetting("allow_all", &allowAll); err != nil {
		t.Fatalf("allow_all read: %v", err)
	}
	if allowAll {
		t.Fatal("v2.2 whitelist migration did not run on the reopened DB (allow_all still true)")
	}
}
