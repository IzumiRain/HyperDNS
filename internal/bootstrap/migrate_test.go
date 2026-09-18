package bootstrap

import (
	"path/filepath"
	"testing"

	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

// openTestStore creates a real encrypted database in a temp dir, because the
// migration's guarantees (marker persistence, DB-wins layering) are about what
// actually lands in the bucket, not what an in-memory fake would claim.
func openTestStore(t *testing.T) *database.DB {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if _, err := crypto.LoadOrGenerateMasterKey(keyPath); err != nil {
		t.Fatalf("create master key: %v", err)
	}
	db, err := database.Create(filepath.Join(dir, "data.db"), mustCipher(t, keyPath))
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustCipher(t *testing.T, keyPath string) *crypto.Cipher {
	t.Helper()
	c, err := crypto.LoadOrGenerateMasterKey(keyPath)
	if err != nil {
		t.Fatalf("load master key: %v", err)
	}
	return c
}

// TestMigrateDefaultAllowAllConvergesOnce: the first call flips allow_all and
// writes the marker; a second call leaves whatever the operator has since
// chosen untouched.
func TestMigrateDefaultAllowAllConvergesOnce(t *testing.T) {
	db := openTestStore(t)

	MigrateDefaultAllowAll(db)

	var allowAll bool = true
	if err := db.GetSetting("allow_all", &allowAll); err != nil {
		t.Fatalf("read allow_all after migration: %v", err)
	}
	if allowAll {
		t.Error("migration did not persist allow_all=false")
	}
	var markers map[string]bool
	if err := db.GetSetting(migrationMarkerKey, &markers); err != nil {
		t.Fatalf("read markers after migration: %v", err)
	}
	if !markers["whitelist_v2_2"] {
		t.Errorf("migration marker missing after run: %v", markers)
	}

	// The operator re-enables public mode from the dashboard.
	if err := db.SetSetting("allow_all", true); err != nil {
		t.Fatalf("operator toggle: %v", err)
	}
	MigrateDefaultAllowAll(db) // second boot
	if err := db.GetSetting("allow_all", &allowAll); err != nil {
		t.Fatalf("re-read allow_all: %v", err)
	}
	if !allowAll {
		t.Error("second migration run overrode the operator's explicit public mode")
	}
}

// TestMigrateDefaultAllowAllRerunIsIdempotent: crash between the effect write
// and the marker write must converge without damage — the effect rewrites the
// same value.
func TestMigrateDefaultAllowAllRerunIsIdempotent(t *testing.T) {
	db := openTestStore(t)

	MigrateDefaultAllowAll(db)
	// Simulate the crash window: the marker is gone but allow_all already
	// landed. Re-running must rewrite the same false and restore the marker.
	if err := db.SetSetting(migrationMarkerKey, map[string]bool{}); err != nil {
		t.Fatalf("wipe markers: %v", err)
	}
	MigrateDefaultAllowAll(db)

	var allowAll bool = true
	if err := db.GetSetting("allow_all", &allowAll); err != nil {
		t.Fatalf("read allow_all: %v", err)
	}
	if allowAll {
		t.Error("idempotent re-run flipped the mode back to public")
	}
}

// TestMigrateDefaultAllowAllNilWriterIsSilent: the guard contract — a nil store
// (impossible in main, defensive here) must not panic.
func TestMigrateDefaultAllowAllNilWriterIsSilent(t *testing.T) {
	MigrateDefaultAllowAll(nil)
}

// TestMigrationDoesNotTouchOtherSettings: the migration writes exactly two
// keys and nothing else in the settings bucket.
func TestMigrationDoesNotTouchOtherSettings(t *testing.T) {
	db := openTestStore(t)
	if err := db.SetSetting("server", map[string]any{"web_port": 18080}); err != nil {
		t.Fatalf("seed server setting: %v", err)
	}

	MigrateDefaultAllowAll(db)

	var server map[string]any
	if err := db.GetSetting("server", &server); err != nil {
		t.Fatalf("read server setting: %v", err)
	}
	if port, _ := server["web_port"].(float64); port != 18080 {
		t.Errorf("migration clobbered an unrelated setting: %v", server)
	}
}
