package bootstrap

import (
	"fmt"
	"log"
)

// migrationMarkerKey is the settings-bucket key holding the set of one-time
// boot migrations this database has already received. Each entry is written in
// the same transaction-free sequence as its effect (effect first, marker
// second), so a crash between the two re-runs the migration on next boot —
// which every migration must therefore tolerate.
const migrationMarkerKey = "migration"

// MigrateDefaultAllowAll converges a pre-v2.2.0 database onto the whitelist
// default.
//
// Before v2.2.0 the compiled default was allow_all=true and no record was ever
// stored until an operator touched the toggle, so a long-running install can
// sit on "no allow_all row at all" while genuinely meaning public mode. The
// v2.2.0 default is the opposite (unknown sources refused), and the user has
// decided an upgrading install follows it: the migration forces one write of
// allow_all=false and marks it done.
//
// Ordering guarantees, given the effect-first/marker-second write pair:
//
//   - Crash before the allow_all write: nothing changed; next boot retries.
//   - Crash between the two writes: allow_all=false is already correct; the
//     missing marker only causes one harmless rewrite of the same value.
//   - After the marker: never touched again — including by a later downgrade,
//     because the marker, not the version, is the gate.
//
// An operator who wants public mode back flips the dashboard toggle, which
// writes its own row; from then on the DB record wins over every default.
func MigrateDefaultAllowAll(store SettingsWriter) {
	if store == nil {
		return
	}
	migrations, err := loadMigrationMarkers(store)
	if err != nil {
		// Unreadable marker state is reported, not fatal: the daemon still
		// starts (with the compiled default) and the operator can see why the
		// migration did not claim to have run.
		log.Printf("[Bootstrap] could not read migration markers, skipping allow_all migration: %v", err)
		return
	}
	if migrations["whitelist_v2_2"] {
		return
	}
	if err := store.SetSetting("allow_all", false); err != nil {
		log.Printf("[Bootstrap] could not persist the v2.2.0 whitelist default (refusing sources by default): %v", err)
		return
	}
	migrations["whitelist_v2_2"] = true
	if err := store.SetSetting(migrationMarkerKey, migrations); err != nil {
		// See the crash-between-writes case above: the effect already landed;
		// the migration will simply run once more on some later boot and
		// rewrite the same value.
		log.Printf("[Bootstrap] whitelist default applied but the marker write failed (it will re-run harmlessly): %v", err)
		return
	}
	log.Printf("[Bootstrap] v2.2.0: client access whitelist enabled — unregistered sources are now refused. Re-enable public access from the dashboard if that is what you intended.")
}

// loadMigrationMarkers reads the marker set, treating an absent record as an
// empty set (a pre-v2.2.0 database) rather than an error.
func loadMigrationMarkers(store SettingsStore) (map[string]bool, error) {
	present, err := store.SettingExists(migrationMarkerKey)
	if err != nil {
		return nil, fmt.Errorf("inspect migration markers: %w", err)
	}
	if !present {
		return map[string]bool{}, nil
	}
	var markers map[string]bool
	if err := store.GetSetting(migrationMarkerKey, &markers); err != nil {
		return nil, fmt.Errorf("read migration markers: %w", err)
	}
	if markers == nil {
		return map[string]bool{}, nil
	}
	return markers, nil
}
