package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"hyperdns/internal/bootstrap"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/web"
)

func TestUnreadableSettingsAbortBeforeWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	right, err := crypto.NewCipher(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatalf("NewCipher(right): %v", err)
	}
	db, err := database.Open(path, right)
	if err != nil {
		t.Fatalf("Open(right): %v", err)
	}
	if err := db.SetSetting("server", &database.ServerSettings{APIKey: "fixture-api-key"}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}

	wrong, err := crypto.NewCipher(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewCipher(wrong): %v", err)
	}
	store, err := database.OpenForInspection(path, wrong)
	if err != nil {
		t.Fatalf("OpenForInspection: %v", err)
	}
	defer store.Close()

	server := &database.ServerSettings{WebPort: 8080}
	err = bootstrap.LoadPresentSettings(store, bootstrap.SettingSpec{Key: "server", Target: server})
	if err == nil {
		t.Fatal("wrong-key setting loaded without an error")
	}
	if server.WebPort != 8080 || server.APIKey != "" {
		t.Fatalf("failed load mutated defaults: %+v", server.Snapshot())
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close inspection: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(after): %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("inspection/failed setting load changed database bytes")
	}
}

func TestValidateStoredStateRejectsWrongAuthoritativeSettingSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	cipher, err := crypto.NewCipher(bytes.Repeat([]byte{0x64}, 32))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	db, err := database.Open(path, cipher)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.SetSetting("access", "not-an-access-object"); err != nil {
		t.Fatalf("SetSetting(access): %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}

	opened, err := database.OpenExisting(path, cipher)
	if err == nil {
		_ = opened.Close()
		t.Fatal("OpenExisting accepted the wrong schema for the access record")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(after): %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed validation changed database bytes")
	}
}

func TestOpenForInspectionDoesNotMigrateBeforeValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	legacy := []byte(`{"server":"legacy-cleartext"}`)
	bdb, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	if err := bdb.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("settings"))
		if err != nil {
			return err
		}
		if err := b.Put([]byte("server"), legacy); err != nil {
			return err
		}
		_, err = tx.CreateBucket([]byte("logs"))
		return err
	}); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	if err := bdb.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}

	cipher, err := crypto.NewCipher(bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	db, err := database.OpenForInspection(path, cipher)
	if err != nil {
		t.Fatalf("OpenForInspection: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(after): %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("inspection changed legacy records, buckets, or pages")
	}
}

// Releases before v1.5.0 stored the admin password in plaintext inside the
// (encrypted) settings record. Upgrading the binary has to convert it in place:
// if it does not, the plaintext stays on disk; if it converts wrongly, the
// operator is locked out of a live resolver.
func TestMigrateAdminPasswordConvertsPlaintext(t *testing.T) {
	const plaintext = "Zx7-quiet-lantern-vps"
	s := &database.ServerSettings{AdminUsername: "admin", AdminPassword: plaintext}

	if !migrateAdminPassword(s) {
		t.Fatal("migrateAdminPassword reported no change for a plaintext record")
	}
	if !crypto.IsPasswordHash(s.AdminPassword) {
		t.Fatalf("stored password is not a hash: %q", s.AdminPassword)
	}
	if strings.Contains(s.AdminPassword, plaintext) {
		t.Fatal("the plaintext survives inside the stored value")
	}
	// The password still has to open the door afterwards.
	if !crypto.VerifyPassword(s.AdminPassword, plaintext) {
		t.Fatal("the converted hash does not verify the original password")
	}
	if crypto.VerifyPassword(s.AdminPassword, plaintext+"x") {
		t.Fatal("the converted hash verifies a wrong password")
	}
	// This one satisfies the policy, so the nag must not be raised.
	if s.AdminPasswordWeak {
		t.Error("a policy-compliant plaintext was flagged weak")
	}
}

// The weak flag can only be computed while the plaintext is still readable —
// after hashing, the information is gone for good. So the conversion is the one
// and only chance to record it.
func TestMigrateAdminPasswordFlagsWeakPlaintext(t *testing.T) {
	for _, pw := range []string{"admin", "hyperdns", "12345", "password"} {
		t.Run(pw, func(t *testing.T) {
			s := &database.ServerSettings{AdminUsername: "admin", AdminPassword: pw}
			if !migrateAdminPassword(s) {
				t.Fatal("no change reported for a plaintext record")
			}
			if !crypto.IsPasswordHash(s.AdminPassword) {
				t.Fatalf("not hashed: %q", s.AdminPassword)
			}
			if !crypto.VerifyPassword(s.AdminPassword, pw) {
				t.Fatal("the converted hash does not verify the original password")
			}
			if !s.AdminPasswordWeak {
				t.Errorf("%q was not flagged weak, so the dashboard would never nag about it", pw)
			}
		})
	}
}

// Restarting the daemon must not re-hash a hash. Doing so would still verify, but
// it would rewrite the settings record on every boot for no reason.
func TestMigrateAdminPasswordIsIdempotent(t *testing.T) {
	const plaintext = "Kq4-amber-tunnel-road"
	hashed, err := crypto.HashPasswordWithCost(plaintext, 1000)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	s := &database.ServerSettings{AdminUsername: "admin", AdminPassword: hashed}

	if migrateAdminPassword(s) {
		t.Fatal("migrateAdminPassword reported a change for an already-hashed record")
	}
	if s.AdminPassword != hashed {
		t.Fatal("an already-hashed record was rewritten")
	}
	if s.AdminPasswordWeak {
		t.Error("the weak flag was set from a hash, which cannot be inspected")
	}
}

// A settings record with no password at all is not a credential to upgrade — and
// hashing "" would turn an unusable record into one that authenticates an empty
// password.
func TestMigrateAdminPasswordIgnoresEmptyAndNil(t *testing.T) {
	if migrateAdminPassword(nil) {
		t.Error("migrateAdminPassword reported a change for nil")
	}
	s := &database.ServerSettings{AdminUsername: "admin"}
	if migrateAdminPassword(s) {
		t.Error("migrateAdminPassword reported a change for an empty password")
	}
	if s.AdminPassword != "" {
		t.Errorf("an empty password became %q", s.AdminPassword)
	}
}

// An empty master API key makes every REST call fail authentication, because both
// auth paths refuse to compare against "" — so the daemon has to fill one in
// rather than start with an API surface nothing can reach.
func TestEnsureAPIKeyFillsInAMissingKey(t *testing.T) {
	s := &database.ServerSettings{APIBind: "127.0.0.1"}

	if !ensureAPIKey(s) {
		t.Fatal("ensureAPIKey reported no change for an empty key")
	}
	if !strings.HasPrefix(s.APIKey, crypto.APIKeyPrefix) {
		t.Errorf("generated key %q does not carry the %q prefix the web auth path routes on",
			s.APIKey, crypto.APIKeyPrefix)
	}
	// Nothing else in the record may move: this runs against a live database on
	// upgrade, in the same pass that persists the settings.
	if s.APIBind != "127.0.0.1" {
		t.Errorf("APIBind became %q", s.APIBind)
	}
}

// A key the operator chose is a credential that may already be distributed, so
// only emptiness is repaired — a short or ugly key is left exactly as it is.
func TestEnsureAPIKeyLeavesAnExistingKeyAlone(t *testing.T) {
	const weakButChosen = "hdns_live_abc"

	s := &database.ServerSettings{APIKey: weakButChosen}
	if ensureAPIKey(s) {
		t.Error("ensureAPIKey reported a change for a key that was already set")
	}
	if s.APIKey != weakButChosen {
		t.Errorf("APIKey became %q, want the operator's own %q", s.APIKey, weakButChosen)
	}

	// A key with no prefix at all is still the operator's: the REST middleware
	// compares it whole and never tests for the prefix, so replacing it would
	// revoke a working credential.
	s = &database.ServerSettings{APIKey: "no-prefix-at-all"}
	if ensureAPIKey(s) {
		t.Error("ensureAPIKey reported a change for a prefixless key")
	}
	if s.APIKey != "no-prefix-at-all" {
		t.Errorf("a prefixless key became %q", s.APIKey)
	}
}

// nil is what a settings record looks like if an earlier step failed, and
// generating a key into nothing would panic on a path that runs before the
// resolver is listening.
func TestEnsureAPIKeyToleratesNil(t *testing.T) {
	if ensureAPIKey(nil) {
		t.Error("ensureAPIKey reported a change for nil")
	}
}

// Two records must not receive the same key. The generator is tested on its own
// in internal/crypto; this pins that this call site actually reaches it rather
// than filling in a constant.
func TestEnsureAPIKeyGeneratesADistinctKeyPerRecord(t *testing.T) {
	a, b := &database.ServerSettings{}, &database.ServerSettings{}
	ensureAPIKey(a)
	ensureAPIKey(b)

	if a.APIKey == b.APIKey {
		t.Errorf("two records were both given %q", a.APIKey)
	}
}

// A record with no admin path is a genuine first run, or a database migrated from
// a pre-v2.1 release. The path has to be generated and reported as a change, so
// the caller persists it in the same pass.
func TestEnsureAdminPathFillsInAMissingPath(t *testing.T) {
	s := &database.ServerSettings{}

	if !ensureAdminPath(s) {
		t.Fatal("ensureAdminPath reported no change for an empty path")
	}
	if !web.IsValidAdminPath(s.AdminPath) {
		t.Errorf("generated path %q is not a valid 16-character lowercase hex path",
			s.AdminPath)
	}
}

// The one-time property. Once a path is stored it is reloaded on every start, so
// a present path must be left alone — regenerating on each boot would move the
// panel out from under the operator, and the whole point of the path is that it
// stays constant.
func TestEnsureAdminPathLeavesAnExistingPathAlone(t *testing.T) {
	const chosen = "a1b2c3d4e5f67890"

	s := &database.ServerSettings{AdminPath: chosen}
	if ensureAdminPath(s) {
		t.Error("ensureAdminPath reported a change for a path that was already set")
	}
	if s.AdminPath != chosen {
		t.Errorf("AdminPath became %q, want the operator's own %q", s.AdminPath, chosen)
	}
}

// nil is what a settings record looks like if an earlier step failed, and
// generating a path into nothing would panic on a path that runs before the
// listeners are up.
func TestEnsureAdminPathToleratesNil(t *testing.T) {
	if ensureAdminPath(nil) {
		t.Error("ensureAdminPath reported a change for nil")
	}
}

// Two records must not receive the same path. The generator is tested on its own
// in internal/web; this pins that this call site actually reaches it rather than
// filling in a constant.
func TestEnsureAdminPathGeneratesADistinctPathPerRecord(t *testing.T) {
	a, b := &database.ServerSettings{}, &database.ServerSettings{}
	ensureAdminPath(a)
	ensureAdminPath(b)

	if a.AdminPath == b.AdminPath {
		t.Errorf("two records were both given %q", a.AdminPath)
	}
}

// The null device is the whole reason this helper exists. /dev/null is a
// character device, so the mode-bits-only check that came before answered "yes,
// a terminal" for it — and /dev/null is exactly what `docker run -d`,
// `docker compose up -d`, cron and systemd's default StandardInput=null hand a
// process. Every one of them started the console menu, read EOF from it and
// exited, taking DNS, DoT, DoH, the relay and the dashboard down with it. A
// container that dies one second after `docker compose up -d` reports success is
// the single worst failure this repo has shipped; it stays covered.
func TestStdinIsInteractiveRejectsTheNullDevice(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("could not open %s: %v", os.DevNull, err)
	}
	defer f.Close()

	if stdinIsInteractive(f) {
		t.Fatalf("%s was reported interactive, so a detached container would start the TUI and exit", os.DevNull)
	}
}

// `hyperdns < answers.txt` and any wrapper that redirects a file into the daemon.
// A regular file is not a character device, so this is the easy case — it is here
// so a future rewrite of the helper cannot regress it silently.
func TestStdinIsInteractiveRejectsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdin.txt")
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("could not write the fixture: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("could not open the fixture: %v", err)
	}
	defer f.Close()

	if stdinIsInteractive(f) {
		t.Error("a regular file was reported interactive, so `hyperdns < file` would run the menu instead of serving")
	}
}

// A pipe is what `echo 1 | hyperdns` and most process supervisors provide. Same
// class of mistake as the null device: something that produces one line and then
// EOF must never be mistaken for an operator.
func TestStdinIsInteractiveRejectsAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("could not create a pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if stdinIsInteractive(r) {
		t.Error("a pipe was reported interactive, so a supervised run would start the menu")
	}
}

// nil never reaches the real call site, which passes os.Stdin — but a helper that
// decides whether to hand the process to a blocking menu is the wrong place to
// panic, and this pins the guard rather than the comment promising it.
func TestStdinIsInteractiveRejectsNil(t *testing.T) {
	if stdinIsInteractive(nil) {
		t.Error("nil was reported interactive")
	}
}

// A closed descriptor makes Stat fail. The daemon must read that as "no console"
// and go on serving; treating an unreadable stdin as a terminal would start a
// menu that can never be answered.
func TestStdinIsInteractiveRejectsAnUnstatableFile(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("could not open %s: %v", os.DevNull, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("could not close the fixture: %v", err)
	}

	if stdinIsInteractive(f) {
		t.Error("a closed file was reported interactive")
	}
}

// The true branch is deliberately not asserted here: it needs a controlling
// terminal, which `go test` does not have on any CI runner or inside the release
// container. What it accepts is "a character device that is not the null device",
// so /dev/zero would pass — no deployment hands a daemon /dev/zero on stdin, and
// the alternative (build-tagged ioctl probes per OS) cannot be compiled or tested
// on the Windows workstation this repo is developed on.
