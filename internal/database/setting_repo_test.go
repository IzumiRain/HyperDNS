package database

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"hyperdns/internal/crypto"
)

// settingsFixture opens a database in a fresh directory. bbolt takes an exclusive
// file lock, so every test needs its own path.
func settingsFixture(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data.db")
	c, err := crypto.NewCipher(bytes.Repeat([]byte{0x2f}, 32))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	db, err := Open(path, c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// rawSetting reads a value through an open handle without going through the
// codec. It deliberately does not reopen the file: bbolt holds an exclusive lock
// for the life of a handle, so a second Open on the same path would block. What
// this needs to bypass is the encoding, not the handle.
func rawSetting(t *testing.T, db *DB, key string) []byte {
	t.Helper()
	var out []byte
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if b == nil {
			return nil
		}
		out = append([]byte(nil), b.Get([]byte(key))...)
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	return out
}

// rawSettingAt reads a value straight out of a closed database file. This is the
// only way to see what a copied backup would actually expose.
func rawSettingAt(t *testing.T, path, key string) []byte {
	t.Helper()
	bdb, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("reopen %s: %v", path, err)
	}
	defer func() { _ = bdb.Close() }()

	var out []byte
	if err := bdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if b == nil {
			return nil
		}
		out = append([]byte(nil), b.Get([]byte(key))...)
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	return out
}

type settingsProbe struct {
	AdminPassword string `json:"admin_password"`
	APIKey        string `json:"api_key"`
	WebPort       int    `json:"web_port"`
	Weak          bool   `json:"admin_password_weak"`
}

// Until v1.5.0 the settings bucket was the one place that stored its contents in
// the clear, so `strings data.db` on any copied backup printed the admin password
// verifier and the live REST API key — no master.key required. This asserts on the
// raw file, because a round-trip test passes either way.
func TestSettingsAreEncryptedAtRest(t *testing.T) {
	db := settingsFixture(t)

	const verifier = "pbkdf2-sha256$600000$c2FsdHNhbHQ$aGFzaGhhc2g"
	const apiKey = "hdns_live_9f2c41aa77b0d3e5"
	want := settingsProbe{AdminPassword: verifier, APIKey: apiKey, WebPort: 8080}
	if err := db.SetSetting("server", want); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	raw := rawSetting(t, db, "server")
	if len(raw) == 0 {
		t.Fatal("nothing was written to the settings bucket")
	}
	if !bytes.HasPrefix(raw, []byte(settingEnvelopePrefix)) {
		t.Fatalf("the stored record carries no encryption envelope: %q", raw)
	}
	for _, secret := range []string{verifier, apiKey, "admin_password", "api_key"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the on-disk record still contains %q", secret)
		}
	}

	// And it has to come back out intact, or the encryption is just data loss.
	var got settingsProbe
	if err := db.GetSetting("server", &got); err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

// A live VPS holds real data, so the read path must keep understanding the plain
// JSON written by every earlier build. If it does not, upgrading the binary locks
// the operator out of their own resolver.
func TestGetSettingReadsLegacyCleartext(t *testing.T) {
	db := settingsFixture(t)

	legacy := []byte(`{"admin_password":"pbkdf2-sha256$600000$x$y","api_key":"hdns_live_legacy","web_port":18080}`)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSettings).Put([]byte("server"), legacy)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var got settingsProbe
	if err := db.GetSetting("server", &got); err != nil {
		t.Fatalf("GetSetting on a legacy record: %v", err)
	}
	if got.APIKey != "hdns_live_legacy" || got.WebPort != 18080 {
		t.Fatalf("legacy record decoded as %+v", got)
	}

	// Reading must not rewrite it; the conversion belongs to Open.
	if raw := rawSetting(t, db, "server"); !bytes.Equal(raw, legacy) {
		t.Errorf("GetSetting rewrote the stored record to %q", raw)
	}
}

// A pre-v2.1 database has a "server" record with no admin_path field. The read
// path must load it without error and leave the field at its zero value, so main
// sees "" and generates a path exactly once — it must not fabricate one here,
// because generating from the read path would produce a different path on the
// next process start. Reading must also not rewrite the stored record.
func TestGetSettingReadsLegacyRecordWithoutAdminPath(t *testing.T) {
	db := settingsFixture(t)

	legacy := []byte(`{"admin_username":"admin","admin_password":"pbkdf2-sha256$600000$s$h","api_key":"hdns_live_legacy","web_port":18080}`)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSettings).Put([]byte("server"), legacy)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var got ServerSettings
	if err := db.GetSetting("server", &got); err != nil {
		t.Fatalf("GetSetting on a legacy record: %v", err)
	}
	if got.AdminPath != "" {
		t.Errorf("a legacy record gained an admin path (%q) — the field must stay empty "+
			"so main's one-time generator can run", got.AdminPath)
	}
	// The rest of the record still has to come through.
	if got.APIKey != "hdns_live_legacy" || got.WebPort != 18080 {
		t.Errorf("legacy record decoded as %+v", got.Snapshot())
	}

	// Reading must not rewrite it; the path generation belongs to main's
	// deterministic first-run step, not to the read path.
	if raw := rawSetting(t, db, "server"); !bytes.Equal(raw, legacy) {
		t.Errorf("GetSetting rewrote the stored record to %q", raw)
	}
}

// Opening an older database has to convert it in place, automatically. This is the
// whole migration contract: the operator upgrades the binary and nothing else.
func TestOpenEncryptsLegacySettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	key := bytes.Repeat([]byte{0x71}, 32)

	// Write a database that looks exactly like a pre-v1.5.0 one: cleartext JSON in
	// the settings bucket.
	legacy := []byte(`{"admin_username":"admin","admin_password":"pbkdf2-sha256$600000$s$h","api_key":"hdns_live_before"}`)
	func() {
		bdb, err := bolt.Open(path, 0600, nil)
		if err != nil {
			t.Fatalf("create legacy db: %v", err)
		}
		defer func() { _ = bdb.Close() }()
		if err := bdb.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists(bucketSettings)
			if err != nil {
				return err
			}
			if err := b.Put([]byte("server"), legacy); err != nil {
				return err
			}
			// A second key proves the pass is not hardcoded to "server".
			return b.Put([]byte("tls"), []byte(`{"enabled":false}`))
		}); err != nil {
			t.Fatalf("seed legacy db: %v", err)
		}
	}()

	c, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	db, err := Open(path, c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var got settingsProbe
	if err := db.GetSetting("server", &got); err != nil {
		t.Fatalf("GetSetting after migration: %v", err)
	}
	if got.APIKey != "hdns_live_before" {
		t.Fatalf("the migration lost the stored value: %+v", got)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, key := range []string{"server", "tls"} {
		raw := rawSettingAt(t, path, key)
		if !bytes.HasPrefix(raw, []byte(settingEnvelopePrefix)) {
			t.Errorf("%q was not converted: %q", key, raw)
		}
	}
	if bytes.Contains(rawSettingAt(t, path, "server"), []byte("hdns_live_before")) {
		t.Error("the API key is still readable in the migrated file")
	}

	// And the whole file, not just the live record. bbolt frees the page a rewritten
	// record used but never zeroes it, so without the compaction step the old
	// cleartext survives in the file's free space and `strings data.db` on a copied
	// backup still hands over the verifier and the API key.
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, secret := range []string{"hdns_live_before", "pbkdf2-sha256$600000$s$h", "admin_password"} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Errorf("%q survives somewhere in the migrated file — the freed pages were not reclaimed", secret)
		}
	}
	if !bytes.Contains(blob, []byte(settingEnvelopePrefix)) {
		t.Error("the migrated file carries no encrypted record at all")
	}
	// The temporary copy must not be left behind next to the database.
	if _, err := os.Stat(path + ".compacting"); !os.IsNotExist(err) {
		t.Errorf("the compaction scratch file was left on disk: %v", err)
	}
}

// The conversion runs on every start, so a second start must be a no-op rather
// than a double-encryption or a needless rewrite.
func TestEncryptLegacySettingsIsIdempotent(t *testing.T) {
	db := settingsFixture(t)

	if err := db.SetSetting("server", settingsProbe{APIKey: "hdns_live_stable", WebPort: 443}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	before := rawSetting(t, db, "server")

	for i := range 3 {
		n, err := db.encryptLegacySettings()
		if err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if n != 0 {
			t.Fatalf("pass %d converted %d record(s), want 0", i, n)
		}
	}

	if after := rawSetting(t, db, "server"); !bytes.Equal(before, after) {
		t.Error("an already-encrypted record was rewritten")
	}
	var got settingsProbe
	if err := db.GetSetting("server", &got); err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if got.APIKey != "hdns_live_stable" || got.WebPort != 443 {
		t.Fatalf("value drifted to %+v", got)
	}
}

// The wrong master.key must say so. Silently treating an undecryptable record as
// absent would hand the operator a fresh random admin password and make them
// think the database was wiped.
func TestGetSettingRejectsTheWrongMasterKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")

	right, err := crypto.NewCipher(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	db, err := Open(path, right)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.SetSetting("server", settingsProbe{APIKey: "hdns_live_secret"}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	wrong, err := crypto.NewCipher(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}
	db2, err := Open(path, wrong)
	if err == nil {
		_ = db2.Close()
		t.Fatal("Open accepted settings sealed with a different key")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile(after): %v", readErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed wrong-key open changed the database")
	}

	// The record must survive: the fix is to restore the original key, so the
	// failed open must not destroy or re-seal anything.
	db3, err := Open(path, right)
	if err != nil {
		t.Fatalf("Open after restoring the key: %v", err)
	}
	defer func() { _ = db3.Close() }()
	var got settingsProbe
	if err := db3.GetSetting("server", &got); err != nil {
		t.Fatalf("GetSetting after restoring the key: %v", err)
	}
	if got.APIKey != "hdns_live_secret" {
		t.Fatalf("restored setting = %+v", got)
	}
}

// Without a master key the daemon still has to boot and still has to persist
// settings, because refusing to save is worse than saving in the clear — and the
// read path accepts both forms anyway.
func TestSettingsFallBackToCleartextWithoutACipher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	db, err := Open(path, nil)
	if err != nil {
		t.Fatalf("Open without a cipher: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.SetSetting("server", settingsProbe{WebPort: 9090}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	raw := rawSetting(t, db, "server")
	if bytes.HasPrefix(raw, []byte(settingEnvelopePrefix)) {
		t.Fatal("a record was sealed with no key loaded")
	}
	var got settingsProbe
	if err := db.GetSetting("server", &got); err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if got.WebPort != 9090 {
		t.Fatalf("round trip = %+v", got)
	}
}

func TestSettingExistsReportsPresenceAndErrors(t *testing.T) {
	db := settingsFixture(t)

	present, err := db.SettingExists("server")
	if err != nil {
		t.Fatalf("SettingExists(absent): %v", err)
	}
	if present {
		t.Fatal("SettingExists reported a key that was never written")
	}
	if err := db.SetSetting("server", settingsProbe{}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	present, err = db.SettingExists("server")
	if err != nil {
		t.Fatalf("SettingExists(present): %v", err)
	}
	if !present {
		t.Fatal("SettingExists missed a persisted zero value")
	}

	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := db.SettingExists("server"); err == nil {
		t.Fatal("SettingExists swallowed the closed-database transaction error")
	}
}

func TestValidateSettingsRejectsAnyUnreadableRecord(t *testing.T) {
	db := settingsFixture(t)
	if err := db.SetSetting("server", settingsProbe{APIKey: "hdns_live_valid"}); err != nil {
		t.Fatalf("SetSetting(server): %v", err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSettings).Put([]byte("auth"), []byte(settingEnvelopePrefix+"not-ciphertext"))
	}); err != nil {
		t.Fatalf("seed invalid auth setting: %v", err)
	}

	if err := db.ValidateSettings(); err == nil {
		t.Fatal("ValidateSettings accepted an unreadable setting")
	}
}

func TestValidateSettingsAcceptsLegacyAndEncryptedRecords(t *testing.T) {
	db := settingsFixture(t)
	if err := db.SetSetting("server", settingsProbe{APIKey: "hdns_live_valid"}); err != nil {
		t.Fatalf("SetSetting(server): %v", err)
	}
	legacy := []byte(`{"enabled":false}`)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSettings).Put([]byte("tls"), legacy)
	}); err != nil {
		t.Fatalf("seed legacy tls setting: %v", err)
	}

	if err := db.ValidateSettings(); err != nil {
		t.Fatalf("ValidateSettings: %v", err)
	}
	if raw := rawSetting(t, db, "tls"); !bytes.Equal(raw, legacy) {
		t.Fatalf("validation rewrote legacy setting: %q", raw)
	}
}

func TestValidateSettingsRejectsInvalidAuthoritativeTopLevelSchemas(t *testing.T) {
	var tests []struct {
		key string
		raw string
	}
	for _, key := range []string{"server", "dns", "sniproxy", "tls", "subscription", "auth", "access"} {
		tests = append(tests,
			struct {
				key string
				raw string
			}{key: key, raw: `null`},
			struct {
				key string
				raw string
			}{key: key, raw: `[]`},
		)
	}
	for _, raw := range []string{`null`, `{}`, `"true"`, `1`, `[]`} {
		tests = append(tests, struct {
			key string
			raw string
		}{key: "allow_all", raw: raw})
	}

	for _, tt := range tests {
		t.Run(tt.key+"_"+tt.raw, func(t *testing.T) {
			db := settingsFixture(t)
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(bucketSettings).Put([]byte(tt.key), []byte(tt.raw))
			}); err != nil {
				t.Fatalf("seed %s: %v", tt.key, err)
			}
			if err := db.ValidateSettings(); err == nil {
				t.Fatalf("ValidateSettings accepted %s=%s", tt.key, tt.raw)
			}
		})
	}
}

func TestValidateSettingsAcceptsAuthoritativeTopLevelSchemas(t *testing.T) {
	db := settingsFixture(t)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		for _, key := range []string{"server", "dns", "sniproxy", "tls", "subscription", "auth", "access"} {
			if err := b.Put([]byte(key), []byte(`{}`)); err != nil {
				return err
			}
		}
		return b.Put([]byte("allow_all"), []byte(`false`))
	}); err != nil {
		t.Fatalf("seed valid authoritative settings: %v", err)
	}
	if err := db.ValidateSettings(); err != nil {
		t.Fatalf("ValidateSettings: %v", err)
	}
}

func TestValidateSettingsRejectsWrongAuthoritativeFieldTypes(t *testing.T) {
	tests := []struct {
		key string
		raw string
	}{
		{key: "server", raw: `{"web_port":"443"}`},
		{key: "dns", raw: `{"enabled":"true"}`},
		{key: "sniproxy", raw: `{"http_port":"80"}`},
		{key: "tls", raw: `{"panel_https":"true"}`},
		{key: "subscription", raw: `{"port":"443"}`},
		{key: "auth", raw: `{"ldap_enabled":"true"}`},
		{key: "access", raw: `{"doh_tokens":"one-token"}`},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			db := settingsFixture(t)
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(bucketSettings).Put([]byte(tt.key), []byte(tt.raw))
			}); err != nil {
				t.Fatalf("seed %s: %v", tt.key, err)
			}
			if err := db.ValidateSettings(); err == nil {
				t.Fatalf("ValidateSettings accepted %s=%s", tt.key, tt.raw)
			}
		})
	}
}

// HasSetting has to tell "absent" from "present but zero" without looking inside
// the value, so the envelope must not change its behaviour. Callers rely on it to
// decide whether a config-file value is a first-run default or an override of a
// deliberate choice.
func TestHasSettingIgnoresTheEnvelope(t *testing.T) {
	db := settingsFixture(t)

	if db.HasSetting("server") {
		t.Fatal("HasSetting reported a key that was never written")
	}
	// A zero value is still a persisted decision.
	if err := db.SetSetting("server", settingsProbe{}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if !db.HasSetting("server") {
		t.Error("HasSetting missed a persisted zero value")
	}
	if err := db.SetSetting("allow_all", false); err != nil {
		t.Fatalf("SetSetting(bool): %v", err)
	}
	if !db.HasSetting("allow_all") {
		t.Error("HasSetting missed a persisted false")
	}
	var flag bool
	if err := db.GetSetting("allow_all", &flag); err != nil {
		t.Fatalf("GetSetting(bool): %v", err)
	}
	if flag {
		t.Error("a stored false read back as true")
	}
}

// An absent key must leave the target untouched and report success, because the
// config-file default is layered underneath it.
func TestGetSettingLeavesTargetAloneWhenAbsent(t *testing.T) {
	db := settingsFixture(t)

	got := settingsProbe{WebPort: 18080, APIKey: "from-config-file"}
	if err := db.GetSetting("nothing-here", &got); err != nil {
		t.Fatalf("GetSetting on an absent key: %v", err)
	}
	if got.WebPort != 18080 || got.APIKey != "from-config-file" {
		t.Fatalf("an absent key overwrote the caller's defaults: %+v", got)
	}
}

// Guard against the envelope prefix ever being changed to something a JSON
// document could start with — that would make the two forms ambiguous and a
// legacy record could be misread as ciphertext.
func TestEnvelopePrefixCannotBeValidJSON(t *testing.T) {
	first := settingEnvelopePrefix[0]
	for _, c := range []byte(`{[""` + "tfn0123456789 \t\r\n-") {
		if first == c {
			t.Fatalf("the envelope prefix starts with %q, which a JSON document can also start with", first)
		}
	}
}
