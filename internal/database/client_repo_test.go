package database

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"hyperdns/internal/crypto"
)

// clientsFixture opens a database in a fresh directory, keyed differently from
// settingsFixture so a record sealed by one can never accidentally decrypt under
// the other. bbolt takes an exclusive file lock, so every test needs its own path.
func clientsFixture(t *testing.T) *DB {
	t.Helper()
	c := testCipher(t, 0x5c)
	db, err := Open(filepath.Join(t.TempDir(), "data.db"), c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testCipher(t *testing.T, keyByte byte) *crypto.Cipher {
	t.Helper()
	c, err := crypto.NewCipher(bytes.Repeat([]byte{keyByte}, 32))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

// rawClient reads a stored client record through an open handle, without going
// through the codec. It does not reopen the file: bbolt holds an exclusive lock
// for the life of a handle, so a second Open on the same path would block.
func rawClient(t *testing.T, db *DB, id string) encClient {
	t.Helper()
	return decodeRawClient(t, rawClientBlob(t, db, id))
}

func rawClientBlob(t *testing.T, db *DB, id string) []byte {
	t.Helper()
	var blob []byte
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		if b == nil {
			return nil
		}
		blob = append([]byte(nil), b.Get([]byte(id))...)
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	return blob
}

// rawClientAt reads a record straight out of a closed database file, which is the
// only way to see what a copied backup would actually expose.
func rawClientAt(t *testing.T, path, id string) encClient {
	t.Helper()
	bdb, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("reopen %s: %v", path, err)
	}
	defer func() { _ = bdb.Close() }()

	var blob []byte
	if err := bdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		if b == nil {
			return nil
		}
		blob = append([]byte(nil), b.Get([]byte(id))...)
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	return decodeRawClient(t, blob)
}

func decodeRawClient(t *testing.T, blob []byte) encClient {
	t.Helper()
	if len(blob) == 0 {
		t.Fatal("nothing was written to the clients bucket")
	}
	var enc encClient
	if err := json.Unmarshal(blob, &enc); err != nil {
		t.Fatalf("the stored record is not JSON: %v", err)
	}
	return enc
}

// putRawClient writes a record in whatever shape the test asks for, bypassing
// packClient. This is how a pre-v1.5.0 record is reproduced.
func putRawClient(t *testing.T, db *DB, enc encClient) {
	t.Helper()
	putRawClientBlob(t, db, enc.ID, mustMarshalClient(t, enc))
}

func mustMarshalClient(t *testing.T, enc encClient) []byte {
	t.Helper()
	blob, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return blob
}

func putRawClientBlob(t *testing.T, db *DB, key string, blob []byte) {
	t.Helper()
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketClients).Put([]byte(key), blob)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// seedLegacyClientFile creates a database file that looks exactly like one an
// older build left behind, then closes it so Open can be tested against it.
func seedLegacyClientFile(t *testing.T, path string, enc encClient) {
	t.Helper()
	blob, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	bdb, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("create legacy db: %v", err)
	}
	defer func() { _ = bdb.Close() }()
	if err := bdb.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketClients)
		if err != nil {
			return err
		}
		return b.Put([]byte(enc.ID), blob)
	}); err != nil {
		t.Fatalf("seed legacy db: %v", err)
	}
}

// The subscription token is the credential a subscriber pastes into their device
// and the thing a reseller sells. Until v1.5.0 it sat in the clients bucket in the
// clear, next to a sealed name and a sealed IP list, so a copied data.db handed
// over every live subscription with no master.key required. This asserts on the
// raw record, because a round-trip test passes either way.
func TestClientTokenIsEncryptedAtRest(t *testing.T) {
	db := clientsFixture(t)

	const token = "hdns_sub_7c41f9aa20b6"
	want := Client{
		ID:         "42",
		Name:       "Reseller Customer",
		Token:      token,
		AllowedIPs: []string{"203.0.113.9"},
		Enabled:    true,
	}
	if err := db.SaveClient(want); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	enc := rawClient(t, db, "42")
	if enc.Token != "" {
		t.Errorf("the token was written to the legacy cleartext field: %q", enc.Token)
	}
	if enc.TokenEnc == "" {
		t.Error("the record carries no sealed token")
	}
	if enc.TokenMAC == "" {
		t.Error("the record carries no lookup fingerprint, so a token lookup would have to decrypt everything")
	}
	for _, secret := range []string{token, "Reseller Customer", "203.0.113.9"} {
		if enc.TokenEnc == secret || enc.TokenMAC == secret {
			t.Errorf("%q is stored verbatim", secret)
		}
	}

	got, err := db.GetClient("42")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.Token != token {
		t.Errorf("token round trip = %q, want %q", got.Token, token)
	}
	if got.Name != want.Name {
		t.Errorf("name round trip = %q", got.Name)
	}
	if len(got.AllowedIPs) != 1 || got.AllowedIPs[0] != "203.0.113.9" {
		t.Errorf("IP round trip = %v", got.AllowedIPs)
	}
}

// Sealing the token would be worthless if it broke the lookup the subscriber
// portal depends on. AES-GCM uses a fresh nonce per record, so two seals of the
// same token look unrelated and the match has to go through the fingerprint.
func TestFindClientByTokenMatchesASealedToken(t *testing.T) {
	db := clientsFixture(t)

	for _, c := range []Client{
		{ID: "1", Name: "one", Token: "hdns_sub_one", Enabled: true},
		{ID: "2", Name: "two", Token: "hdns_sub_two", Enabled: true},
	} {
		if err := db.SaveClient(c); err != nil {
			t.Fatalf("SaveClient(%s): %v", c.ID, err)
		}
	}

	got, err := db.FindClientByToken("hdns_sub_two")
	if err != nil {
		t.Fatalf("FindClientByToken: %v", err)
	}
	if got.ID != "2" {
		t.Fatalf("found client %q, want %q", got.ID, "2")
	}
	if got.Token != "hdns_sub_two" {
		t.Errorf("the matched record came back with token %q", got.Token)
	}

	// A near miss must not match, and an empty token must never match a record.
	for _, bogus := range []string{"hdns_sub_twx", "hdns_sub_tw", "hdns_sub_twoo", "HDNS_SUB_TWO", ""} {
		if _, err := db.FindClientByToken(bogus); !errors.Is(err, ErrClientNotFound) {
			t.Errorf("FindClientByToken(%q) = %v, want ErrClientNotFound", bogus, err)
		}
	}
}

// A live VPS holds real subscribers, so the read path must keep understanding a
// record written by every earlier build. If it does not, upgrading the binary
// silently disables every paying account.
func TestLegacyCleartextTokenKeepsWorking(t *testing.T) {
	db := clientsFixture(t)

	nameEnc, err := db.cipher.EncryptString("Legacy Customer")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	// The pre-v1.5.0 shape: name sealed, token in the clear, no UUID stored.
	putRawClient(t, db, encClient{ID: "77", NameEnc: nameEnc, Token: "hdns_sub_legacy", Enabled: true})

	got, err := db.GetClient("77")
	if err != nil {
		t.Fatalf("GetClient on a legacy record: %v", err)
	}
	if got.Token != "hdns_sub_legacy" {
		t.Errorf("legacy token decoded as %q", got.Token)
	}
	if got.Name != "Legacy Customer" {
		t.Errorf("legacy name decoded as %q", got.Name)
	}
	if want := db.generateDeterministicUUID("77", "hdns_sub_legacy"); got.UUID != want {
		t.Errorf("UUID = %q, want the deterministic %q", got.UUID, want)
	}

	found, err := db.FindClientByToken("hdns_sub_legacy")
	if err != nil {
		t.Fatalf("a legacy record could not be found by its own token: %v", err)
	}
	if found.ID != "77" {
		t.Errorf("found client %q", found.ID)
	}

	// Reading must not rewrite it; the conversion belongs to Open.
	if enc := rawClient(t, db, "77"); enc.Token == "" || enc.TokenEnc != "" {
		t.Error("a read rewrote the stored record")
	}
}

// Opening an older database has to convert it in place, automatically: the
// operator upgrades the binary and nothing else. The subscriber's link has to keep
// working across that conversion, and the old plaintext has to leave the file.
func TestOpenEncryptsLegacyClientTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	const token = "hdns_sub_beforeupgrade"
	c := testCipher(t, 0x36)

	nameEnc, err := c.EncryptString("Paying Subscriber")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	seedLegacyClientFile(t, path, encClient{ID: "9", NameEnc: nameEnc, Token: token, Enabled: true})
	wantUUID := (&DB{cipher: c}).generateDeterministicUUID("9", token)

	db, err := Open(path, c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	got, err := db.GetClient("9")
	if err != nil {
		t.Fatalf("GetClient after migration: %v", err)
	}
	if got.Token != token {
		t.Fatalf("the migration lost the token: %q", got.Token)
	}
	if got.Name != "Paying Subscriber" {
		t.Errorf("the migration disturbed the name: %q", got.Name)
	}
	// The UUID is what a subscription link is built from, so it must not move.
	if got.UUID != wantUUID {
		t.Errorf("the migration changed the client's UUID to %q, want %q", got.UUID, wantUUID)
	}
	if found, err := db.FindClientByToken(token); err != nil || found.ID != "9" {
		t.Fatalf("the subscriber's own token stopped authenticating after the migration: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	enc := rawClientAt(t, path, "9")
	if enc.Token != "" {
		t.Errorf("the token is still in the cleartext field: %q", enc.Token)
	}
	if enc.TokenEnc == "" || enc.TokenMAC == "" {
		t.Error("the record was not converted")
	}
	// Pinned during the migration, so the identity survives even if the key does not.
	if enc.UUID != wantUUID {
		t.Errorf("the stored UUID is %q, want %q", enc.UUID, wantUUID)
	}

	// And the whole file, not just the live record: bbolt frees the page a rewritten
	// record used but never zeroes it, so without the compaction step the old token
	// survives in the file's free space and a copied backup still hands it over.
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(blob, []byte(token)) {
		t.Error("the token survives somewhere in the migrated file — the freed pages were not reclaimed")
	}
	if _, err := os.Stat(path + ".compacting"); !os.IsNotExist(err) {
		t.Errorf("the compaction scratch file was left on disk: %v", err)
	}
}

// The conversion runs on every start, so a second start must be a no-op rather
// than a double-seal or a needless rewrite.
func TestEncryptLegacyClientTokensIsIdempotent(t *testing.T) {
	db := clientsFixture(t)

	if err := db.SaveClient(Client{ID: "5", Name: "stable", Token: "hdns_sub_stable", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	before := rawClientBlob(t, db, "5")

	for i := range 3 {
		n, err := db.encryptLegacyClientTokens()
		if err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if n != 0 {
			t.Fatalf("pass %d converted %d record(s), want 0", i, n)
		}
	}

	if after := rawClientBlob(t, db, "5"); !bytes.Equal(after, before) {
		t.Error("an already-sealed record was rewritten")
	}
	got, err := db.GetClient("5")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.Token != "hdns_sub_stable" {
		t.Fatalf("the token drifted to %q", got.Token)
	}
}

// An IP registration rewrites the record, which is the most common write on a live
// resolver. It must not lose the token it never saw in the clear on the wire.
func TestRegisterIPPreservesTheSealedToken(t *testing.T) {
	db := clientsFixture(t)

	const token = "hdns_sub_roaming"
	if err := db.SaveClient(Client{ID: "3", Name: "roamer", Token: token, Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	if _, _, err := db.RegisterClientIP(token, "198.51.100.7"); err != nil {
		t.Fatalf("RegisterClientIP: %v", err)
	}
	got, err := db.GetClient("3")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.Token != token {
		t.Fatalf("the token became %q after an IP registration", got.Token)
	}
	if len(got.AllowedIPs) != 1 || got.AllowedIPs[0] != "198.51.100.7" {
		t.Errorf("IP = %v", got.AllowedIPs)
	}
	if enc := rawClient(t, db, "3"); enc.Token != "" {
		t.Errorf("the rewrite put the token back in the clear: %q", enc.Token)
	}
	// The same token must still find it, so the fingerprint was rewritten too.
	if _, err := db.FindClientByToken(token); err != nil {
		t.Errorf("the token stopped matching after a rewrite: %v", err)
	}
}

func TestValidateClientsAcceptsLegacyAndEncryptedRecordsWithoutMutation(t *testing.T) {
	db := clientsFixture(t)
	if err := db.SaveClient(Client{ID: "sealed", Name: "sealed", Token: "hdns_sub_sealed", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	nameEnc, err := db.cipher.EncryptString("legacy")
	if err != nil {
		t.Fatalf("EncryptString(name): %v", err)
	}
	ipEnc, err := db.cipher.EncryptString(`[]`)
	if err != nil {
		t.Fatalf("EncryptString(IPs): %v", err)
	}
	putRawClient(t, db, encClient{ID: "legacy", NameEnc: nameEnc, Token: "hdns_sub_legacy", AllowedIPEnc: ipEnc, Enabled: true})
	beforeSealed := rawClientBlob(t, db, "sealed")
	beforeLegacy := rawClientBlob(t, db, "legacy")

	if err := db.ValidateClients(); err != nil {
		t.Fatalf("ValidateClients: %v", err)
	}
	if after := rawClientBlob(t, db, "sealed"); !bytes.Equal(after, beforeSealed) {
		t.Error("validation rewrote an encrypted client")
	}
	if after := rawClientBlob(t, db, "legacy"); !bytes.Equal(after, beforeLegacy) {
		t.Error("validation migrated a legacy client")
	}
}

func TestValidateClientsRejectsEveryUnreadableEncryptedField(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*encClient)
	}{
		{name: "name", mutate: func(c *encClient) { c.NameEnc = "not-ciphertext" }},
		{name: "token", mutate: func(c *encClient) { c.TokenEnc = "not-ciphertext" }},
		{name: "allowed IPs", mutate: func(c *encClient) { c.AllowedIPEnc = "not-ciphertext" }},
		{name: "register secret", mutate: func(c *encClient) { c.RegisterSecretEnc = "not-ciphertext" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := clientsFixture(t)
			if err := db.SaveClient(Client{
				ID: "validation", Name: "fixture", Token: "hdns_sub_fixture",
				AllowedIPs: []string{"198.51.100.8"}, RegisterSecret: "register-fixture", Enabled: true,
			}); err != nil {
				t.Fatalf("SaveClient: %v", err)
			}
			enc := rawClient(t, db, "validation")
			tt.mutate(&enc)
			putRawClient(t, db, enc)

			if err := db.ValidateClients(); err == nil {
				t.Fatal("ValidateClients accepted an unreadable authoritative field")
			}
		})
	}
}

func TestValidateClientsRejectsMalformedAllowedIPJSON(t *testing.T) {
	db := clientsFixture(t)
	if err := db.SaveClient(Client{ID: "validation-json", Name: "fixture", Token: "hdns_sub_fixture", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	enc := rawClient(t, db, "validation-json")
	sealed, err := db.cipher.EncryptString(`{"not":"an IP list"}`)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	enc.AllowedIPEnc = sealed
	putRawClient(t, db, enc)

	if err := db.ValidateClients(); err == nil {
		t.Fatal("ValidateClients accepted an encrypted IP field with invalid schema")
	}
}

func TestValidateClientsRejectsNullAllowedIPJSON(t *testing.T) {
	db := clientsFixture(t)
	if err := db.SaveClient(Client{ID: "validation-null-ips", Name: "fixture", Token: "hdns_sub_fixture", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	enc := rawClient(t, db, "validation-null-ips")
	sealed, err := db.cipher.EncryptString(`null`)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	enc.AllowedIPEnc = sealed
	putRawClient(t, db, enc)

	if err := db.ValidateClients(); err == nil {
		t.Fatal("ValidateClients accepted null instead of a JSON string array")
	}
}

func TestValidateClientsRejectsMismatchedEncryptedTokenFingerprint(t *testing.T) {
	db := clientsFixture(t)
	if err := db.SaveClient(Client{ID: "validation-mac", Name: "fixture", Token: "hdns_sub_fixture", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	enc := rawClient(t, db, "validation-mac")
	enc.TokenMAC = db.cipher.BlindIndex("hdns_sub_different")
	putRawClient(t, db, enc)

	if err := db.ValidateClients(); err == nil {
		t.Fatal("ValidateClients accepted a fingerprint that does not match the encrypted token")
	}
}

func TestValidateClientsRejectsMalformedRecordStructure(t *testing.T) {
	tests := []struct {
		name string
		key  string
		blob func(*testing.T, *DB) []byte
	}{
		{name: "null", key: "bad", blob: func(*testing.T, *DB) []byte { return []byte(`null`) }},
		{name: "array", key: "bad", blob: func(*testing.T, *DB) []byte { return []byte(`[]`) }},
		{name: "scalar", key: "bad", blob: func(*testing.T, *DB) []byte { return []byte(`1`) }},
		{name: "empty object", key: "bad", blob: func(*testing.T, *DB) []byte { return []byte(`{}`) }},
		{name: "empty id", key: "bad", blob: func(t *testing.T, db *DB) []byte {
			name, _ := db.cipher.EncryptString("name")
			return mustMarshalClient(t, encClient{NameEnc: name, Token: "legacy"})
		}},
		{name: "key id mismatch", key: "bucket-id", blob: func(t *testing.T, db *DB) []byte {
			name, _ := db.cipher.EncryptString("name")
			return mustMarshalClient(t, encClient{ID: "stored-id", NameEnc: name, Token: "legacy"})
		}},
		{name: "missing name identity", key: "bad", blob: func(t *testing.T, _ *DB) []byte {
			return mustMarshalClient(t, encClient{ID: "bad", Token: "legacy"})
		}},
		{name: "tokenless", key: "bad", blob: func(t *testing.T, db *DB) []byte {
			name, _ := db.cipher.EncryptString("name")
			return mustMarshalClient(t, encClient{ID: "bad", NameEnc: name})
		}},
		{name: "both token forms", key: "bad", blob: func(t *testing.T, db *DB) []byte {
			name, _ := db.cipher.EncryptString("name")
			token, _ := db.cipher.EncryptString("sealed")
			return mustMarshalClient(t, encClient{ID: "bad", NameEnc: name, Token: "legacy", TokenEnc: token, TokenMAC: "mac"})
		}},
		{name: "encrypted token missing mac", key: "bad", blob: func(t *testing.T, db *DB) []byte {
			name, _ := db.cipher.EncryptString("name")
			token, _ := db.cipher.EncryptString("sealed")
			return mustMarshalClient(t, encClient{ID: "bad", NameEnc: name, TokenEnc: token})
		}},
		{name: "mac without encrypted token", key: "bad", blob: func(t *testing.T, db *DB) []byte {
			name, _ := db.cipher.EncryptString("name")
			return mustMarshalClient(t, encClient{ID: "bad", NameEnc: name, Token: "legacy", TokenMAC: "mac"})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := clientsFixture(t)
			putRawClientBlob(t, db, tt.key, tt.blob(t, db))
			if err := db.ValidateClients(); err == nil {
				t.Fatal("ValidateClients accepted malformed client structure")
			}
		})
	}
}

func TestValidateClientsAcceptsDocumentedTokenFormats(t *testing.T) {
	db := clientsFixture(t)
	name, err := db.cipher.EncryptString("legacy")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	putRawClient(t, db, encClient{ID: "legacy", NameEnc: name, Token: "hdns_sub_legacy", Enabled: true})
	if err := db.SaveClient(Client{ID: "modern", Name: "modern", Token: "hdns_sub_modern", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := db.ValidateClients(); err != nil {
		t.Fatalf("ValidateClients: %v", err)
	}
}

// The wrong master.key must say so. Reading an undecryptable token as an empty
// string would be the worst outcome available: the next write — an IP
// registration, a traffic update — would persist that empty token and destroy the
// subscriber's credential permanently, with no way back even once the right key
// is restored.
func TestClientTokenRejectsTheWrongMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")

	db, err := Open(path, testCipher(t, 0x11))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.SaveClient(Client{ID: "8", Name: "sealed", Token: "hdns_sub_secret", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}
	db2, err := Open(path, testCipher(t, 0x22))
	if err == nil {
		_ = db2.Close()
		t.Fatal("Open accepted client records sealed with a different key")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile(after): %v", readErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed wrong-key open changed the database")
	}

	// The record must survive, because the fix is to restore the original key.
	db3, err := Open(path, testCipher(t, 0x11))
	if err != nil {
		t.Fatalf("reopen with the right key: %v", err)
	}
	defer func() { _ = db3.Close() }()
	got, err := db3.GetClient("8")
	if err != nil {
		t.Fatalf("GetClient after restoring the key: %v", err)
	}
	if got.Token != "hdns_sub_secret" {
		t.Fatalf("the token came back as %q", got.Token)
	}
}

// A record with neither form of token must not be matched by anything, or one
// malformed row would authenticate every guess.
func TestFindClientByTokenIgnoresATokenlessRecord(t *testing.T) {
	db := clientsFixture(t)

	putRawClient(t, db, encClient{ID: "empty", UUID: "fixed", Enabled: true})

	for _, guess := range []string{"", "anything", "hdns_sub_guess"} {
		if _, err := db.FindClientByToken(guess); !errors.Is(err, ErrClientNotFound) {
			t.Errorf("FindClientByToken(%q) = %v, want ErrClientNotFound", guess, err)
		}
	}
}

// A mixed database — some records converted, some not — is what a resolver looks
// like if an earlier conversion failed halfway. Both forms have to keep resolving.
func TestFindClientByTokenAcrossBothFormats(t *testing.T) {
	db := clientsFixture(t)

	if err := db.SaveClient(Client{ID: "new", Name: "new", Token: "hdns_sub_new", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	nameEnc, err := db.cipher.EncryptString("old")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	putRawClient(t, db, encClient{ID: "old", NameEnc: nameEnc, Token: "hdns_sub_old", Enabled: true})

	for token, wantID := range map[string]string{"hdns_sub_new": "new", "hdns_sub_old": "old"} {
		got, err := db.FindClientByToken(token)
		if err != nil {
			t.Fatalf("FindClientByToken(%q): %v", token, err)
		}
		if got.ID != wantID {
			t.Errorf("FindClientByToken(%q) found %q, want %q", token, got.ID, wantID)
		}
	}
}

// A client record has no cleartext fallback, unlike a settings record: the name,
// the IP list and the token are all sealed, so there is no half-encrypted shape to
// write. With no key loaded the save has to be refused outright — writing a record
// with three empty secrets would look like a successful save and quietly destroy
// the account. The daemon cannot reach this state (main.go exits if the master key
// cannot be loaded), so the only thing being pinned here is that a
// misconfiguration fails loudly instead of corrupting the bucket.
func TestSaveClientRefusesWithoutAMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	db, err := Open(path, nil)
	if err != nil {
		t.Fatalf("Open without a cipher: %v", err)
	}
	defer func() { _ = db.Close() }()

	err = db.SaveClient(Client{ID: "6", Name: "keyless", Token: "hdns_sub_nokey", Enabled: true})
	if err == nil {
		t.Fatal("SaveClient stored a client with no master key loaded")
	}
	if blob := rawClientBlob(t, db, "6"); len(blob) != 0 {
		t.Errorf("the refused save still wrote %q", blob)
	}

	// A legacy database opened without a key still has to be readable, because that
	// is how an operator diagnoses a missing master.key rather than a lost one.
	putRawClient(t, db, encClient{ID: "7", Token: "hdns_sub_legacy", Enabled: true})
	got, err := db.GetClient("7")
	if err != nil {
		t.Fatalf("GetClient on a legacy record with no key: %v", err)
	}
	if got.Token != "hdns_sub_legacy" {
		t.Errorf("legacy token read as %q", got.Token)
	}
	if found, err := db.FindClientByToken("hdns_sub_legacy"); err != nil || found.ID != "7" {
		t.Fatalf("FindClientByToken on a legacy record with no key: %v", err)
	}
}

// The subscription portal is a public URL, so a subscriber refreshing it — or a
// bot holding one valid token — drives this path as fast as it likes. Every visit
// used to commit a bbolt transaction, an fsync, to move LastSeen forward by a
// second. A repeat visit from an address that is already registered must not earn
// a write at all.
func TestRegisterIPSkipsTheWriteForAnUnchangedAddress(t *testing.T) {
	db := clientsFixture(t)

	const token = "hdns_sub_repeat"
	if err := db.SaveClient(Client{ID: "20", Name: "repeat", Token: token, Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	// First visit: nothing is registered yet, so it has to be written.
	if _, alreadyPresent, err := db.RegisterClientIP(token, "198.51.100.20"); err != nil {
		t.Fatalf("first RegisterClientIP: %v", err)
	} else if alreadyPresent {
		t.Fatal("the first registration reported the address as already present")
	}
	first := rawClientBlob(t, db, "20")

	// Second visit from the same address: the record must be untouched, byte for
	// byte. Comparing the sealed blob is the strongest available assertion —
	// AES-GCM uses a fresh nonce per write, so any rewrite changes every byte.
	_, alreadyPresent, err := db.RegisterClientIP(token, "198.51.100.20")
	if err != nil {
		t.Fatalf("second RegisterClientIP: %v", err)
	}
	if !alreadyPresent {
		t.Error("the repeat visit did not report the address as already present")
	}
	if second := rawClientBlob(t, db, "20"); !bytes.Equal(first, second) {
		t.Error("a repeat visit from an unchanged address rewrote the stored record")
	}

	// A different address still has to be persisted immediately: this is the whole
	// point of the endpoint.
	if _, alreadyPresent, err := db.RegisterClientIP(token, "198.51.100.21"); err != nil {
		t.Fatalf("moved RegisterClientIP: %v", err)
	} else if alreadyPresent {
		t.Error("a new address was reported as already present")
	}
	got, err := db.GetClient("20")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if len(got.AllowedIPs) != 1 || got.AllowedIPs[0] != "198.51.100.21" {
		t.Fatalf("stored AllowedIPs = %v, want the new address", got.AllowedIPs)
	}
}

// A stale LastSeen has to start moving again eventually, or the dashboard's
// "last seen" column would freeze for any subscriber whose address never changes.
func TestRegisterIPRefreshesAStaleLastSeen(t *testing.T) {
	db := clientsFixture(t)

	const token = "hdns_sub_stale"
	stale := time.Now().Add(-2 * lastSeenWriteInterval)
	if err := db.SaveClient(Client{
		ID: "21", Name: "stale", Token: token, Enabled: true,
		AllowedIPs: []string{"198.51.100.30"}, LastSeen: stale,
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	if _, alreadyPresent, err := db.RegisterClientIP(token, "198.51.100.30"); err != nil {
		t.Fatalf("RegisterClientIP: %v", err)
	} else if !alreadyPresent {
		t.Error("an unchanged address was not reported as already present")
	}

	got, err := db.GetClient("21")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !got.LastSeen.After(stale) {
		t.Fatalf("LastSeen stayed at %v, want it refreshed", got.LastSeen)
	}
}

// A flush persists every metered subscriber at once. Doing it one record at a
// time meant one fsync per account, and quota enforcement read a stale total for
// however long that took.
func TestAddClientTrafficAppliesEveryDelta(t *testing.T) {
	db := clientsFixture(t)

	for i, used := range map[string]uint64{"30": 100, "31": 0, "32": 7} {
		if err := db.SaveClient(Client{
			ID: i, Name: "meter " + i, Token: "tok-" + i, Enabled: true,
			TrafficUsedBytes: used,
		}); err != nil {
			t.Fatalf("SaveClient %s: %v", i, err)
		}
	}

	unapplied, err := db.AddClientTraffic(map[string]uint64{"30": 400, "31": 25, "32": 0})
	if err != nil {
		t.Fatalf("AddClientTraffic: %v", err)
	}
	if len(unapplied) != 0 {
		t.Fatalf("unapplied = %v, want none", unapplied)
	}

	for id, want := range map[string]uint64{"30": 500, "31": 25, "32": 7} {
		got, err := db.GetClient(id)
		if err != nil {
			t.Fatalf("GetClient %s: %v", id, err)
		}
		if got.TrafficUsedBytes != want {
			t.Errorf("client %s TrafficUsedBytes = %d, want %d", id, got.TrafficUsedBytes, want)
		}
	}

	// An empty call is a no-op, not an error: a flush with nothing pending is the
	// common case.
	if unapplied, err := db.AddClientTraffic(nil); err != nil || unapplied != nil {
		t.Fatalf("AddClientTraffic(nil) = %v, %v", unapplied, err)
	}
}

// Bytes belonging to a deleted account have nowhere to go. Reporting that as an
// error would make every later flush look broken to the operator; retrying them
// forever would keep it that way.
func TestAddClientTrafficDropsDeletedAccounts(t *testing.T) {
	db := clientsFixture(t)

	if err := db.SaveClient(Client{ID: "40", Name: "live", Token: "tok-40", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	unapplied, err := db.AddClientTraffic(map[string]uint64{"40": 90, "ghost": 999})
	if err != nil {
		t.Fatalf("AddClientTraffic: %v", err)
	}
	if _, held := unapplied["ghost"]; held {
		t.Error("bytes for a deleted account were handed back to be retried forever")
	}

	got, err := db.GetClient("40")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.TrafficUsedBytes != 90 {
		t.Fatalf("the live account got %d bytes, want 90", got.TrafficUsedBytes)
	}
}

// A failed transaction must hand every byte back. Losing them would make traffic
// free for as long as the fault lasted, which is the one outcome a reseller cannot
// tolerate.
func TestAddClientTrafficHandsEverythingBackOnFailure(t *testing.T) {
	db := clientsFixture(t)

	if err := db.SaveClient(Client{ID: "50", Name: "live", Token: "tok-50", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	deltas := map[string]uint64{"50": 123}
	unapplied, err := db.AddClientTraffic(deltas)
	if err == nil {
		t.Fatal("AddClientTraffic reported success against a closed database")
	}
	if unapplied["50"] != 123 {
		t.Fatalf("unapplied = %v, want the whole 123 handed back", unapplied)
	}
}

// bolt's Delete answers nil for a key it never held, so the repository has to do the
// existence check itself. Without it every front-end reported "deleted" for an ID that
// never existed: the REST route answered 200 {"deleted":true}, and the TUI printed a
// green tick at an operator who had mistyped the ID.
func TestDeleteClientReportsAMissingID(t *testing.T) {
	db := clientsFixture(t)

	if err := db.SaveClient(Client{ID: "60", Name: "live", Token: "tok-60", Enabled: true}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	if err := db.DeleteClient("NOPE0000"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("DeleteClient on an unknown ID = %v, want ErrClientNotFound", err)
	}

	// The stored record is untouched by the failed delete, and deleting it really does
	// succeed — the guard rejects a missing key, not every key.
	if _, err := db.GetClient("60"); err != nil {
		t.Fatalf("GetClient after the rejected delete: %v", err)
	}
	if err := db.DeleteClient("60"); err != nil {
		t.Fatalf("DeleteClient on a stored ID: %v", err)
	}
	if _, err := db.GetClient("60"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("GetClient after the delete = %v, want ErrClientNotFound", err)
	}

	// And a second delete of the same ID is now a 404 rather than a second success, so a
	// retried request cannot report that it removed a record twice.
	if err := db.DeleteClient("60"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("the second DeleteClient = %v, want ErrClientNotFound", err)
	}
}
