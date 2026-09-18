package database

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"hyperdns/internal/crypto"
)

func TestDatabase_ClientEncryptionAndCRUD(t *testing.T) {
	// A fixed filename in the package directory would survive a panic and be
	// reused by the next run, and bbolt's exclusive lock makes that a hang rather
	// than an error.
	tmpDB := filepath.Join(t.TempDir(), "test_hyperdns.db")

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	db, err := Open(tmpDB, cipher)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// 1. Add Client
	client := Client{
		ID:         "1001",
		Name:       "Sorena Gamer",
		Token:      "tok_abc123xyz",
		AllowedIPs: []string{"198.51.100.50"},
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
		CreatedAt:  time.Now(),
		Enabled:    true,
	}

	if err := db.SaveClient(client); err != nil {
		t.Fatalf("failed to save client: %v", err)
	}

	// 2. Fetch and Verify Decrypted Data
	fetched, err := db.GetClient("1001")
	if err != nil {
		t.Fatalf("failed to get client: %v", err)
	}

	if fetched.Name != "Sorena Gamer" {
		t.Errorf("expected name 'Sorena Gamer', got '%s'", fetched.Name)
	}
	if len(fetched.AllowedIPs) != 1 || fetched.AllowedIPs[0] != "198.51.100.50" {
		t.Errorf("unexpected allowed IPs: %v", fetched.AllowedIPs)
	}

	// 3. Test RegisterClientIP (Shelter/Shecan 1-IP Update)
	_, alreadyPresent, err := db.RegisterClientIP("tok_abc123xyz", "198.51.100.99")
	if err != nil {
		t.Fatalf("failed to register IP: %v", err)
	}
	if alreadyPresent {
		t.Errorf("expected alreadyPresent to be false on IP change")
	}

	updated, _ := db.GetClient("1001")
	if len(updated.AllowedIPs) != 1 || updated.AllowedIPs[0] != "198.51.100.99" {
		t.Errorf("IP was not strictly replaced: %v", updated.AllowedIPs)
	}
}

// bucketNames lists what a database file actually contains, read through an open
// handle.
func bucketNames(t *testing.T, db *DB) []string {
	t.Helper()
	var names []string
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			names = append(names, string(name))
			return nil
		})
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	return names
}

func hasBucket(names []string, want string) bool {
	return slices.Contains(names, want)
}

// A fresh database must not contain a `logs` bucket. Nothing has ever written DNS
// telemetry to disk — it lives in memory and on the SSE stream — and an empty
// bucket with that name reads as a claim that query history is persisted.
func TestOpenDoesNotCreateRetiredBuckets(t *testing.T) {
	db := clientsFixture(t)

	names := bucketNames(t, db)
	for _, retired := range []string{"logs", "upstreams"} {
		if hasBucket(names, retired) {
			t.Errorf("a fresh database created the retired %q bucket", retired)
		}
	}
	for _, live := range []string{"clients", "policies", "settings"} {
		if !hasBucket(names, live) {
			t.Errorf("a fresh database is missing the %q bucket", live)
		}
	}
}

// An existing installation already has the two stale buckets. Opening it has to
// drop them without touching anything else, and a second open has to be a no-op.
func TestOpenDropsEmptyRetiredBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	c := testCipher(t, 0x64)

	func() {
		bdb, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
		if err != nil {
			t.Fatalf("create legacy db: %v", err)
		}
		defer func() { _ = bdb.Close() }()
		if err := bdb.Update(func(tx *bolt.Tx) error {
			for _, name := range []string{"clients", "policies", "logs", "settings", "upstreams"} {
				if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed legacy db: %v", err)
		}
	}()

	for pass := range 2 {
		db, err := Open(path, c)
		if err != nil {
			t.Fatalf("Open pass %d: %v", pass, err)
		}
		names := bucketNames(t, db)
		for _, retired := range []string{"logs", "upstreams"} {
			if hasBucket(names, retired) {
				t.Errorf("pass %d left the %q bucket in place", pass, retired)
			}
		}
		for _, live := range []string{"clients", "policies", "settings"} {
			if !hasBucket(names, live) {
				t.Errorf("pass %d dropped the %q bucket", pass, live)
			}
		}
		// Still writable, so the drop did not disturb the live buckets.
		if err := db.SaveClient(Client{ID: "1", Name: "after", Token: "hdns_sub_after", Enabled: true}); err != nil {
			t.Fatalf("pass %d SaveClient: %v", pass, err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("pass %d Close: %v", pass, err)
		}
	}
}

// If one of those buckets somehow holds data, dropping it would be data loss, so
// the guard has to keep it.
func TestOpenKeepsARetiredBucketThatHoldsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")

	func() {
		bdb, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
		if err != nil {
			t.Fatalf("create legacy db: %v", err)
		}
		defer func() { _ = bdb.Close() }()
		if err := bdb.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("logs"))
			if err != nil {
				return err
			}
			return b.Put([]byte("1"), []byte(`{"domain":"example.com"}`))
		}); err != nil {
			t.Fatalf("seed legacy db: %v", err)
		}
	}()

	db, err := Open(path, testCipher(t, 0x65))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if !hasBucket(bucketNames(t, db), "logs") {
		t.Fatal("a bucket holding records was dropped")
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		if got := tx.Bucket([]byte("logs")).Get([]byte("1")); string(got) != `{"domain":"example.com"}` {
			t.Errorf("the retained record reads as %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestOpenExistingDoesNotCreateMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	db, err := OpenExisting(path, testCipher(t, 0x69))
	if err == nil {
		_ = db.Close()
		t.Fatal("OpenExisting created a missing database")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("missing database now exists: %v", statErr)
	}
}

func TestCreateRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	const fixture = "not-a-database"
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	db, err := Create(path, testCipher(t, 0x68))
	if err == nil {
		_ = db.Close()
		t.Fatal("Create reused an existing path")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read fixture: %v", readErr)
	}
	if string(got) != fixture {
		t.Fatalf("Create changed existing file to %q", got)
	}
}

func TestOpenRejectsInvalidExistingStoreBeforeAnyMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	bdb, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	if err := bdb.Update(func(tx *bolt.Tx) error {
		settings, err := tx.CreateBucket(bucketSettings)
		if err != nil {
			return err
		}
		if err := settings.Put([]byte("server"), []byte(`null`)); err != nil {
			return err
		}
		_, err = tx.CreateBucket(bucketLogs)
		return err
	}); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	if err := bdb.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	db, err := Open(path, testCipher(t, 0x6a))
	if err == nil {
		_ = db.Close()
		t.Fatal("Open accepted an invalid existing store")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rejected fixture: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed existing-store validation changed database bytes")
	}

	check, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("inspect rejected fixture: %v", err)
	}
	defer func() { _ = check.Close() }()
	if err := check.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketLogs) == nil {
			t.Error("Open dropped a retired bucket before validation")
		}
		if tx.Bucket(bucketClients) != nil || tx.Bucket(bucketPolicies) != nil {
			t.Error("Open created live buckets before validation")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect transaction: %v", err)
	}
}

func TestOpenValidatesThenMigratesExistingStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	bdb, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	if err := bdb.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(bucketSettings)
		if err != nil {
			return err
		}
		return b.Put([]byte("server"), []byte(`{"api_key":"legacy"}`))
	}); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	if err := bdb.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	validationReached := make(chan struct{})
	allowMigration := make(chan struct{})
	oldHook := afterExistingStoreValidation
	afterExistingStoreValidation = func() {
		close(validationReached)
		<-allowMigration
	}
	t.Cleanup(func() { afterExistingStoreValidation = oldHook })

	result := make(chan struct {
		db  *DB
		err error
	}, 1)
	go func() {
		db, err := OpenExisting(path, testCipher(t, 0x6b))
		result <- struct {
			db  *DB
			err error
		}{db: db, err: err}
	}()
	<-validationReached

	competing, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 50 * time.Millisecond})
	if err == nil {
		_ = competing.Close()
		close(allowMigration)
		t.Fatal("a competing writer opened after validation and before migration")
	}
	close(allowMigration)

	opened := <-result
	if opened.err != nil {
		t.Fatalf("OpenExisting: %v", opened.err)
	}
	defer func() { _ = opened.db.Close() }()
	if raw := rawSetting(t, opened.db, "server"); !bytes.HasPrefix(raw, []byte(settingEnvelopePrefix)) {
		t.Fatalf("valid legacy setting was not migrated: %q", raw)
	}
}
