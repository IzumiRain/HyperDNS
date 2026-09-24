package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"hyperdns/internal/crypto"
)

var (
	bucketClients      = []byte("clients")
	bucketPolicies     = []byte("policies")
	bucketLogs         = []byte("logs")
	bucketSettings     = []byte("settings")
	bucketUpstreams    = []byte("upstreams")
	bucketCustomGroups = []byte("custom_groups")
)

// bucketsInUse is everything a v1.5.0 database actually holds.
//
// bucketsRetired is what every earlier build created and none of them ever wrote.
// DNS telemetry lives in memory only — StatsService keeps the last 100 entries and
// fans the rest out over SSE — and the upstream list is a field of the DNS settings
// record. An empty bucket named `logs` inside a resolver's database invites the
// assumption that query history is kept on disk, which is a privacy claim this
// daemon does not make; they are dropped rather than carried forward and audited
// again at every release.
var (
	bucketsInUse   = [][]byte{bucketClients, bucketPolicies, bucketSettings, bucketCustomGroups}
	bucketsRetired = [][]byte{bucketLogs, bucketUpstreams}
)

// DB manages the embedded B+Tree database with AES-256-GCM encryption.
type DB struct {
	bolt   *bolt.DB
	cipher *crypto.Cipher
	mu     sync.RWMutex
}

// afterExistingStoreValidation is a test seam for proving that validation and
// migration remain under the same exclusive bbolt handle.
var afterExistingStoreValidation = func() {}

// OpenForInspection opens an existing database read-only. It never creates
// directories, buckets, records, or migration pages. This API is diagnostic;
// production existing-store startup must use OpenExisting so validation and
// migration remain under one exclusive lock.
func OpenForInspection(dbPath string, cipher *crypto.Cipher) (*DB, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("database path is empty")
	}
	bdb, err := bolt.Open(dbPath, 0600, &bolt.Options{
		ReadOnly: true,
		Timeout:  3 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to inspect database at %s: %w", dbPath, err)
	}
	return &DB{bolt: bdb, cipher: cipher}, nil
}

// OpenExisting opens an existing database under one exclusive lock, validates
// all persisted settings and clients, and only then permits migration writes.
func OpenExisting(dbPath string, cipher *crypto.Cipher) (*DB, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("database path is empty")
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		return nil, fmt.Errorf("inspect existing database at %s: %w", dbPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("existing database path %s is not a regular file", dbPath)
	}
	return openDatabase(dbPath, cipher, true)
}

// Create initializes a fresh database and refuses to reuse an existing path.
func Create(dbPath string, cipher *crypto.Cipher) (*DB, error) {
	if dbPath == "" {
		dbPath = "data.db"
	}
	if _, err := os.Stat(dbPath); err == nil {
		return nil, fmt.Errorf("database already exists at %s", dbPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect database path %s: %w", dbPath, err)
	}
	return openDatabase(dbPath, cipher, false)
}

// Open opens existing storage fail-closed, or explicitly creates a fresh file
// after classifying the path before bbolt can create it as a side effect.
func Open(dbPath string, cipher *crypto.Cipher) (*DB, error) {
	if dbPath == "" {
		dbPath = "data.db"
	}
	if _, err := os.Stat(dbPath); err == nil {
		return OpenExisting(dbPath, cipher)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect database path %s: %w", dbPath, err)
	}
	return Create(dbPath, cipher)
}

func openDatabase(dbPath string, cipher *crypto.Cipher, existing bool) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if !existing && dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create database directory %s: %w", dir, err)
		}
	}

	options := &bolt.Options{Timeout: 3 * time.Second}
	if existing {
		options.OpenFile = func(path string, _ int, mode os.FileMode) (*os.File, error) {
			return os.OpenFile(path, os.O_RDWR, mode)
		}
	}
	bdb, err := bolt.Open(dbPath, 0600, options)
	if err != nil {
		return nil, fmt.Errorf("failed to open database at %s: %w", dbPath, err)
	}
	db := &DB{bolt: bdb, cipher: cipher}
	if existing {
		if err := db.validateStoredState(); err != nil {
			_ = bdb.Close()
			return nil, fmt.Errorf("refusing to modify invalid persisted state: %w", err)
		}
		afterExistingStoreValidation()
	}

	// Initialize the buckets that are still in use, and drop the two that never
	// held anything. Dropping is guarded on the bucket being empty, so a database
	// that somehow does hold rows keeps them and says so instead.
	dropped := 0
	err = bdb.Update(func(tx *bolt.Tx) error {
		for _, bName := range bucketsInUse {
			if _, err := tx.CreateBucketIfNotExists(bName); err != nil {
				return fmt.Errorf("failed to create bucket %s: %w", string(bName), err)
			}
		}
		for _, bName := range bucketsRetired {
			b := tx.Bucket(bName)
			if b == nil {
				continue
			}
			if n := b.Stats().KeyN; n != 0 {
				log.Printf("[DB] The retired %q bucket holds %d record(s), so it was left in place.", bName, n)
				continue
			}
			if err := tx.DeleteBucket(bName); err != nil {
				return fmt.Errorf("failed to drop the retired bucket %s: %w", string(bName), err)
			}
			dropped++
		}
		return nil
	})
	if err != nil {
		_ = bdb.Close()
		return nil, err
	}

	// Seal anything a pre-v1.5.0 build left in the clear: the settings records
	// (admin password verifier, REST API key, TLS paths) and the subscription
	// tokens. This is the automatic half of the format change — an existing
	// installation converts itself on the next start, with no operator step and no
	// data loss. A failure here is reported but never fatal: the read path still
	// understands the old form, so a resolver that cannot re-encrypt keeps serving.
	converted := 0
	if dropped > 0 {
		// Not counted as a conversion: the pages those buckets used never held a
		// secret, so they are not worth a whole-file rewrite on their own. If a real
		// migration runs on the same start, the compaction below reclaims them anyway.
		log.Printf("[DB] Dropped %d empty bucket(s) that no version of HyperDNS ever wrote to.", dropped)
	}
	if n, err := db.encryptLegacySettings(); err != nil {
		log.Printf("[DB] Could not encrypt the legacy settings records: %v; they stay in cleartext.", err)
	} else if n > 0 {
		log.Printf("[DB] Encrypted %d settings record(s) that were stored in cleartext by an older version.", n)
		converted += n
	}
	if n, err := db.encryptLegacyClientTokens(); err != nil {
		log.Printf("[DB] Could not encrypt the legacy subscription tokens: %v; they stay in cleartext.", err)
	} else if n > 0 {
		log.Printf("[DB] Encrypted the subscription token of %d client(s) that an older version stored in cleartext.", n)
		converted += n
	}

	// Re-encrypting in place is not enough on its own — see compactDatabase.
	if converted > 0 {
		rebuilt, err := compactDatabase(db.bolt, dbPath, cipher)
		if rebuilt == nil {
			return nil, err
		}
		db.bolt = rebuilt
		if err != nil {
			log.Printf("[DB] Could not rewrite the database file: %v; the freed pages may still hold the old cleartext. Compact it manually before copying data.db anywhere.", err)
		} else {
			log.Printf("[DB] Rewrote the database file, so the pages that held the cleartext are gone.")
		}
	}

	return db, nil
}

func (db *DB) validateStoredState() error {
	if err := db.ValidateSettings(); err != nil {
		return err
	}
	return db.ValidateClients()
}

// compactDatabase rewrites the database file and returns a handle to the
// replacement.
//
// Re-encrypting a record in place does not remove the old one from the file:
// bbolt marks the page it used as free but never zeroes it, so the previous
// cleartext keeps sitting in the file's free space and `strings data.db` on a
// copied backup still prints the old password verifier and API key. Only a full
// rewrite drops those pages, which is why the conversion is followed by one.
//
// The original is replaced only by a copy that has been reopened and checked
// bucket by bucket. Any failure before that point leaves the original in place
// and returns it, so the caller can carry on with a working — if untidy —
// database. A nil handle means the database is unusable and the caller must fail.
func compactDatabase(src *bolt.DB, dbPath string, cipher *crypto.Cipher) (*bolt.DB, error) {
	reopen := func() (*bolt.DB, error) {
		return bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 3 * time.Second})
	}

	// Record what the copy has to contain before it is allowed to replace the
	// original. This is the one operation here that could destroy the only copy of
	// an operator's data, so it is checked rather than trusted.
	want := map[string]int{}
	if err := src.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			want[string(name)] = b.Stats().KeyN
			return nil
		})
	}); err != nil {
		return src, fmt.Errorf("could not survey the database: %w", err)
	}

	tmpPath := dbPath + ".compacting"
	_ = os.Remove(tmpPath)
	dst, err := bolt.Open(tmpPath, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return src, fmt.Errorf("could not create the compacted copy: %w", err)
	}
	if err := bolt.Compact(dst, src, 0); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmpPath)
		return src, fmt.Errorf("could not compact the database: %w", err)
	}
	err = dst.View(func(tx *bolt.Tx) error {
		for name, keys := range want {
			b := tx.Bucket([]byte(name))
			if b == nil {
				return fmt.Errorf("the copy is missing the %q bucket", name)
			}
			if got := b.Stats().KeyN; got != keys {
				return fmt.Errorf("the copy has %d key(s) in %q, want %d", got, name, keys)
			}
		}
		return nil
	})
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return src, fmt.Errorf("the compacted copy did not verify: %w", err)
	}

	// Past this point the original has to be closed, so every remaining failure
	// has to leave a usable handle behind.
	if err := src.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return src, fmt.Errorf("could not close the database before replacing it: %w", err)
	}
	if err := os.Rename(tmpPath, dbPath); err != nil {
		_ = os.Remove(tmpPath)
		original, rerr := reopen()
		if rerr != nil {
			return nil, fmt.Errorf("could not replace the database (%v) and could not reopen the original: %w", err, rerr)
		}
		validated := &DB{bolt: original, cipher: cipher}
		if verr := validated.validateStoredState(); verr != nil {
			_ = original.Close()
			return nil, fmt.Errorf("could not replace the database (%v) and reopened original failed validation: %w", err, verr)
		}
		return original, fmt.Errorf("could not replace the database with the compacted copy: %w", err)
	}
	rebuilt, err := reopen()
	if err != nil {
		return nil, fmt.Errorf("the database was rewritten but could not be reopened: %w", err)
	}
	validated := &DB{bolt: rebuilt, cipher: cipher}
	if err := validated.validateStoredState(); err != nil {
		_ = rebuilt.Close()
		return nil, fmt.Errorf("the rewritten database failed validation after reopen: %w", err)
	}
	return rebuilt, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	if db == nil || db.bolt == nil {
		return nil
	}
	return db.bolt.Close()
}
