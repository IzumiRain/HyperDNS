package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The master key is the one piece of state in this project that cannot be
// regenerated: every client record in a live database is sealed with it, so a start
// that quietly mints a replacement destroys the operator's data with no error to
// read. These tests exist to pin the refusal, which means most of them assert what
// the key file still contains after a failed load.

// writeKeyFile puts content in a fresh temporary directory and returns its path.
func writeKeyFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// mustReadFile is the on-disk state after a call, which is what these tests are
// really about.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after the call: %v", err)
	}
	return data
}

func TestLoadOrGenerateMasterKeyNeverReplacesAnExistingKey(t *testing.T) {
	key := testKey(0xA7)
	path := writeKeyFile(t, key)

	cipher, err := LoadOrGenerateMasterKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateMasterKey: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, path), key) {
		t.Fatal("the key file was rewritten; every record sealed with the old key is now unreadable")
	}

	// The file being untouched is only half the guarantee: the cipher has to be built
	// from that key rather than from a fresh one held in memory.
	sealed, err := cipher.EncryptString("a client record")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	reference, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	got, err := reference.DecryptString(sealed)
	if err != nil {
		t.Fatalf("the loaded cipher does not use the key on disk: %v", err)
	}
	if got != "a client record" {
		t.Errorf("decrypted %q, want %q", got, "a client record")
	}
}

func TestLoadOrGenerateMasterKeyRefusesAnUnusableFileInsteadOfReplacingIt(t *testing.T) {
	cases := map[string][]byte{
		"empty":                     {},
		"whitespace only":           []byte("   \n\t "),
		"one byte short":            bytes.Repeat([]byte{0x11}, 31),
		"one byte long":             bytes.Repeat([]byte{0x11}, 33),
		"a passphrase, not a key":   []byte("correct horse battery staple"),
		"64 characters but not hex": bytes.Repeat([]byte("z"), 64),
		"hex for eight bytes":       []byte(hex.EncodeToString(bytes.Repeat([]byte{0x11}, 8))),
		"base64 for 31 bytes":       []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 31))),
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeKeyFile(t, content)

			cipher, err := LoadOrGenerateMasterKey(path)
			// Fatal by design: the alternative is a daemon that starts fine and cannot
			// read a single stored record, which looks like data loss rather than a
			// misplaced file.
			if !errors.Is(err, ErrMasterKeyUnusable) {
				t.Fatalf("error = %v, want ErrMasterKeyUnusable", err)
			}
			if cipher != nil {
				t.Error("a cipher was returned alongside the refusal")
			}
			if got := mustReadFile(t, path); !bytes.Equal(got, content) {
				t.Errorf("the file was modified: %d bytes now, %d before", len(got), len(content))
			}
			// The message has to name the file, because the operator reading it is
			// deciding whether to move that exact file aside.
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error does not name the key file: %s", err)
			}
		})
	}
}

func TestLoadOrGenerateMasterKeyAcceptsTheEncodingsAnOperatorLeavesBehind(t *testing.T) {
	key := testKey(0x5C)
	reference, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	// Every one of these is a file a person plausibly produced by hand: a copy-paste
	// into an editor that appended a newline, a key printed with xxd, a key printed
	// with base64. Rejecting them would be safe but would send the operator looking
	// for a corruption that is not there.
	cases := map[string][]byte{
		"32 raw bytes":                   key,
		"32 raw bytes with a newline":    append(bytes.Clone(key), '\n'),
		"32 raw bytes with CRLF":         append(bytes.Clone(key), '\r', '\n'),
		"lower-case hex":                 []byte(hex.EncodeToString(key)),
		"upper-case hex":                 []byte(strings.ToUpper(hex.EncodeToString(key))),
		"padded base64":                  []byte(base64.StdEncoding.EncodeToString(key)),
		"unpadded base64":                []byte(base64.RawStdEncoding.EncodeToString(key)),
		"padded base64url":               []byte(base64.URLEncoding.EncodeToString(key)),
		"unpadded base64url with a tail": []byte(base64.RawURLEncoding.EncodeToString(key) + "\n"),
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeKeyFile(t, content)

			cipher, err := LoadOrGenerateMasterKey(path)
			if err != nil {
				t.Fatalf("LoadOrGenerateMasterKey: %v", err)
			}
			sealed, err := cipher.EncryptString("a client record")
			if err != nil {
				t.Fatalf("EncryptString: %v", err)
			}
			if got, err := reference.DecryptString(sealed); err != nil || got != "a client record" {
				t.Errorf("the loaded key is not the one in the file: %q, %v", got, err)
			}
			if !bytes.Equal(mustReadFile(t, path), content) {
				t.Error("the file was rewritten into a different encoding")
			}
		})
	}
}

// keyOnDisk is a generated key file's raw bytes, length-checked so that a later
// comparison cannot pass against a truncated write.
func keyOnDisk(t *testing.T, path string) []byte {
	t.Helper()
	data := mustReadFile(t, path)
	if len(data) != masterKeySize {
		t.Fatalf("key file holds %d bytes, want %d", len(data), masterKeySize)
	}
	return data
}

func TestLoadOrGenerateMasterKeyGeneratesExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	cipher, err := LoadOrGenerateMasterKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	generated := keyOnDisk(t, path)

	// This one file opens every client record, so on a shared VPS a world-readable
	// key is the whole database. Windows has no POSIX mode bits to assert.
	if runtime.GOOS != "windows" {
		info, serr := os.Stat(path)
		if serr != nil {
			t.Fatalf("Stat: %v", serr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %04o, want 0600", perm)
		}
	}

	sealed, err := cipher.EncryptString("a client record")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	// The second call is the restart, and it has to load rather than mint. A fresh
	// key here is the failure that orphans a live database with no error to read.
	second, err := LoadOrGenerateMasterKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !bytes.Equal(keyOnDisk(t, path), generated) {
		t.Fatal("the second call rewrote the key file")
	}
	if got, derr := second.DecryptString(sealed); derr != nil || got != "a client record" {
		t.Errorf("a restart cannot read what the first start wrote: %q, %v", got, derr)
	}
}

func TestGeneratedMasterKeysDifferBetweenInstalls(t *testing.T) {
	dir := t.TempDir()

	// Eight installs rather than two: a key derived from the path, from the clock at
	// one-second resolution, or from a constant would pass a single comparison often
	// enough to look fine. This project is meant to be resold, so one operator being
	// able to open another's records is the failure being ruled out.
	var keys [][]byte
	for i := range 8 {
		path := filepath.Join(dir, fmt.Sprintf("install-%d.key", i))
		if _, err := LoadOrGenerateMasterKey(path); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
		keys = append(keys, keyOnDisk(t, path))
	}

	zero := make([]byte, masterKeySize)
	seen := make(map[string]int, len(keys))
	for i, key := range keys {
		if bytes.Equal(key, zero) {
			t.Fatalf("install %d was given an all-zero key; the random source returned nothing", i)
		}
		if first, dup := seen[string(key)]; dup {
			t.Fatalf("installs %d and %d were given the same key", first, i)
		}
		seen[string(key)] = i
	}
}

func TestLoadOrGenerateMasterKeyCreatesTheDirectoryItWasPointedAt(t *testing.T) {
	// The installers put the key under a data directory that does not exist yet on a
	// first run, so refusing here would break a clean install.
	path := filepath.Join(t.TempDir(), "data", "secrets", "master.key")

	if _, err := LoadOrGenerateMasterKey(path); err != nil {
		t.Fatalf("LoadOrGenerateMasterKey: %v", err)
	}
	keyOnDisk(t, path)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		// A 0600 file inside a traversable directory is still private, but the daemon
		// creates this directory for secrets and nothing else belongs in it.
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("directory mode = %04o, want 0700", perm)
		}
	}
}

func TestLoadOrGenerateMasterKeyDefaultsToTheWorkingDirectory(t *testing.T) {
	// An empty key_path is the documented default rather than an error. t.Chdir keeps
	// the generated file out of the package directory, which is where a bare
	// "master.key" would otherwise land and be committed by accident.
	t.Chdir(t.TempDir())

	cipher, err := LoadOrGenerateMasterKey("")
	if err != nil {
		t.Fatalf("LoadOrGenerateMasterKey: %v", err)
	}

	reference, err := NewCipher(keyOnDisk(t, "master.key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	sealed, err := cipher.EncryptString("a client record")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if got, derr := reference.DecryptString(sealed); derr != nil || got != "a client record" {
		t.Errorf("the cipher does not use ./master.key: %q, %v", got, derr)
	}
}

func TestLoadOrGenerateMasterKeyRefusesWhenTheKeyPathCannotBeRead(t *testing.T) {
	// A directory where the key file should be is the shape a misconfigured volume
	// mount takes. The read fails with something other than "not found", and the only
	// safe response is to stop: a key may well exist somewhere this process cannot
	// see, and generating one over the top is unrecoverable.
	dir := t.TempDir()

	cipher, err := LoadOrGenerateMasterKey(dir)
	if err == nil {
		t.Fatal("a directory was accepted as a key file")
	}
	if cipher != nil {
		t.Error("a cipher was returned alongside the refusal")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("the failure was treated as a missing file: %s", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error does not name the path: %s", err)
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatalf("ReadDir: %v", rerr)
	}
	if len(entries) != 0 {
		t.Errorf("a key was written despite the refusal: %v", entries)
	}
}

// loadExistingMasterKey is the branch taken when a key file appears between this
// process reading and creating it — two daemons started together, or a systemd
// restart overlapping the old process. It parses the file a second time in its own
// code path, so it is tested separately: the hazard is a future edit that makes this
// site generate a key instead of refusing, which no test of the main path would see.
func TestLoadExistingMasterKeyHandlesTheRaceLoserTheSameWay(t *testing.T) {
	key := testKey(0x3E)
	path := writeKeyFile(t, key)

	cipher, err := loadExistingMasterKey(path)
	if err != nil {
		t.Fatalf("loadExistingMasterKey: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, path), key) {
		t.Fatal("the winner's key file was rewritten by the loser")
	}
	reference, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	sealed, err := cipher.EncryptString("a client record")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if got, derr := reference.DecryptString(sealed); derr != nil || got != "a client record" {
		t.Errorf("the two processes ended up with different keys: %q, %v", got, derr)
	}

	// And the same refusal, because a file that lost the race is no more trustworthy
	// than one found on the first read.
	bad := writeKeyFile(t, []byte("not a key"))
	if _, err := loadExistingMasterKey(bad); !errors.Is(err, ErrMasterKeyUnusable) {
		t.Errorf("error = %v, want ErrMasterKeyUnusable", err)
	}
}
