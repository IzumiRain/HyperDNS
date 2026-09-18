package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// masterKeySize is the AES-256 key length.
const masterKeySize = 32

// ErrMasterKeyUnusable is returned when the key file exists but does not hold a
// key this build can use. It is deliberately fatal: quietly replacing the file
// mints a new key and makes every previously encrypted record unreadable.
var ErrMasterKeyUnusable = errors.New("crypto: master key file exists but is not a valid AES-256 key")

// LoadOrGenerateMasterKey loads a 32-byte AES-256 master key from keyPath, or
// generates a new cryptographically secure random key when the file does not
// exist yet.
//
// An existing file is never overwritten. The previous implementation
// regenerated the key whenever the file was not exactly 32 bytes long, so a
// truncated write or an editor-appended newline silently destroyed access to
// every encrypted client record on the next start.
func LoadOrGenerateMasterKey(keyPath string) (*Cipher, error) {
	if keyPath == "" {
		keyPath = "master.key"
	}

	keyData, err := os.ReadFile(keyPath)
	switch {
	case err == nil:
		key, perr := parseKeyMaterial(keyData)
		if perr != nil {
			return nil, fmt.Errorf("%w: %s %v; restore the original key or move the file aside, "+
				"accepting that records encrypted with it cannot be recovered", ErrMasterKeyUnusable, keyPath, perr)
		}
		return NewCipher(key)

	case !errors.Is(err, os.ErrNotExist):
		// Permission denied, a directory in the way, an I/O fault: a key may well
		// be there, so refuse instead of generating a replacement over the top.
		return nil, fmt.Errorf("failed to read master key %s: %w", keyPath, err)
	}

	key := make([]byte, masterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random master key: %w", err)
	}

	if dir := filepath.Dir(keyPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create master key directory %s: %w", dir, err)
		}
	}

	// O_EXCL rather than os.WriteFile: two daemons starting together must not
	// each write a different key, and a file created since the read above must
	// not be clobbered.
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadExistingMasterKey(keyPath)
		}
		return nil, fmt.Errorf("failed to save master key to %s: %w", keyPath, err)
	}
	if _, werr := f.Write(key); werr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to write master key to %s: %w", keyPath, werr)
	}
	// Flush before use: a crash between first start and the first write of
	// encrypted data would otherwise leave records no key on disk can open.
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to flush master key to %s: %w", keyPath, serr)
	}
	if cerr := f.Close(); cerr != nil {
		return nil, fmt.Errorf("failed to close master key %s: %w", keyPath, cerr)
	}

	return NewCipher(key)
}

// loadExistingMasterKey re-reads a key file that appeared between this process
// deciding to generate one and actually creating it.
func loadExistingMasterKey(keyPath string) (*Cipher, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read master key %s: %w", keyPath, err)
	}
	key, perr := parseKeyMaterial(keyData)
	if perr != nil {
		return nil, fmt.Errorf("%w: %s %v", ErrMasterKeyUnusable, keyPath, perr)
	}
	return NewCipher(key)
}

// parseKeyMaterial accepts the encodings an operator plausibly leaves in the key
// file: 32 raw bytes, the same with surrounding whitespace, 64 hex characters,
// or base64. Every form is verified to decode to exactly 32 bytes, so a
// malformed file is reported instead of being replaced.
func parseKeyMaterial(data []byte) ([]byte, error) {
	if len(data) == masterKeySize {
		return data, nil
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == masterKeySize {
		return trimmed, nil
	}
	if len(trimmed) == 0 {
		return nil, errors.New("is empty")
	}

	if decoded, err := hex.DecodeString(string(trimmed)); err == nil && len(decoded) == masterKeySize {
		return decoded, nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(string(trimmed)); err == nil && len(decoded) == masterKeySize {
			return decoded, nil
		}
	}

	return nil, fmt.Errorf("holds %d bytes, which is neither a raw 32-byte key nor a hex/base64 encoding of one", len(data))
}
