package crypto

import (
	"crypto/rand"
	"encoding/hex"
)

// APIKeyPrefix is the visible marker on every master API key this build mints.
//
// internal/web/auth.go routes on it: a bearer credential starting with this
// prefix is treated as an API key rather than a dashboard session cookie, so the
// prefix is load-bearing and not decoration. Changing it invalidates every key
// an operator has already distributed.
const APIKeyPrefix = "hdns_live_"

// apiKeyEntropyBytes is 128 bits, hex-encoded to 32 characters. The key is a
// bearer credential compared for equality, never stretched or derived from, so
// the only property that matters is that it cannot be guessed or enumerated.
const apiKeyEntropyBytes = 16

// GenerateAPIKey returns a fresh master API key.
//
// This used to be written out by hand in four places — the REST rotation
// endpoint, the dashboard's rotation endpoint, first-run generation in main, and
// the installers — with the shell copies using a different length from the Go
// ones. Anything that reads a key by its shape (the length check in a support
// script, an operator eyeballing whether a key looks truncated) was measuring a
// value that depended on which door minted it.
//
// crypto/rand.Read does not fail: since Go 1.24 it either fills the buffer or
// panics inside the runtime, so there is no error path here that could emit a
// partially-filled — and therefore low-entropy — key.
func GenerateAPIKey() string {
	b := make([]byte, apiKeyEntropyBytes)
	_, _ = rand.Read(b)
	return APIKeyPrefix + hex.EncodeToString(b)
}
