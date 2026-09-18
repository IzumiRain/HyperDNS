package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The prefix is not cosmetic: internal/web/auth.go decides whether a credential
// is an API key or a session token by testing for it. A rename here would make
// every distributed key stop authenticating, which is why it is pinned.
func TestGeneratedAPIKeyCarriesTheRoutingPrefix(t *testing.T) {
	key := GenerateAPIKey()
	if !strings.HasPrefix(key, APIKeyPrefix) {
		t.Fatalf("GenerateAPIKey() = %q, want the %q prefix that auth.go routes on", key, APIKeyPrefix)
	}
	if APIKeyPrefix != "hdns_live_" {
		t.Errorf("APIKeyPrefix = %q, want %q: every key already handed to an operator carries the old "+
			"value, and auth.go recognises credentials by it", APIKeyPrefix, "hdns_live_")
	}
}

// A truncated or short key is the failure this function exists to make
// impossible, so the body is checked for full length and for being real hex
// rather than merely non-empty.
func TestGeneratedAPIKeyBodyIsFullLengthHex(t *testing.T) {
	body := strings.TrimPrefix(GenerateAPIKey(), APIKeyPrefix)

	if want := 2 * apiKeyEntropyBytes; len(body) != want {
		t.Fatalf("the random part is %d characters, want %d (%d bytes hex-encoded)",
			len(body), want, apiKeyEntropyBytes)
	}
	raw, err := hex.DecodeString(body)
	if err != nil {
		t.Fatalf("the random part %q does not decode as hex: %v", body, err)
	}
	if len(raw) != apiKeyEntropyBytes {
		t.Fatalf("decoded %d bytes of entropy, want %d", len(raw), apiKeyEntropyBytes)
	}

	// An all-zero body is what a silently failed random read looks like, and it
	// would pass every check above.
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("the random part decoded to all zero bytes, which is what an unfilled buffer looks like")
	}
}

// Rotation has to produce a key that is actually different from the one it
// replaces, and a fixed seed or a reused buffer is exactly the sort of mistake a
// single-call test cannot see.
func TestGeneratedAPIKeysDoNotRepeat(t *testing.T) {
	const runs = 256

	seen := make(map[string]struct{}, runs)
	for range runs {
		key := GenerateAPIKey()
		if _, dup := seen[key]; dup {
			t.Fatalf("GenerateAPIKey() returned %q twice in %d calls: rotating a key could hand back "+
				"the key it was meant to revoke", key, runs)
		}
		seen[key] = struct{}{}
	}
}
