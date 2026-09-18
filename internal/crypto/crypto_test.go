package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrypto_EncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	plain := "Sensitive Client IP: 185.100.234.106 | Account: ProGamer"
	enc, err := cipher.EncryptString(plain)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	if enc == plain {
		t.Errorf("ciphertext matches plaintext")
	}

	dec, err := cipher.DecryptString(enc)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if dec != plain {
		t.Errorf("expected %s, got %s", plain, dec)
	}
}

// The key file goes to a temporary directory, not the package directory, because what
// LoadOrGenerateMasterKey writes is a real 32-byte AES key: a run interrupted between the
// generate and the deferred remove used to leave one sitting in internal/crypto/, one
// `git add .` away from being published. t.TempDir also gives each run its own path, so a
// second copy of the suite cannot read the first one's key.
func TestCrypto_Keygen(t *testing.T) {
	tmpKey := filepath.Join(t.TempDir(), "master.key")

	c1, err := LoadOrGenerateMasterKey(tmpKey)
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	c2, err := LoadOrGenerateMasterKey(tmpKey)
	if err != nil {
		t.Fatalf("failed to reload master key: %v", err)
	}

	text := "HyperDNS v2.0 Next-Gen"
	enc, _ := c1.EncryptString(text)
	dec, _ := c2.DecryptString(enc)

	if dec != text {
		t.Errorf("expected %s, got %s", text, dec)
	}
}

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// The whole reason BlindIndex exists: AES-GCM draws a fresh nonce per call, so the
// same secret seals to two unrelated ciphertexts and cannot be looked up by
// comparing ciphertext. If this ever stops being true the nonce has been fixed, and
// the encryption is broken in a much worse way than the lookup.
func TestEncryptUsesAFreshNoncePerCall(t *testing.T) {
	c, err := NewCipher(testKey(0x41))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	const secret = "hdns_sub_7c41f9aa20b6"
	first, err := c.EncryptString(secret)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	second, err := c.EncryptString(secret)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if first == second {
		t.Fatal("the same plaintext sealed to identical ciphertext — the nonce is not random")
	}
	for _, enc := range []string{first, second} {
		got, err := c.DecryptString(enc)
		if err != nil {
			t.Fatalf("DecryptString: %v", err)
		}
		if got != secret {
			t.Errorf("round trip = %q", got)
		}
	}
}

// A stored fingerprint is only useful if it is stable for one key and unrelated
// across keys: stable, or the subscriber's token stops matching the record it was
// stored in; unrelated, or a fingerprint copied out of one operator's database
// could be recognised in another's.
func TestBlindIndexIsDeterministicAndKeyed(t *testing.T) {
	a, err := NewCipher(testKey(0x11))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	b, err := NewCipher(testKey(0x22))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	const secret = "hdns_sub_stable"
	want := a.BlindIndex(secret)
	if want == "" {
		t.Fatal("BlindIndex returned nothing for a real secret")
	}
	for range 4 {
		if got := a.BlindIndex(secret); got != want {
			t.Fatalf("BlindIndex is not deterministic: %q then %q", want, got)
		}
	}
	// A second cipher over the same key bytes must agree, or a restart would
	// invalidate every stored fingerprint.
	again, err := NewCipher(testKey(0x11))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if got := again.BlindIndex(secret); got != want {
		t.Errorf("a reopened cipher produced %q, want %q", got, want)
	}
	if got := b.BlindIndex(secret); got == want {
		t.Error("two different master keys produced the same fingerprint")
	}

	// Near misses must not collide, or a guessed token would authenticate.
	for _, other := range []string{"hdns_sub_stablx", "hdns_sub_stabl", "hdns_sub_stablee", "HDNS_SUB_STABLE", " hdns_sub_stable"} {
		if a.BlindIndex(other) == want {
			t.Errorf("%q fingerprints the same as %q", other, secret)
		}
	}
}

// The fingerprint is stored next to the ciphertext, so it must not leak the secret
// it was derived from — not its bytes and not its length.
func TestBlindIndexLeaksNeitherContentNorLength(t *testing.T) {
	c, err := NewCipher(testKey(0x33))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	wantLen := base64.RawURLEncoding.EncodedLen(sha256.Size)
	for _, secret := range []string{"a", "hdns_sub_7c41f9aa20b6", strings.Repeat("long", 512)} {
		got := c.BlindIndex(secret)
		if len(got) != wantLen {
			t.Errorf("BlindIndex(%d-byte secret) is %d chars, want a fixed %d", len(secret), len(got), wantLen)
		}
		if strings.Contains(got, secret) {
			t.Errorf("the fingerprint of %q contains the secret itself", secret)
		}
	}
}

// The lookup subkey has to be derived, not borrowed: using the AES key as an HMAC
// key too is the classic way to weaken both primitives. If the HKDF step is ever
// dropped, this catches it.
func TestBlindIndexDoesNotReuseTheMasterKey(t *testing.T) {
	key := testKey(0x44)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	const secret = "hdns_sub_domainsep"
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(secret))
	naive := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if c.BlindIndex(secret) == naive {
		t.Error("the fingerprint is an HMAC under the master key itself — the HKDF derivation was skipped")
	}
}

// An empty secret must fingerprint to nothing rather than to the HMAC of the empty
// string: a stored empty fingerprint would otherwise match every tokenless record,
// and one malformed row would authenticate a blank token.
func TestBlindIndexRefusesEmptyAndNilReceiver(t *testing.T) {
	c, err := NewCipher(testKey(0x55))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if got := c.BlindIndex(""); got != "" {
		t.Errorf(`BlindIndex("") = %q, want ""`, got)
	}

	// The database layer calls this on a handle opened with no master key.
	var nilCipher *Cipher
	if got := nilCipher.BlindIndex("hdns_sub_anything"); got != "" {
		t.Errorf("BlindIndex on a nil cipher = %q, want \"\"", got)
	}
	if got := (&Cipher{}).BlindIndex("hdns_sub_anything"); got != "" {
		t.Errorf("BlindIndex on a zero cipher = %q, want \"\"", got)
	}
}

// A short or long key must be refused rather than padded or truncated into
// something that silently encrypts under the wrong strength.
func TestNewCipherRejectsAKeyThatIsNot32Bytes(t *testing.T) {
	for _, n := range []int{0, 1, 16, 24, 31, 33, 64} {
		if _, err := NewCipher(bytes.Repeat([]byte{0x66}, n)); err != ErrInvalidKey {
			t.Errorf("NewCipher(%d bytes) = %v, want ErrInvalidKey", n, err)
		}
	}
	if _, err := NewCipher(nil); err != ErrInvalidKey {
		t.Errorf("NewCipher(nil) = %v, want ErrInvalidKey", err)
	}
}

// A tampered or foreign ciphertext must fail closed. GCM authenticates, so this is
// really a check that the tag is being verified and the error is not swallowed.
func TestDecryptRejectsTamperedAndForeignCiphertext(t *testing.T) {
	c, err := NewCipher(testKey(0x77))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	other, err := NewCipher(testKey(0x88))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	sealed, err := c.EncryptString("hdns_sub_tamper")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if _, err := other.DecryptString(sealed); err != ErrDecryptionFailed {
		t.Errorf("decrypting under the wrong key = %v, want ErrDecryptionFailed", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("the ciphertext is not RawURL base64: %v", err)
	}
	for _, i := range []int{0, len(raw) / 2, len(raw) - 1} {
		bad := append([]byte(nil), raw...)
		bad[i] ^= 0x01
		if _, err := c.Decrypt(bad); err != ErrDecryptionFailed {
			t.Errorf("flipping a bit at %d decrypted anyway: %v", i, err)
		}
	}
	// Shorter than a nonce is a distinct failure, not a panic.
	if _, err := c.Decrypt(raw[:4]); err != ErrCiphertextTooShort {
		t.Errorf("Decrypt on a truncated blob = %v, want ErrCiphertextTooShort", err)
	}
	if _, err := c.DecryptString("not base64 at all!!"); err == nil {
		t.Error("DecryptString accepted a value that is not base64")
	}
}
