package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidKey         = errors.New("crypto: key must be exactly 32 bytes for AES-256")
	ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")
	ErrDecryptionFailed   = errors.New("crypto: decryption failed (corrupted data or wrong key)")
)

// blindIndexInfo separates the lookup subkey from the master key. Reusing the
// AES key for anything but AES-GCM is the classic way to weaken both, so the
// index gets its own key derived through HKDF.
const blindIndexInfo = "hyperdns:blind-index:v1"

// Cipher provides hardware-accelerated AES-256-GCM AEAD encryption/decryption.
type Cipher struct {
	aead   cipher.AEAD
	macKey []byte
}

// NewCipher creates a new AES-256-GCM cipher instance from a 32-byte master key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to init AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to init GCM mode: %w", err)
	}

	macKey, err := hkdf.Key(sha256.New, key, nil, blindIndexInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive the lookup subkey: %w", err)
	}

	return &Cipher{aead: gcm, macKey: macKey}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a fresh random 12-byte nonce.
// Output format: [12-byte Nonce][Ciphertext + 16-byte Auth Tag]
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("crypto: cipher is uninitialized")
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt authenticates and decrypts ciphertext that was produced by Encrypt.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("crypto: cipher is uninitialized")
	}

	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns a URL-safe Base64 encoded string.
func (c *Cipher) EncryptString(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	enc, err := c.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(enc), nil
}

// DecryptString decodes a URL-safe Base64 string and decrypts it back to a string.
func (c *Cipher) DecryptString(b64Ciphertext string) (string, error) {
	if b64Ciphertext == "" {
		return "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return "", fmt.Errorf("invalid base64 encoding: %w", err)
	}
	dec, err := c.Decrypt(data)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

// BlindIndex returns a deterministic, keyed fingerprint of a secret, so a stored
// value can be looked up without being decrypted or stored in the clear.
//
// AES-GCM uses a fresh nonce per record, which is what makes it safe — and also
// what makes two encryptions of the same secret look unrelated. A lookup by
// secret would therefore have to decrypt every stored record, which on a public
// endpoint is a CPU-exhaustion primitive. The fingerprint is compared instead:
// it is stable across records, and because it is an HMAC under a key nobody has
// without master.key, it reveals nothing about the secret to whoever holds a
// copy of the database.
//
// The result must only ever be compared in constant time.
func (c *Cipher) BlindIndex(plaintext string) string {
	if plaintext == "" || c == nil || len(c.macKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, c.macKey)
	mac.Write([]byte(plaintext))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
