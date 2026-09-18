package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTPStep is the RFC 6238 time step: 30 seconds, the interval every mainstream
// authenticator app defaults to. TOTPDigits is the code length (6) and
// TOTPSkew is how many steps on either side of "now" are accepted (±1), which
// absorbs the clock drift between a phone and the server — the single most
// common reason a correct code is rejected.
const (
	TOTPStep   = 30 * time.Second
	TOTPDigits = 6
	TOTPSkew   = 1
)

// GenerateTOTPSecret returns a fresh base32 (RFC 4648, no padding) secret of 20
// entropy bytes — 160 bits, the RFC 4226 recommendation and what Google
// Authenticator expects to render without truncation.
//
// The error is discarded by callers per the same reasoning as the admin-path
// generator: crypto/rand.Read either fills b or crashes the process.
func GenerateTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// otpauthURI builds the enrollment URI an authenticator app photographs or
// imports. Label is "issuer:account" per the key URI format; both are escaped,
// because a username is attacker-influenced text and a raw colon in the label
// would split the issuer from the account in apps that parse it naively.
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	q.Set("period", fmt.Sprintf("%d", int(TOTPStep.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpCode derives the HOTP value (RFC 4226) for one time counter using HMAC-SHA1
// over the 8-byte big-endian counter, then applies the dynamic truncation. The
// result is returned as the zero-padded decimal code the apps display.
func totpCode(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint64(sum[offset])&0x7f)<<24 |
		uint64(sum[offset+1])<<16 |
		uint64(sum[offset+2])<<8 |
		uint64(sum[offset+3])
	mod := uint64(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	code %= mod
	return fmt.Sprintf("%0*d", TOTPDigits, code)
}

// decodeSecret accepts the canonical no-padding base32 the generator emits and
// the padded form some apps display when a secret is pasted by hand. Anything
// else — base64, hex, a QR of something else entirely — fails closed.
func decodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	if b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err == nil {
		return b, nil
	}
	return base32.StdEncoding.DecodeString(s)
}

// ValidateTOTP reports whether code is the authenticator's code for secret at
// some step within TOTPSkew of now. Comparison is constant time in the code's
// digits so a timing leak cannot narrow the search space below the one-in-a-
// million an online guess already costs.
//
// An empty or undecodable secret answers false: a half-configured 2FA record
// must never authenticate.
func ValidateTOTP(secret, code string) bool {
	return ValidateTOTPAt(secret, code, time.Now())
}

// ValidateTOTPAt is ValidateTOTP against an explicit instant, which is what
// keeps the RFC 6238 test vectors honest — the vectors are time-tables, not
// "now".
func ValidateTOTPAt(secret, code string, now time.Time) bool {
	key, err := decodeSecret(secret)
	if err != nil || len(key) == 0 {
		return false
	}
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return false
	}
	counter := uint64(now.Unix()) / uint64(TOTPStep/time.Second)
	for d := -int64(TOTPSkew); d <= int64(TOTPSkew); d++ {
		want := totpCode(key, uint64(int64(counter)+d))
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
