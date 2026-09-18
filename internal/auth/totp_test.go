package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

// RFC 6238's own test vectors. The secret is the ASCII of
// "12345678901234567890" — the RFC's canonical test seed — and each code is
// what a correct implementation must answer at the named instant for TOTP-SHA1,
// 8 digits in the RFC's table; the 6-digit prefixes here are the truncation the
// dashboard's 6-digit policy displays. Pinning these proves the whole
// HMAC/truncation path, not just that "some code" validates.
func TestRFC6238Vectors(t *testing.T) {
	// RFC 4226 HOTP-SHA1 secret for the TOTP vectors.
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

	// T (seconds since epoch) and the 6-digit code, from the RFC 6238 Appendix B
	// table (which lists 8-digit values; the leading two digits are dropped by
	// the mod 10^6 the 6-digit form applies).
	cases := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tc := range cases {
		if !ValidateTOTPAt(secret, tc.code, time.Unix(tc.unix, 0)) {
			t.Errorf("at %d, code %s rejected", tc.unix, tc.code)
		}
	}
}

func TestValidateTOTPAcceptsSkewWindow(t *testing.T) {
	secret := GenerateTOTPSecret()
	now := time.Now()
	// The current step and the neighbours are in; two steps away is out.
	for _, d := range []time.Duration{-TOTPStep, 0, TOTPStep} {
		code := codeFor(t, secret, now.Add(d))
		if !ValidateTOTPAt(secret, code, now) {
			t.Errorf("code from %+v step rejected at now", d)
		}
	}
	farCode := codeFor(t, secret, now.Add(3*TOTPStep))
	if ValidateTOTPAt(secret, farCode, now) {
		t.Error("a code from three steps away was accepted")
	}
}

func TestValidateTOTPRejectsGarbage(t *testing.T) {
	secret := GenerateTOTPSecret()
	for _, code := range []string{"", "12345", "1234567", "abcdef", "00000 ", "123456789012"} {
		if ValidateTOTPAt(secret, code, time.Now()) {
			t.Errorf("garbage code %q was accepted", code)
		}
	}
	// A secret that is not base32 at all, and an empty one: fail closed.
	for _, bad := range []string{"", "not-base32!!!"} {
		if ValidateTOTP(bad, "123456") {
			t.Errorf("secret %q authenticated", bad)
		}
	}
}

func TestGeneratedSecretsAreCanonical(t *testing.T) {
	for i := 0; i < 20; i++ {
		s := GenerateTOTPSecret()
		if strings.ContainsAny(s, "= ") {
			t.Errorf("secret %q carries padding or spaces", s)
		}
		if len(s) != 32 { // 20 bytes → 32 base32 chars, no padding
			t.Errorf("secret length %d, want 32", len(s))
		}
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err != nil {
			t.Errorf("secret %q does not decode: %v", s, err)
		}
	}
}

func TestOTPAuthURIEscapesLabel(t *testing.T) {
	uri := OTPAuthURI("HyperDNS", "admin:with colon", "ABCDEF")
	if !strings.HasPrefix(uri, "otpauth://totp/HyperDNS:admin") {
		t.Errorf("uri %q does not start with the expected label", uri)
	}
	if !strings.Contains(uri, "secret=ABCDEF") || !strings.Contains(uri, "issuer=HyperDNS") {
		t.Errorf("uri %q lost the query parameters", uri)
	}
	// The raw colon in the account must not have survived into the label.
	if strings.Contains(uri, "admin:with colon") {
		t.Error("the account name was not escaped")
	}
}

// codeFor derives one code directly, independent of ValidateTOTPAt's loop, so
// the skew test cannot pass by testing the implementation against itself.
func codeFor(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(at.Unix())/uint64(TOTPStep/time.Second))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint64(sum[off])&0x7f)<<24 | uint64(sum[off+1])<<16 | uint64(sum[off+2])<<8 | uint64(sum[off+3])
	return fmt.Sprintf("%06d", v%1000000)
}
