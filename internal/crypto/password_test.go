package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	const pw = "correct-horse-Battery-9"

	encoded, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if strings.Contains(encoded, pw) {
		t.Fatalf("encoded hash leaks the plaintext: %q", encoded)
	}
	if !IsPasswordHash(encoded) {
		t.Fatalf("IsPasswordHash(%q) = false, want true", encoded)
	}
	if !VerifyPassword(encoded, pw) {
		t.Fatal("VerifyPassword rejected the correct password")
	}
	if VerifyPassword(encoded, pw+"x") {
		t.Fatal("VerifyPassword accepted a wrong password")
	}
	if VerifyPassword(encoded, strings.ToUpper(pw)) {
		t.Fatal("VerifyPassword is case-insensitive")
	}
	if NeedsRehash(encoded) {
		t.Fatal("a freshly minted hash should not need rehashing")
	}
}

func TestHashPasswordSaltsEveryCall(t *testing.T) {
	a, err := HashPassword("same-password-1A")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("same-password-1A")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of one password are identical, so the salt is not random")
	}
	// Both must still verify — a fresh salt is only useful if it is recorded.
	if !VerifyPassword(a, "same-password-1A") || !VerifyPassword(b, "same-password-1A") {
		t.Fatal("independently salted hashes must both verify")
	}
}

func TestHashPasswordRejectsUnusableInput(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("hashing an empty password must fail")
	}
	if _, err := HashPassword(strings.Repeat("a", maxPasswordLength+1)); err == nil {
		t.Fatal("hashing an over-long password must fail")
	}
}

// A stored plaintext is what every install carries before migration. It must
// still authenticate, or upgrading the binary locks the operator out of a live
// server.
func TestVerifyPasswordLegacyPlaintext(t *testing.T) {
	if !VerifyPassword("admin", "admin") {
		t.Fatal("legacy plaintext comparison must still work before migration")
	}
	if VerifyPassword("admin", "Admin") {
		t.Fatal("legacy comparison must be exact")
	}
	if IsPasswordHash("admin") {
		t.Fatal("plaintext must not be mistaken for a hash")
	}
	if !NeedsRehash("admin") {
		t.Fatal("plaintext must be reported as needing conversion")
	}
}

func TestVerifyPasswordEmptyNeverAuthorises(t *testing.T) {
	// The old login handler substituted "admin" for an empty stored password,
	// which meant a blank setting was a working backdoor. Nothing may match an
	// empty stored value, including an empty submission.
	cases := [][2]string{
		{"", ""},
		{"", "admin"},
		{"anything", ""},
	}
	for _, c := range cases {
		if VerifyPassword(c[0], c[1]) {
			t.Fatalf("VerifyPassword(%q, %q) = true, want false", c[0], c[1])
		}
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	good, err := HashPassword("a-good-password-7Z")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	parts := strings.Split(good, "$")

	// Each of these looks hash-shaped but must not verify anything.
	malformed := []string{
		"pbkdf2-sha256$600000$notbase64!!$" + parts[3],
		"pbkdf2-sha256$600000$" + parts[2] + "$notbase64!!",
		"pbkdf2-sha256$abc$" + parts[2] + "$" + parts[3],
		"pbkdf2-sha256$0$" + parts[2] + "$" + parts[3],
		"pbkdf2-sha256$-1$" + parts[2] + "$" + parts[3],
		"pbkdf2-sha512$600000$" + parts[2] + "$" + parts[3],
		"pbkdf2-sha256$600000$$" + parts[3],
		"pbkdf2-sha256$600000$" + parts[2],
	}
	for _, m := range malformed {
		if IsPasswordHash(m) && m != malformed[5] {
			t.Errorf("IsPasswordHash(%q) = true, want false", m)
		}
		if VerifyPassword(m, "a-good-password-7Z") {
			t.Errorf("VerifyPassword accepted the correct plaintext against malformed %q", m)
		}
	}

	// An absurd iteration count in a tampered record must be refused rather than
	// executed, so a poisoned settings row cannot stall every login.
	bomb := "pbkdf2-sha256$999999999$" + parts[2] + "$" + parts[3]
	if IsPasswordHash(bomb) {
		t.Error("an out-of-range iteration count must not be accepted as a hash")
	}
	done := make(chan bool, 1)
	go func() { done <- VerifyPassword(bomb, "a-good-password-7Z") }()
	select {
	case ok := <-done:
		if ok {
			t.Error("the iteration bomb must not verify")
		}
	case <-time.After(5 * time.Second):
		t.Error("VerifyPassword executed an out-of-range iteration count instead of refusing it")
	}
}

func TestNeedsRehashOnWeakerCost(t *testing.T) {
	salt := make([]byte, passwordSaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	weak, err := hashPasswordWith("legacy-cost-pass-3", 1000, salt)
	if err != nil {
		t.Fatalf("hashPasswordWith: %v", err)
	}
	if !VerifyPassword(weak, "legacy-cost-pass-3") {
		t.Fatal("a hash at the old cost must still verify")
	}
	if !NeedsRehash(weak) {
		t.Fatal("a hash below the current cost must be reported as needing a rehash")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{"good mixed", "admin", "Zx7-quiet-lantern", false},
		{"good long single class", "admin", "quietlanternriverstone", false},
		{"persian passphrase", "admin", "گذرواژهٔ‌بلندِمن", false},
		{"generated hex", "admin", "9f2ac41b7de05c83", false},

		{"empty", "admin", "", true},
		{"too short", "admin", "Zx7-quie", true},
		{"exactly one under", "admin", "Zx7-quiet", true},
		{"the old default", "admin", "admin", true},
		{"common word", "admin", "password123", true},
		{"common word dressed up", "admin", "password2024!", true},
		{"product name", "admin", "hyperdns", true},
		{"equals username", "operator1", "operator1", true},
		{"single repeated rune", "admin", "aaaaaaaaaaaa", true},
		{"sequential run", "admin", "abcdefghijkl", true},
		{"descending run", "admin", "9876543210", true},
		{"one class and short of 16", "admin", "quietlantern", true},
		{"leading space", "admin", " Zx7-quiet-lantern", true},
		{"trailing space", "admin", "Zx7-quiet-lantern ", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tc.username, tc.password)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidatePasswordStrength(%q, %q) = nil, want an error", tc.username, tc.password)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidatePasswordStrength(%q, %q) = %v, want nil", tc.username, tc.password, err)
			}
			if got := IsWeakPassword(tc.username, tc.password); got != tc.wantErr {
				t.Fatalf("IsWeakPassword = %v, want %v", got, tc.wantErr)
			}
		})
	}
}

// The whole install-time password story depends on the values the installers and
// main.go generate passing the same policy they enforce on the operator.
func TestGeneratedPasswordShapePassesPolicy(t *testing.T) {
	// 12 random bytes rendered as hex, which is what generateInitialPassword and
	// `openssl rand -hex 12` both produce.
	const generated = "3f0a9c1d5e7b2048ac91"
	if err := ValidatePasswordStrength("admin", generated); err != nil {
		t.Fatalf("a generated install password must satisfy the policy it enforces: %v", err)
	}
}

// Login is unauthenticated, so the cost of one verification is the cost an
// attacker can impose. This is not a strict assertion about hardware; it fails
// only if the work factor has drifted somewhere absurd.
func TestVerifyPasswordCostIsBounded(t *testing.T) {
	encoded, err := HashPassword("timing-probe-pass-5")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	start := time.Now()
	if !VerifyPassword(encoded, "timing-probe-pass-5") {
		t.Fatal("verification failed")
	}
	elapsed := time.Since(start)
	t.Logf("PBKDF2-HMAC-SHA256 at %d iterations: %v per verification", DefaultPBKDF2Iterations, elapsed)
	if elapsed > 3*time.Second {
		t.Errorf("one verification took %v; the work factor is too high for an unauthenticated endpoint", elapsed)
	}
}
