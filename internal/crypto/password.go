package crypto

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

// Password storage for the single dashboard administrator.
//
// The admin password used to be kept as plaintext inside the "server" settings
// record. The record itself is AES-256-GCM encrypted, but that only protects it
// at rest: the value was readable by anything holding the settings struct, it
// would appear verbatim in a debug dump or a crash log, and an operator who
// reuses passwords loses far more than this panel. Storing a one-way hash costs
// nothing here — the value is only ever compared, never displayed.
//
// PBKDF2-HMAC-SHA256 from the standard library is used deliberately instead of
// argon2id: it adds no dependency (keeping the offline build reliable and the
// module graph at three direct requirements) and it is CPU-hard rather than
// memory-hard. Memory-hardness on an unauthenticated endpoint is a lever an
// attacker can pull — ~64 MB per attempt is a real threat to the 1 GB VPS this
// project targets, where the DNS resolver must keep answering. Iteration count
// follows current OWASP guidance for PBKDF2-HMAC-SHA256.
const (
	// pbkdf2Scheme is the identifier written into the encoded hash. Every stored
	// value names its own scheme and cost, so these constants can be raised
	// later without invalidating existing hashes.
	pbkdf2Scheme = "pbkdf2-sha256"

	// DefaultPBKDF2Iterations is the work factor applied to new hashes.
	DefaultPBKDF2Iterations = 600_000

	// passwordSaltSize is 16 bytes: enough that two installs never collide, so a
	// precomputed table cannot be shared between them.
	passwordSaltSize = 16

	// passwordKeySize matches the SHA-256 output width.
	passwordKeySize = 32

	// MinPasswordLength replaces the previous 5-character rule, which allowed
	// passwords a dictionary run guesses in seconds. Length is the only property
	// that reliably resists offline guessing, so it is preferred here over
	// character-class rules that mostly teach people to append "1!".
	MinPasswordLength = 10

	// maxPasswordLength bounds the work an unauthenticated caller can request.
	// PBKDF2 runs HMAC over the password on every iteration, so an unbounded
	// password is an unbounded amount of hashing per login attempt.
	maxPasswordLength = 256
)

// ErrPasswordHashUnsupported is returned when a stored value looks like an
// encoded hash but this build cannot evaluate it — a newer scheme, a truncated
// record, corrupted base64.
var ErrPasswordHashUnsupported = errors.New("crypto: stored password hash is not in a supported format")

// HashPassword derives a verifier for plaintext and returns it in the
// self-describing form "pbkdf2-sha256$<iterations>$<salt>$<hash>", both fields
// raw (unpadded) standard base64. The salt is fresh on every call, so hashing
// the same password twice yields different strings.
func HashPassword(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("crypto: refusing to hash an empty password")
	}
	if len(plaintext) > maxPasswordLength {
		return "", fmt.Errorf("crypto: password is longer than %d bytes", maxPasswordLength)
	}

	salt := make([]byte, passwordSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		// A predictable salt is not a salt. Fail rather than derive from zeros.
		return "", fmt.Errorf("crypto: failed to generate password salt: %w", err)
	}

	return hashPasswordWith(plaintext, DefaultPBKDF2Iterations, salt)
}

// HashPasswordWithCost is the testing seam for the work factor. Production
// always uses DefaultPBKDF2Iterations; the sole reason this exists is that the
// web test suite logs in hundreds of times, and every login pays a full
// derivation. Under the race detector that is slow enough to age a TOTP code
// out of its ±1-step window between the moment a test derives it and the
// moment the handler spends it — which made the 2FA tests flap for a reason
// that has nothing to do with what they check. A low cost keeps the suite
// inside a step without weakening a single production hash.
func HashPasswordWithCost(plaintext string, iterations int) (string, error) {
	if iterations < 1 {
		return "", errors.New("crypto: password iterations must be positive")
	}
	salt := make([]byte, passwordSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("crypto: failed to generate password salt: %w", err)
	}
	return hashPasswordWith(plaintext, iterations, salt)
}

// hashPasswordWith is the deterministic core, split out so tests can pin a salt
// and an iteration count.
func hashPasswordWith(plaintext string, iterations int, salt []byte) (string, error) {
	key, err := pbkdf2.Key(sha256.New, plaintext, salt, iterations, passwordKeySize)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to derive password hash: %w", err)
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s",
		pbkdf2Scheme, iterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// IsPasswordHash reports whether stored is an encoded hash produced by
// HashPassword rather than a legacy plaintext password. It is the migration
// signal: anything that is not a hash still needs converting.
func IsPasswordHash(stored string) bool {
	_, _, _, err := parsePasswordHash(stored)
	return err == nil
}

// VerifyPassword reports whether plaintext matches the stored value.
//
// A stored hash is verified by re-deriving with the recorded salt and cost. A
// stored plaintext (a value written before hashing existed, or one supplied by
// config.json) is compared directly, in constant time, so an install that has
// not migrated yet can still be logged into — see main.go, which converts it on
// the next start.
func VerifyPassword(stored, plaintext string) bool {
	if stored == "" || plaintext == "" {
		// An empty stored password must never authorise anything, and in
		// particular must not be treated as "matches an empty submission".
		return false
	}
	if len(plaintext) > maxPasswordLength {
		return false
	}

	scheme, iterations, salt, want, err := splitPasswordHash(stored)
	if err != nil {
		// Legacy plaintext.
		return subtle.ConstantTimeCompare([]byte(stored), []byte(plaintext)) == 1
	}
	if scheme != pbkdf2Scheme {
		return false
	}

	got, kerr := pbkdf2.Key(sha256.New, plaintext, salt, iterations, len(want))
	if kerr != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, got) == 1
}

// NeedsRehash reports whether a stored hash was produced with a weaker cost
// than this build now applies, so it can be upgraded the next time the
// plaintext is available.
func NeedsRehash(stored string) bool {
	_, iterations, _, err := parsePasswordHash(stored)
	if err != nil {
		// Not a hash at all: it needs converting, which is a stronger statement.
		return true
	}
	return iterations < DefaultPBKDF2Iterations
}

// parsePasswordHash validates the encoding and reports the scheme, cost and
// salt length without deriving anything.
func parsePasswordHash(stored string) (scheme string, iterations int, saltLen int, err error) {
	s, iter, salt, _, err := splitPasswordHash(stored)
	if err != nil {
		return "", 0, 0, err
	}
	return s, iter, len(salt), nil
}

func splitPasswordHash(stored string) (scheme string, iterations int, salt, hash []byte, err error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 {
		return "", 0, nil, nil, ErrPasswordHashUnsupported
	}
	scheme = parts[0]
	if scheme != pbkdf2Scheme {
		return "", 0, nil, nil, ErrPasswordHashUnsupported
	}

	iterations, err = strconv.Atoi(parts[1])
	if err != nil || iterations < 1 {
		return "", 0, nil, nil, ErrPasswordHashUnsupported
	}
	// A hostile settings record could name an absurd cost and turn every login
	// into a stall. Cap what this build is willing to execute.
	if iterations > 20*DefaultPBKDF2Iterations {
		return "", 0, nil, nil, ErrPasswordHashUnsupported
	}

	enc := base64.RawStdEncoding
	if salt, err = enc.DecodeString(parts[2]); err != nil || len(salt) == 0 {
		return "", 0, nil, nil, ErrPasswordHashUnsupported
	}
	if hash, err = enc.DecodeString(parts[3]); err != nil || len(hash) == 0 {
		return "", 0, nil, nil, ErrPasswordHashUnsupported
	}
	return scheme, iterations, salt, hash, nil
}

// commonPasswords are the values dictionary runs against exposed control panels
// try first, plus the ones this project's own history and documentation made
// obvious. The list is short on purpose: it is not a substitute for the length
// rule, it exists to stop the handful of choices that make the length rule moot.
var commonPasswords = map[string]struct{}{
	"admin": {}, "password": {}, "passw0rd": {}, "p@ssword": {}, "p@ssw0rd": {},
	"administrator": {}, "root": {}, "toor": {}, "letmein": {}, "welcome": {},
	"changeme": {}, "change-me": {}, "secret": {}, "default": {}, "qwerty": {},
	"qwertyuiop": {}, "asdfghjkl": {}, "zxcvbnm": {}, "iloveyou": {},
	"dragon": {}, "monkey": {}, "sunshine": {}, "princess": {}, "football": {},
	"baseball": {}, "superman": {}, "trustno1": {}, "starwars": {},
	"hyperdns": {}, "hyperrain": {}, "smartdns": {}, "dnsadmin": {},
	"adminadmin": {}, "admin1234": {}, "admin12345": {}, "administrator1": {},
	"password1": {}, "password12": {}, "password123": {}, "password1234": {},
	"1234567890": {}, "0987654321": {}, "12345678": {}, "123456789": {},
	"1qaz2wsx": {}, "qazwsxedc": {}, "abc123456": {}, "a1b2c3d4": {},
}

// ValidatePasswordStrength reports why plaintext is unfit to be the
// administrator password, or nil when it is acceptable. The returned message is
// written to be shown to the operator verbatim.
//
// This is deliberately only enforced when a password is *set*. Verification
// never applies it, so an install carrying a short legacy password keeps
// working and the operator is prompted to change it rather than locked out.
func ValidatePasswordStrength(username, plaintext string) error {
	if plaintext == "" {
		return errors.New("password cannot be empty")
	}
	if len(plaintext) > maxPasswordLength {
		return fmt.Errorf("password cannot be longer than %d characters", maxPasswordLength)
	}
	// Count runes, not bytes: a Persian or emoji passphrase is not short just
	// because UTF-8 spends more bytes on it.
	runes := []rune(plaintext)
	if len(runes) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters (this one is %d)", MinPasswordLength, len(runes))
	}
	if strings.TrimSpace(plaintext) != plaintext {
		return errors.New("password cannot start or end with a space")
	}

	folded := strings.ToLower(plaintext)
	if _, bad := commonPasswords[folded]; bad {
		return errors.New("that password appears on every guessing list; choose something unrelated to the product or to the word \"admin\"")
	}
	// Trailing digits are the usual way a common password is dressed up to pass
	// a length rule ("password2024"), so strip them and re-check.
	if stripped := strings.TrimRight(folded, "0123456789!@#$%^&*_-."); stripped != folded && len(stripped) >= 4 {
		if _, bad := commonPasswords[stripped]; bad {
			return errors.New("that is a common password with characters appended; choose something unrelated")
		}
	}

	if username != "" && strings.EqualFold(plaintext, username) {
		return errors.New("password cannot be the same as the username")
	}

	if isSingleRepeatedRune(runes) {
		return errors.New("password cannot be the same character repeated")
	}
	if isSequentialRun(runes) {
		return errors.New("password cannot be a single run of consecutive characters")
	}
	// A single character class over ten ASCII characters is still weak against a
	// targeted run, so ask for two. The rule is skipped once length or alphabet
	// already carries the keyspace: a 16-character phrase, or anything using a
	// non-ASCII script (a Persian passphrase is not weak for being all one
	// "class" — it draws from a far larger alphabet than [a-z]).
	if len(runes) < 16 && !hasNonASCII(runes) && countCharacterClasses(runes) < 2 {
		return errors.New("password must combine at least two of: lower case, upper case, digits, symbols — or be at least 16 characters long")
	}

	return nil
}

// IsWeakPassword is the boolean form of ValidatePasswordStrength, used to flag
// an install that is still carrying a pre-policy password so the dashboard can
// prompt for a replacement.
func IsWeakPassword(username, plaintext string) bool {
	return ValidatePasswordStrength(username, plaintext) != nil
}

func isSingleRepeatedRune(runes []rune) bool {
	for _, r := range runes[1:] {
		if r != runes[0] {
			return false
		}
	}
	return true
}

// isSequentialRun reports whether every rune steps by the same ±1 from the last
// ("abcdefghij", "9876543210"). Anything with a break in it is not a run.
func isSequentialRun(runes []rune) bool {
	if len(runes) < 4 {
		return false
	}
	step := runes[1] - runes[0]
	if step != 1 && step != -1 {
		return false
	}
	for i := 2; i < len(runes); i++ {
		if runes[i]-runes[i-1] != step {
			return false
		}
	}
	return true
}

// hasNonASCII reports whether the password draws on an alphabet wider than
// printable ASCII, which by itself makes an exhaustive run far more expensive.
func hasNonASCII(runes []rune) bool {
	for _, r := range runes {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

func countCharacterClasses(runes []rune) int {
	var lower, upper, digit, other bool
	for _, r := range runes {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			// Symbols, punctuation, and scripts without case (Persian, CJK) all
			// land here and count as their own class.
			other = true
		}
	}
	n := 0
	for _, present := range []bool{lower, upper, digit, other} {
		if present {
			n++
		}
	}
	return n
}
