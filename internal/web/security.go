// Shared validation for security-sensitive free-text settings: the admin path,
// subscription URI paths, CIDR lists and the subscriber's custom CSS.
//
// These values are operator-supplied and land in routing decisions (which URL is
// the panel, which URL is a public subscriber link) or in HTML that a stranger
// reads (/sub/ pages). A bad value is not a 404 someone files a ticket about:
// an admin path that is not exactly one opaque segment can smuggle the dashboard
// behind a predictable address, and a CSS value containing <style>-breaking
// sequences can turn a theming field into an HTML injection vector on a page
// the operator cannot see. Validating once here keeps every handler that reads
// these settings honest without each one re-learning the rules.
package web

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// adminPathLen is the exact length of the generated admin path: 16 hex
// characters, 64 bits of entropy. The length is fixed rather than ranged —
// a path shorter than this is a legacy or hand-edited value and is rejected,
// and a longer one breaks the front-end's base-path arithmetic, which counts
// characters when stripping the prefix.
const adminPathLen = 16

var adminPathPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// IsValidAdminPath reports whether s is a well-formed admin path.
func IsValidAdminPath(s string) bool {
	return adminPathPattern.MatchString(s)
}

// GenerateAdminPath returns a new admin path drawn from the system CSPRNG.
//
// The error is discarded because crypto/rand.Read is documented never to return
// one — it fills b entirely or crashes the process — the same reasoning main.go
// uses for the generated admin password.
func GenerateAdminPath() string {
	b := make([]byte, adminPathLen/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normalizeURIPath reduces an operator-supplied URI path to its canonical form:
// it must be empty or begin with a single "/", it must not end with one (except
// when it is just "/"), and it must not contain backslashes, control characters
// or whitespace — any of which would change how a browser or an intermediate
// proxy treats the address. Returns the cleaned path, or "" if it cannot be
// cleaned to something safe.
func normalizeURIPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if strings.ContainsAny(p, "\\\t\r\n ") {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for strings.HasSuffix(p, "/") && len(p) > 1 {
		p = p[:len(p)-1]
	}
	// At least two segments deep is not a requirement; a single "/" path is
	// the root and is valid. What is not valid is a bare empty segment
	// somewhere in the middle — "//x" — because it parses differently in
	// net/http's mux than it reads.
	if strings.Contains(p, "//") {
		return ""
	}
	return p
}

// NormalizeURIPath is the exported form used by settings handlers.
func NormalizeURIPath(p string) string {
	return normalizeURIPath(p)
}

// NormalizeCIDRs parses and canonicalises a comma- or newline-separated list of
// CIDR blocks, keeping only entries that name an address with an explicit or
// implied network mask. Invalid entries are dropped rather than failing the
// whole list, matching how the installers write these values by hand.
func NormalizeCIDRs(raw string) []string {
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == ';'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Accept bare IPs by expanding them to /32 or /128.
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				if ip.To4() != nil {
					part += "/32"
				} else {
					part += "/128"
				}
			}
		}
		ip, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			continue
		}
		// Canonicalise: use the network address, not the host address.
		_ = ip
		key := ipnet.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// hostnameLabelRe matches one DNS label: 1 to 63 characters, alphanumeric, with
// hyphens allowed inside but never at the ends. This is the label shape RFC 1035
// permits; matching it per label is what keeps a hostname from silently carrying
// a scheme, a wildcard, or a path delimiter.
var hostnameLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain canonicalises an operator-supplied hostname for TLS SNI
// selection and for the addresses the resolver answers proxied records with.
//
// A domain lands in certificate matching, so a value that is not a bare hostname
// — one carrying a scheme, a port, a path, a wildcard or a backslash — would be
// served exactly as typed and break the handshake it is supposed to satisfy. The
// input is lowercased, a single trailing dot (a fully-qualified name) is
// stripped, and the result must be a valid hostname. Returns "" if the input is
// empty or cannot be cleaned to one.
func NormalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return ""
	}
	// An IP address is not a hostname: SNI needs a name, and serving an IP would
	// make certificate verification impossible when the certificate names a domain.
	if net.ParseIP(s) != nil {
		return ""
	}
	if strings.Contains(s, "://") || strings.ContainsAny(s, "/\\*:") {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if !hostnameLabelRe.MatchString(label) {
			return ""
		}
	}
	return s
}

// IsValidDomain reports whether s, after normalisation, is a non-empty hostname.
func IsValidDomain(s string) bool {
	return NormalizeDomain(s) != ""
}

// IsValidPort reports whether p is in the usable TCP/UDP port range.
//
// Zero is deliberately invalid: it is the callers' explicit "not configured"
// sentinel for an optional listener (e.g. the HTTP redirect port), and treating it
// as a bound port would make an operator's disabled toggle into a live listener.
func IsValidPort(p int) bool {
	return p >= 1 && p <= 65535
}

// IsValidTimeZone reports whether name is an IANA location the Go runtime can
// load. The zone is used when rendering subscriber and statistics timestamps, so
// a typo must fail at save time rather than silently producing UTC for every
// subscriber and every chart.
func IsValidTimeZone(name string) bool {
	if name == "" {
		return false
	}
	_, err := time.LoadLocation(name)
	return err == nil
}

// ValidateCertificatePair verifies that the certificate and private key files at
// the given paths load and match each other, without requiring the daemon to
// restart first.
//
// This is the save-time guard that stops a mismatched, missing or unreadable pair
// from being persisted as a valid configuration and only failing on the restart
// every other setting told the operator to perform. It deliberately does not
// check expiry or hostname coverage — those depend on the domain the certificate
// will be used for and are Phase 1's concern, inspected separately.
func ValidateCertificatePair(certPath, keyPath string) error {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return errors.New("certificate and key paths are required")
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return fmt.Errorf("certificate and key do not pair: %w", err)
	}
	return nil
}

// ValidatePanelCertificate is the startup guard for the HTTPS panel listener: it
// loads the certificate and key, then checks the four things that make a
// handshake succeed. It runs before any listener is opened, so a bad pair stops
// the daemon rather than serving a panel that no modern browser will accept.
//
//   - the key matches the certificate (tls.LoadX509KeyPair);
//   - the certificate is currently valid — not yet issued, and not expired;
//   - when a domain is given, the certificate actually names it;
//   - when a domain is given, the certificate is not self-signed.
//
// Domain is optional because the panel can be reached by IP and, before ACME
// runs, only carries a self-signed fallback certificate. When it is non-empty
// it is matched against the certificate's subject names — and the self-signed
// check is what makes the ACME paths fire at all. The fallback generator puts
// the configured domain in its SAN, so a date-and-hostname reading of a
// fallback pair passes every one of those checks and the daemon starts with a
// "Not secure" banner it was written never to show. A self-signed certificate
// is only acceptable to a browser that was told to trust it by hand, which is
// the no-domain SSH-tunnel case, not a named-domain public install.
func ValidatePanelCertificate(certPath, keyPath, domain string) error {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return errors.New("certificate and key paths are required")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("certificate and key do not pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return errors.New("certificate file contains no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("certificate could not be parsed: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("certificate is not valid yet (not before %s)", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate expired %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if domain != "" {
		if err := leaf.VerifyHostname(domain); err != nil {
			return fmt.Errorf("certificate does not cover domain %q: %w", domain, err)
		}
		if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
			return fmt.Errorf("certificate for %q is self-signed — the panel would show \"Not secure\" for every visitor; issue a CA-signed certificate (the dashboard's Issue SSL button uses the built-in ACME client) instead", domain)
		}
	}
	return nil
}

// SafeRedirectHost reduces a request Host header to the bare hostname or IP that
// may be used as the destination of an HTTP-to-HTTPS redirect.
//
// The HTTP redirect listener cannot trust the Host header: it is attacker-typed,
// and a Location built from it directly is an open redirect. The only part that
// may be used is a plain host — no scheme, no userinfo, no port (the caller adds
// the configured panel port), no path, no query. When the configured panel domain
// is known it is preferred over this value; SafeRedirectHost is the fallback for
// the all-IP deployment where there is no certificate name to bounce to.
func SafeRedirectHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	// A scheme, userinfo, path, query or fragment is never part of a Host header
	// value. These must be rejected before splitting on the port: net.SplitHostPort
	// reads "https://panel.example" as host "https" with a non-numeric port and
	// does not complain, so the scheme would otherwise survive as a bare hostname.
	if strings.ContainsAny(h, "/\\?#@") {
		return ""
	}
	// Drop a trailing port. net.SplitHostPort handles host:port and [v6]:port,
	// returning the host without its brackets for an IPv6 literal.
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	// Strip brackets so a bracketed IPv6 literal with no port is recognised as an
	// IP before the colon check below.
	h = strings.Trim(h, "[]")
	if ip := net.ParseIP(h); ip != nil {
		return h
	}
	// A remaining colon is a leftover port or a malformed IPv6 literal — nothing a
	// bare hostname may carry.
	if strings.Contains(h, ":") {
		return ""
	}
	return NormalizeDomain(h)
}

// maxThemeCSSBytes bounds the subscriber theme. It is not a style sheet — the
// realistic ceiling for the overrides an operator writes by hand is a few
// kilobytes, and a value past that is either a paste accident or an attempt to
// smuggle payload onto a page that is served to strangers with no other
// filtering. 16 KiB is the bound, chosen with an order of magnitude of margin
// over anything legitimate.
const maxThemeCSSBytes = 16 * 1024

// SanitizeThemeCSS removes the constructs that turn a CSS textbox into a vector
// for the subscriber page. It is a whitelist of removals, not a parser:
//
//   - <style> and </style> break out of the element the CSS is injected into.
//     Matching is case-insensitive because an HTML tokenizer leaves a raw-text
//     element on the first ASCII-case-insensitive "</style": a lowercase-only
//     replacement let "</STYLE><SCRIPT>" through and handed a reseller stored
//     script execution on every subscriber's page.
//   - <script> does not execute from inside <style> in browsers, but stripping
//     the tag defeats any later change that inlines the CSS elsewhere and the
//     cost is zero.
//   - @import and url(http…/https…) fetch content the operator did not approve
//     from hosts they cannot see, and url() is the CSS mechanism that loads
//     cross-origin resources. Only relative and data: URIs survive.
//   - expression() is the legacy Internet Explorer evaluation function; it does
//     not run anywhere that still matters, but its presence is a marker of
//     hostile input and its removal costs nothing.
//
// The result is the cleaned text, or the input unchanged if it is already
// clean. Callers still enforce the size limit and the HTML context rules
// independently; sanitizing here is a second layer, not the only one.
func SanitizeThemeCSS(css string) string {
	css = themeCSSTagRe.ReplaceAllString(css, "&lt;$1$2")
	css = themeCSSImportRe.ReplaceAllString(css, "")
	css = themeCSSExternalURLRe.ReplaceAllString(css, "")
	css = themeCSSExpressionRe.ReplaceAllString(css, "")
	return css
}

var (
	// themeCSSTagRe matches an opening or closing <style>/<script> tag prefix in
	// any case. The captured groups keep the operator's original spelling in the
	// defanged output, so the value they see back is recognisably theirs.
	themeCSSTagRe         = regexp.MustCompile(`(?i)<(/?)(style|script)`)
	themeCSSImportRe      = regexp.MustCompile(`(?i)@import\s+[^;{}]*;?`)
	themeCSSExternalURLRe = regexp.MustCompile(`(?i)url\(\s*(?:["']?)\s*(?:https?:|//)[^"')]*["']?\s*\)`)
	themeCSSExpressionRe  = regexp.MustCompile(`(?i)expression\s*\([^)]*\)`)
)

// themeCSSHasExternalReference reports whether the CSS pulls content from
// outside the panel — an @import rule or a url() that names an absolute or
// protocol-relative target. Such a value is stripped by SanitizeThemeCSS, and
// a settings handler may use this to tell the operator *why* their CSS came
// back different rather than silently changing it.
func themeCSSHasExternalReference(css string) bool {
	return themeCSSImportRe.MatchString(css) || themeCSSExternalURLRe.MatchString(css)
}
