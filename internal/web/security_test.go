package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIsValidAdminPath pins the acceptance and rejection rules for the 16-char
// hexadecimal admin path.
func TestIsValidAdminPath(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  bool
	}{
		// Valid: exactly 16 lowercase hex chars.
		{"a1b2c3d4e5f67890", true},
		{"0000000000000000", true},
		{"ffffffffffffffff", true},
		{"deadbeefcafe0123", true},

		// Too short or too long.
		{"a1b2c3d4e5f6789", false},   // 15 chars
		{"a1b2c3d4e5f678901", false}, // 17 chars
		{"", false},

		// Uppercase rejected — paths are canonical lowercase.
		{"A1B2C3D4E5F67890", false},
		{"DeadBeefCafe0123", false},

		// Non-hex characters.
		{"g1b2c3d4e5f67890", false},
		{"a1b2c3d4e5f6789x", false},

		// Spaces and path separators.
		{"a1b2c3d4e5f6 890", false},
		{"/a1b2c3d4e5f67890", false},
		{"a1b2c3d4e5f67890/", false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := IsValidAdminPath(tc.input); got != tc.want {
				t.Errorf("IsValidAdminPath(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestGenerateAdminPathProperties checks the structural guarantees on generated
// paths without asserting on the random value itself.
func TestGenerateAdminPathProperties(t *testing.T) {
	seen := map[string]bool{}
	for i := range 20 {
		p := GenerateAdminPath()
		if !IsValidAdminPath(p) {
			t.Fatalf("iteration %d: GenerateAdminPath() = %q, not a valid admin path", i, p)
		}
		if seen[p] {
			t.Fatalf("iteration %d: GenerateAdminPath() returned %q twice — the generator is not random", i, p)
		}
		seen[p] = true
	}
}

// TestNormalizeURIPath covers the canonicalisation rules that protect the
// subscription URI path from path traversal and broken routing.
func TestNormalizeURIPath(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		// Empty stays empty.
		{"\t  \n", ""},
		{"", ""},

		// Leading slash added, trailing slash removed.
		{"sub", "/sub"},
		{"/sub", "/sub"},
		{"/sub/", "/sub"},
		{"sub/", "/sub"},

		// Nested paths allowed.
		{"/sub/v2", "/sub/v2"},
		{"sub/v2/", "/sub/v2"},

		// Root path allowed.
		{"/", "/"},

		// Double slashes rejected.
		{"//sub", ""},
		{"/sub//v2", ""},

		// Backslashes and whitespace rejected.
		{"sub\\v2", ""},
		{"/sub v2", ""},
		{"/sub\tv2", ""},
	} {
		t.Run("input:"+tc.input, func(t *testing.T) {
			if got := NormalizeURIPath(tc.input); got != tc.want {
				t.Errorf("NormalizeURIPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestNormalizeCIDRs covers the CIDR normalisation rules: valid CIDRs are
// accepted and canonicalised, bare IPs are expanded to /32 or /128, duplicates
// are dropped, and invalid entries are skipped.
func TestNormalizeCIDRs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", nil},
		{"single CIDR", "10.0.0.0/8", []string{"10.0.0.0/8"}},
		{"bare IPv4 gets /32", "203.0.113.9", []string{"203.0.113.9/32"}},
		{"bare IPv6 gets /128", "::1", []string{"::1/128"}},
		{"comma-separated", "10.0.0.0/8,192.168.1.0/24", []string{"10.0.0.0/8", "192.168.1.0/24"}},
		{"newline-separated", "10.0.0.0/8\n192.168.1.0/24", []string{"10.0.0.0/8", "192.168.1.0/24"}},
		{"duplicates dropped", "10.0.0.0/8,10.0.0.0/8", []string{"10.0.0.0/8"}},
		// Host bits in the input are normalised to network address.
		{"host bits normalised", "10.1.2.3/8", []string{"10.0.0.0/8"}},
		{"invalid entries skipped", "10.0.0.0/8,not-a-cidr,192.168.1.0/24", []string{"10.0.0.0/8", "192.168.1.0/24"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeCIDRs(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("NormalizeCIDRs(%q) = %v (len %d), want %v (len %d)",
					tc.input, got, len(got), tc.want, len(tc.want))
			}
			for i, w := range tc.want {
				if got[i] != w {
					t.Errorf("NormalizeCIDRs(%q)[%d] = %q, want %q", tc.input, i, got[i], w)
				}
			}
		})
	}
}

// TestSanitizeThemeCSSRemovesVectors confirms that each external-load and
// HTML-break construct is removed or defanged.
func TestSanitizeThemeCSSRemovesVectors(t *testing.T) {
	// Each entry describes a single construct; the want is what remains after
	// sanitising. For complete removal the want is an empty string or a
	// vestigial space/semicolon that the browser's CSS parser ignores harmlessly.
	for _, tc := range []struct {
		name  string
		input string
		// wantAbsent: these strings must NOT appear in the sanitised output.
		wantAbsent []string
		// wantPresent: these strings MUST appear (proving safe content survives).
		wantPresent []string
	}{
		{
			name:        "@import removed",
			input:       `@import url("https://attacker.example/steal.css"); body { color: red; }`,
			wantAbsent:  []string{`@import`, `attacker.example`},
			wantPresent: []string{`body`, `color: red`},
		},
		{
			name:        "external url() removed",
			input:       `body { background: url("https://attacker.example/img.png"); }`,
			wantAbsent:  []string{`attacker.example`},
			wantPresent: []string{`body`, `background:`},
		},
		{
			name:        "protocol-relative url() removed",
			input:       `body { background: url(//attacker.example/img.png); }`,
			wantAbsent:  []string{`attacker.example`},
			wantPresent: []string{`body`, `background:`},
		},
		{
			name:        "expression() removed",
			input:       `body { width: expression(alert(1)); }`,
			wantAbsent:  []string{`expression(`, `alert(`},
			wantPresent: []string{`body`, `width:`},
		},
		{
			name:        "<style> tag escaped",
			input:       `</style><script>alert(1)</script><style>body{color:red}`,
			wantAbsent:  []string{"</style>", "<script>"},
			wantPresent: []string{"body{color:red}"},
		},
		{
			name:        "safe relative url() preserved",
			input:       `body { background: url('/img/bg.png'); }`,
			wantPresent: []string{`url('/img/bg.png')`},
		},
		{
			name:        "safe data URI preserved",
			input:       `body { background: url("data:image/png;base64,abc"); }`,
			wantPresent: []string{`data:image/png;base64,abc`},
		},
		{
			name:        "ordinary color rules survive untouched",
			input:       `.portal-card { background: #1a1a2e; color: rgba(0,200,100,0.9); }`,
			wantPresent: []string{`#1a1a2e`, `rgba(0,200,100,0.9)`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeThemeCSS(tc.input)
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("SanitizeThemeCSS output still contains %q: %s", absent, got)
				}
			}
			for _, present := range tc.wantPresent {
				if !strings.Contains(got, present) {
					t.Errorf("SanitizeThemeCSS output lost %q: %s", present, got)
				}
			}
		})
	}
}

// TestSanitizeThemeCSSCaseInsensitive confirms that vector patterns in mixed
// case are also caught, since CSS is case-insensitive and attackers know it.
func TestSanitizeThemeCSSCaseInsensitive(t *testing.T) {
	cases := []string{
		`@IMPORT url("https://x.example/");`,
		`@Import url("https://x.example/");`,
		`body { background: URL("HTTPS://x.example/"); }`,
		`body { width: EXPRESSION(alert(1)); }`,
		`body { width: Expression ( alert(1) ); }`,
	}
	for _, input := range cases {
		got := SanitizeThemeCSS(input)
		if strings.Contains(strings.ToLower(got), "x.example") ||
			strings.Contains(strings.ToLower(got), "alert(") {
			t.Errorf("SanitizeThemeCSS left a vector in %q: %s", input, got)
		}
	}
}

// TestSanitizeThemeCSSEscapesTagBreakoutInAnyCase is the case half of the
// tag-escaping rule, and it is the one that decides whether the sanitiser is a
// control at all.
//
// The theme lands inside a <style> element as template.CSS, which html/template
// inserts verbatim. An HTML tokenizer leaves a raw-text element on the first
// ASCII-case-insensitive "</style", so "</STYLE><SCRIPT>" closes the element and
// starts executing script on a page every subscriber loads and the operator
// never sees. Matching only the lowercase spelling defeats the whole control
// with a Shift key, so every case variant of the four tag prefixes has to be
// defanged.
func TestSanitizeThemeCSSEscapesTagBreakoutInAnyCase(t *testing.T) {
	for _, input := range []string{
		`</STYLE><SCRIPT>alert(1)</SCRIPT><STYLE>`,
		`</Style><Script>alert(1)</Script><Style>`,
		`</StYlE ><sCrIpT>alert(1)</sCrIpT>`,
		`</style><script>alert(1)</script>`,
	} {
		got := SanitizeThemeCSS(input)
		lower := strings.ToLower(got)
		for _, breakout := range []string{"</style", "<style", "</script", "<script"} {
			if strings.Contains(lower, breakout) {
				t.Errorf("SanitizeThemeCSS(%q) still contains a raw %q breakout: %s", input, breakout, got)
			}
		}
	}
}

// TestNormalizeDomain covers the hostname canonicalisation rules that keep a
// domain from silently carrying something that breaks TLS SNI or certificate
// matching — a scheme, a port, a path, a wildcard, or an IP address.
func TestNormalizeDomain(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		// Simple names are lowercased and accepted.
		{"example.com", "example.com"},
		{"EXAMPLE.com", "example.com"},
		// A single trailing dot (a fully-qualified name) is stripped.
		{"example.com.", "example.com"},
		// Leading/trailing whitespace is trimmed.
		{"  example.com  ", "example.com"},
		// Multi-label and single-label names.
		{"sub.example.co.uk", "sub.example.co.uk"},
		{"localhost", "localhost"},
		{"panel-1.example.com", "panel-1.example.com"},

		// Rejected: not a bare hostname.
		{"https://example.com", ""}, // scheme
		{"example.com:8443", ""},    // port
		{"example.com/sub", ""},     // path
		{"*.example.com", ""},       // wildcard
		{"example\\com", ""},        // backslash

		// Rejected: an IP address is not a hostname.
		{"203.0.113.9", ""},
		{"2001:db8::1", ""},

		// Rejected: malformed hostnames.
		{"", ""},
		{"   ", ""},
		{"exa mple.com", ""},     // space
		{"-bad.example.com", ""}, // leading hyphen
		{"bad-.example.com", ""}, // trailing hyphen
		{"..example.com", ""},    // empty label

		// Over-long hostnames are rejected.
		{strings.Repeat("a", 254), ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := NormalizeDomain(tc.input); got != tc.want {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestIsValidPort pins the accepted and rejected ports.
func TestIsValidPort(t *testing.T) {
	for _, tc := range []struct {
		p    int
		want bool
	}{
		{443, true},
		{80, true},
		{8443, true},
		{53, true},
		{1, true},
		{65535, true},
		{0, false}, // the "not configured" sentinel
		{-1, false},
		{65536, false},
		{-443, false},
	} {
		t.Run(fmt.Sprintf("port_%d", tc.p), func(t *testing.T) {
			if got := IsValidPort(tc.p); got != tc.want {
				t.Errorf("IsValidPort(%d) = %v, want %v", tc.p, got, tc.want)
			}
		})
	}
}

// TestIsValidTimeZone accepts well-known IANA locations and rejects a typo or an
// empty value, so a misconfigured zone cannot silently render UTC.
func TestIsValidTimeZone(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"Europe/London", true},
		{"Asia/Tehran", true},
		{"UTC", true},
		{"Etc/GMT-3", true},
		{"America/New_York", true},
		{"", false},
		{"Europe/Londonn", false}, // typo
		{"Not/AZone", false},
		{" UTC ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidTimeZone(tc.name); got != tc.want {
				t.Errorf("IsValidTimeZone(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// writeTestCertificatePair generates a self-signed server certificate and key on
// the system CSPRNG and writes them as PEM files in a fresh temp directory. The
// certificate names a single DNS name, so a caller can rely on it for hostname
// match tests and on it not matching a different name.
func writeTestCertificatePair(t *testing.T, dnsName string) (certPath, keyPath string) {
	t.Helper()
	return writeTestCertificatePairFor(t, dnsName, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// writeTestCertificatePairFor is the general form of writeTestCertificatePair: the
// caller chooses the certificate validity window, so a test can build an already
// expired or not-yet-valid certificate.
func writeTestCertificatePairFor(t *testing.T, dnsName string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// writeTestChainPair writes a leaf certificate signed by a freshly generated
// test CA. Every pair from writeTestCertificatePair is self-signed, and since
// the self-signed rejection a configured panel domain refuses exactly those —
// so tests that stand a listener up behind a domain use this helper instead,
// the way a real Let's Encrypt deployment would look.
func writeTestChainPair(t *testing.T, dnsName string) (certPath, keyPath, caPath string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA GenerateKey: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "HyperDNS Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA CreateCertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf GenerateKey: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf CreateCertificate: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	caPath = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o600); err != nil {
		t.Fatalf("write leaf: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}), 0o600); err != nil {
		t.Fatalf("write leaf key: %v", err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return certPath, keyPath, caPath
}

// TestValidateCertificatePair accepts a matching pair and rejects each failure
// mode: missing paths, unreadable files, a non-PEM file, and a mismatched pair.
func TestValidateCertificatePair(t *testing.T) {
	certPath, keyPath := writeTestCertificatePair(t, "test.example")

	if err := ValidateCertificatePair(certPath, keyPath); err != nil {
		t.Fatalf("ValidateCertificatePair rejected a valid pair: %v", err)
	}

	// A mismatched pair: take the key from one pair and the cert from another.
	otherCert, _ := writeTestCertificatePair(t, "other.example")
	if err := ValidateCertificatePair(otherCert, keyPath); err == nil {
		t.Error("ValidateCertificatePair accepted a cert from one pair and a key from another")
	}

	// A missing key file.
	if err := ValidateCertificatePair(certPath, filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Error("ValidateCertificatePair accepted a pair whose key file does not exist")
	}

	// A non-PEM file.
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	if err := ValidateCertificatePair(junk, keyPath); err == nil {
		t.Error("ValidateCertificatePair accepted a certificate file that is not a certificate")
	}

	// Empty paths are the caller's "not configured" state and must be reported.
	if err := ValidateCertificatePair("", ""); err == nil {
		t.Error("ValidateCertificatePair accepted empty paths")
	}
	if err := ValidateCertificatePair("   ", "  "); err == nil {
		t.Error("ValidateCertificatePair accepted whitespace paths")
	}
}

// TestValidatePanelCertificate accepts a valid, currently-usable pair and rejects
// each failure mode the startup guard has to catch: a mismatch, a not-yet-valid
// certificate, an expired certificate, a certificate that does not cover the
// configured domain, and empty paths. The positive case is a CA-signed pair —
// the self-signed refusal for named domains is pinned separately in
// TestValidatePanelCertificateRefusesSelfSignedForDomain.
func TestValidatePanelCertificate(t *testing.T) {
	certPath, keyPath, _ := writeTestChainPair(t, "panel.example")

	if err := ValidatePanelCertificate(certPath, keyPath, "panel.example"); err != nil {
		t.Fatalf("ValidatePanelCertificate rejected a valid pair for its own name: %v", err)
	}
	// A domain that is not covered must be reported before the listener opens.
	if err := ValidatePanelCertificate(certPath, keyPath, "other.example"); err == nil {
		t.Error("ValidatePanelCertificate accepted a certificate that does not cover the domain")
	}
	// Empty paths are the caller's "not configured" state.
	if err := ValidatePanelCertificate("", "", "panel.example"); err == nil {
		t.Error("ValidatePanelCertificate accepted empty paths")
	}

	// A not-yet-valid certificate: issued tomorrow, so it cannot serve today.
	futureCert, futureKey := writeTestCertificatePairFor(t, "panel.example", time.Now().Add(time.Hour), time.Now().Add(24*time.Hour))
	if err := ValidatePanelCertificate(futureCert, futureKey, "panel.example"); err == nil {
		t.Error("ValidatePanelCertificate accepted a certificate that is not valid yet")
	}

	// An expired certificate: valid until yesterday.
	pastCert, pastKey := writeTestCertificatePairFor(t, "panel.example", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if err := ValidatePanelCertificate(pastCert, pastKey, "panel.example"); err == nil {
		t.Error("ValidatePanelCertificate accepted an expired certificate")
	}

	// A mismatched pair is still a hard failure, as in ValidateCertificatePair.
	otherCert, _ := writeTestCertificatePair(t, "other.example")
	if err := ValidatePanelCertificate(otherCert, keyPath, "panel.example"); err == nil {
		t.Error("ValidatePanelCertificate accepted a cert from one pair and a key from another")
	}
}

// TestValidatePanelCertificateRefusesSelfSignedForDomain pins the check that
// makes the ACME paths fire on a fresh domain install: the fallback generator
// writes the configured domain into the fallback certificate's SAN, so a
// self-signed pair passes every date and hostname test and used to be accepted
// as "a usable certificate is already in place" — which is how a domain
// install ended up serving Not secure with the issuer never having run.
func TestValidatePanelCertificateRefusesSelfSignedForDomain(t *testing.T) {
	certPath, keyPath := writeTestCertificatePair(t, "panel.example")

	err := ValidatePanelCertificate(certPath, keyPath, "panel.example")
	if err == nil {
		t.Fatal("ValidatePanelCertificate accepted a self-signed certificate for the configured domain")
	}
	if !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("the error should name the self-signed condition, got: %v", err)
	}

	// Without a domain the same pair is acceptable: that is the SSH-tunnel
	// deployment, where a hand-trusted self-signed pair is the documented way
	// to carry TLS.
	if err := ValidatePanelCertificate(certPath, keyPath, ""); err != nil {
		t.Errorf("ValidatePanelCertificate refused a self-signed pair on a no-domain install: %v", err)
	}
}

// TestValidatePanelCertificateAcceptsCASignedForDomain: the positive half. A
// leaf signed by any CA — here a test CA standing in for Let's Encrypt — is
// accepted for the name it carries.
func TestValidatePanelCertificateAcceptsCASignedForDomain(t *testing.T) {
	certPath, keyPath, _ := writeTestChainPair(t, "panel.example")

	if err := ValidatePanelCertificate(certPath, keyPath, "panel.example"); err != nil {
		t.Fatalf("ValidatePanelCertificate refused a CA-signed certificate for its own name: %v", err)
	}
}

// TestSafeRedirectHost pins which Host values may be used as the destination of
// an HTTP-to-HTTPS redirect. Only a bare hostname or IP may survive; everything
// that would let a typed Host header redirect elsewhere is dropped.
func TestSafeRedirectHost(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		// Plain names and IPs survive.
		{"panel.example", "panel.example"},
		{"PANEL.example", "panel.example"},
		{"panel.example", "panel.example"},
		{"203.0.113.9", "203.0.113.9"},
		{"2001:db8::1", "2001:db8::1"},

		// A trailing port is stripped; the caller re-adds the panel port.
		{"panel.example:8443", "panel.example"},
		{"203.0.113.9:8080", "203.0.113.9"},
		{"[2001:db8::1]:8443", "2001:db8::1"},

		// Anything that changes the destination is dropped.
		{"https://panel.example", ""}, // scheme
		{"user@panel.example", ""},    // userinfo
		{"panel.example/path", ""},    // path
		{"panel.example?x=1", ""},     // query
		{"panel.example#frag", ""},    // fragment
		{"panel.example:8443:extra", ""},
		{"", ""},
		{"   ", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := SafeRedirectHost(tc.input); got != tc.want {
				t.Errorf("SafeRedirectHost(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
