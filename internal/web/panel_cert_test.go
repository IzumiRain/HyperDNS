package web

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"hyperdns/internal/database"
	"hyperdns/internal/service/acme"
)

// The panel-certificate resolver (v2.2.0 field report): renaming the panel
// domain saved the new name immediately while the certificate swap was a
// best-effort background run — a failed swap left CertPath naming the OLD
// domain's pair while Domain named the new one, and the panel served a
// certificate browsers rejected as ERR_CERT_COMMON_NAME_INVALID. The
// subscription surface never had the bug because its record changes only on
// success. panelCertificatePair resolves by the live domain, healing the
// stale-path state at boot with no write; these tests pin each precedence
// step using the same isolated-acme-dir pattern as the subscriber tests.

// stagePanelACMEPair writes a CA-signed pair for dnsName into the test's
// isolated ACME directory and points the manager at it.
func stagePanelACMEPair(t *testing.T, ws *WebServer, dnsName string) (certPath, keyPath string) {
	t.Helper()
	acmeDir := filepath.Join(t.TempDir(), "acme")
	ws.SetACMEManager(acme.NewManager("", "", acmeDir, nil))
	certPath, keyPath, _ = writeTestChainPair(t, dnsName)
	if err := os.MkdirAll(acmeDir, 0o700); err != nil {
		t.Fatalf("mkdir acme: %v", err)
	}
	dstCert := filepath.Join(acmeDir, dnsName+".crt")
	dstKey := filepath.Join(acmeDir, dnsName+".key")
	if err := os.Rename(certPath, dstCert); err != nil {
		t.Fatalf("move cert: %v", err)
	}
	if err := os.Rename(keyPath, dstKey); err != nil {
		t.Fatalf("move key: %v", err)
	}
	return dstCert, dstKey
}

// The report's exact field state: Domain renamed to the new name, CertPath
// still naming the old domain's pair, and a valid ACME pair for the NEW name
// on disk. The resolver must return the ACME pair.
func TestPanelCertificatePairHealsARenamedDomain(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	// A valid pair for the OLD name, left in the stored paths.
	oldCert, oldKey, _ := writeTestChainPair(t, "old.example")
	acmeCert, acmeKey := stagePanelACMEPair(t, ws, "web.example")
	ws.tlsSettings = &database.TLSSettings{Domain: "web.example", CertPath: oldCert, KeyPath: oldKey}

	gotCert, gotKey, err := ws.panelCertificatePair()
	if err != nil {
		t.Fatalf("panelCertificatePair refused the healed state: %v", err)
	}
	if gotCert != acmeCert || gotKey != acmeKey {
		t.Fatalf("resolver returned %s/%s, want the ACME pair %s/%s — a stale stored path must not outrank the live domain's pair", gotCert, gotKey, acmeCert, acmeKey)
	}
}

// Stored paths that DO cover the domain win: the pair the ACME apply wrote
// (or an operator-supplied one) is used as-is, no fallback needed.
func TestPanelCertificatePairUsesStoredPathsWhenTheyCoverTheDomain(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	stagePanelACMEPair(t, ws, "unrelated.example") // present but irrelevant

	cert, key, _ := writeTestChainPair(t, "web.example")
	ws.tlsSettings = &database.TLSSettings{Domain: "web.example", CertPath: cert, KeyPath: key}

	gotCert, gotKey, err := ws.panelCertificatePair()
	if err != nil {
		t.Fatalf("panelCertificatePair refused a valid stored pair: %v", err)
	}
	if gotCert != cert || gotKey != key {
		t.Fatalf("resolver returned %s/%s, want the stored pair %s/%s", gotCert, gotKey, cert, key)
	}
}

// Nothing covers the domain: the error names the Let's Encrypt fix, so the
// operator is told how to close the gap instead of reading a bare refusal.
func TestPanelCertificatePairErrorsNamingTheFix(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	stagePanelACMEPair(t, ws, "other.example")

	ws.tlsSettings = &database.TLSSettings{Domain: "web.example", CertPath: "certs/missing.pem", KeyPath: "certs/missing.key"}
	_, _, err := ws.panelCertificatePair()
	if err == nil {
		t.Fatal("a domain with no covering certificate resolved to a pair")
	}
	if !strings.Contains(err.Error(), "Let's Encrypt") {
		t.Errorf("the error does not name the fix: %v", err)
	}
}

// StartACMEIfNeeded with a renamed domain whose pair is already on disk must
// be a no-op: issuing again burns Let's Encrypt quota for a certificate the
// server already holds, and failing closed would loop a healthy install.
func TestStartACMEIfNeededSkipsWhenARenamedPairIsOnDisk(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	stagePanelACMEPair(t, ws, "web.example")

	oldCert, oldKey, _ := writeTestChainPair(t, "old.example")
	ws.tlsSettings = &database.TLSSettings{Domain: "web.example", CertPath: oldCert, KeyPath: oldKey}

	// A manager whose issuance would fail loudly if it ran: DirectoryURL
	// points at a closed port and CertDir at nowhere. The skip is what keeps
	// this test green — any issuance attempt times out or errors and the
	// post-check logs, but the assertion below is that the pair stayed
	// resolvable without it.
	ws.StartACMEIfNeeded()

	if _, _, err := ws.panelCertificatePair(); err != nil {
		t.Fatalf("after StartACMEIfNeeded the renamed pair no longer resolves: %v", err)
	}
}

// The handler's already-on-disk fast path: renaming the panel domain to a
// name with a valid pair on disk applies it synchronously — issuing:false in
// the response, paths applied, no ACME run started.
func TestTLSIssuePanelAppliesAnOnDiskPairWithoutIssuing(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()
	acmeCert, acmeKey := stagePanelACMEPair(t, ws, "web.example")
	// The gate is held so any attempt to start a run would be refused —
	// proving the fast path never tried.
	ws.acmeRunning.Store(true)
	defer ws.acmeRunning.Store(false)

	w := postJSON(t, h, "/api/tls/issue", `{"domain":"web.example","email":"","purpose":"panel"}`, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/tls/issue = %d — %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["issuing"] != false {
		t.Fatalf("issuing = %v, want false (the pair was on disk; no run may start)", body["issuing"])
	}
	detail, _ := body["detail"].(string)
	if !strings.Contains(detail, "already on this server") {
		t.Errorf("detail does not describe the no-quota apply: %q", detail)
	}
	if ws.tlsSettings.CertPath != acmeCert || ws.tlsSettings.KeyPath != acmeKey {
		t.Fatalf("stored paths = %s/%s, want the applied ACME pair %s/%s", ws.tlsSettings.CertPath, ws.tlsSettings.KeyPath, acmeCert, acmeKey)
	}
}

// The boot-level healing, through Start(): the report's exact field state
// (Domain renamed, CertPath still naming the old domain's pair, the new
// name's ACME pair on disk) must come up serving the NEW name's certificate
// — not the stale stored pair, not a fail-closed error.
func TestPanelStartServesTheRenamedDomainsPair(t *testing.T) {
	domain := "web.example"

	// A valid CA pair for the OLD name stays in the stored paths; the NEW
	// name's pair sits in the ACME directory.
	ws, port, _, cleanup := startTLSPanel(t, tlsPanelConfig{panelHTTPS: true})
	defer cleanup()
	stagePanelACMEPair(t, ws, domain)
	oldCert, oldKey, _ := writeTestChainPair(t, "old.example")
	ws.tlsSettings.Domain = domain
	ws.tlsSettings.CertPath = oldCert
	ws.tlsSettings.KeyPath = oldKey

	if err := ws.Start(); err != nil {
		t.Fatalf("Start refused a renamed domain whose ACME pair is on disk: %v", err)
	}
	if ws.tlsSettings.CertPath == oldCert {
		t.Fatal("Start loaded the stale stored pair instead of resolving by the live domain")
	}

	// A real handshake against the panel must present the new name.
	leafCN := peerLeafCN(t, port, domain)
	if !strings.Contains(leafCN, domain) {
		t.Fatalf("the panel presented a certificate for %q, want the renamed domain %q", leafCN, domain)
	}
}

// peerLeafCN performs a TLS handshake against the panel port with hostname
// verification disabled and returns the presented leaf's subject CN, so a
// test can assert WHICH certificate was served without trusting the test CA.
func peerLeafCN(t *testing.T, port int, _ string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true, // we are reading the presented name, not trusting it
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no peer certificate presented")
	}
	return certs[0].Subject.CommonName
}
