package web

// Mantis PoC: panel purpose re-save burns a Let's Encrypt order even when the
// configured pair is already valid for the saved name.
//
// internal/web/tls.go:254-258 only takes the synchronous "already on this
// server" fast path when panelCertificatePair() resolves a pair whose paths
// DIFFER from the stored CertPath/KeyPath. When the stored pair is already
// valid for the new name (the ordinary "Save" click on an unchanged or
// re-saved domain), the two paths are equal, the condition is false, and the
// handler falls through to startACMEIssuance: a fresh RFC 8555 order against
// Let's Encrypt for a name this daemon already holds a valid certificate for.
// Let's Encrypt allows five duplicate certificates per name per week, so a
// handful of re-saves exhausts the weekly quota and blocks a later
// legitimate renewal.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdns/internal/service/acme"
)

// mantisCASignedPair builds a leaf for dnsName signed by a fresh test CA — the
// shape ValidatePanelCertificate accepts (not self-signed, valid dates,
// matching hostname).
func mantisCASignedPair(t *testing.T, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	caT := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mantis Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafT := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
}

func mantisWritePair(t *testing.T, certPath, keyPath string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write %s: %v", keyPath, err)
	}
}

// TestMantisPanelResaveWithValidCertBurnsAnOrder is the F2 reproducer. The
// stored pair is already valid for panel.example, so saving the same domain
// again must be a no-op over ACME. The unfixed handler returns issuing=true.
func TestMantisPanelResaveWithValidCertBurnsAnOrder(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	certDir := t.TempDir()
	// An unreachable directory URL keeps the PoC off the public network; the
	// assertion is made on the synchronous HTTP response, before the goroutine
	// this handler spawns ever reaches the CA.
	ws.acmeManager = acme.NewManager("http://127.0.0.1:1/dir", "test@example.com", certDir, nil)

	certPEM, keyPEM := mantisCASignedPair(t, "panel.example")
	certPath := filepath.Join(certDir, "panel.example.crt")
	keyPath := filepath.Join(certDir, "panel.example.key")
	mantisWritePair(t, certPath, keyPath, certPEM, keyPEM)

	// The settings record is configured exactly the way a daemon that already
	// holds a good certificate is: domain stored, paths pointing at the pair.
	ws.tlsSettings.Domain = "panel.example"
	ws.tlsSettings.CertPath = certPath
	ws.tlsSettings.KeyPath = keyPath

	body := `{"domain":"panel.example","email":"test@example.com","purpose":"panel"}`
	req := httptest.NewRequest(http.MethodPost, "/api/tls/issue", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ws.handleTLSSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handler returned %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Success bool   `json:"success"`
		Issuing bool   `json:"issuing"`
		Detail  string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if resp.Issuing {
		t.Errorf("F2 reproduced: saving a domain whose valid certificate is already the "+
			"configured pair started a new ACME issuance (detail %q). Let's Encrypt allows 5 "+
			"duplicate certificates per name per week, so repeated Saves exhaust the quota and "+
			"block a later real renewal.", resp.Detail)
	}
}

// TestMantisPanelResaveWithPairOnAcmeDirIsFree is the negative control: when
// the valid pair lives at the ACME directory rather than at the stored paths,
// the fast path DOES fire and no order is placed. This proves the defect is
// specifically the paths-already-equal case, not the whole purpose=panel flow.
func TestMantisPanelResaveWithPairOnAcmeDirIsFree(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	certDir := t.TempDir()
	ws.acmeManager = acme.NewManager("http://127.0.0.1:1/dir", "test@example.com", certDir, nil)

	certPEM, keyPEM := mantisCASignedPair(t, "panel.example")
	acmeCert := filepath.Join(certDir, "panel.example.crt")
	acmeKey := filepath.Join(certDir, "panel.example.key")
	mantisWritePair(t, acmeCert, acmeKey, certPEM, keyPEM)

	// Stored paths deliberately point somewhere else (an old pair for a
	// previous name), so the fast path's inequality condition is true.
	ws.tlsSettings.Domain = "panel.example"
	ws.tlsSettings.CertPath = filepath.Join(t.TempDir(), "old.crt")
	ws.tlsSettings.KeyPath = filepath.Join(t.TempDir(), "old.key")

	body := `{"domain":"panel.example","email":"test@example.com","purpose":"panel"}`
	req := httptest.NewRequest(http.MethodPost, "/api/tls/issue", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ws.handleTLSSettings(rec, req)

	var resp struct {
		Issuing bool   `json:"issuing"`
		Detail  string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if resp.Issuing {
		t.Errorf("negative control failed: the fast path should have applied the pair at the "+
			"ACME directory without issuing, but issuing=true (%q)", resp.Detail)
	}
}
