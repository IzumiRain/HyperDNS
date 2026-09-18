package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// selfSignedPEM produces a self-signed leaf certificate naming dnsName — the
// shape the daemon's own fallback generator emits, including the configured
// domain in the SAN. It is the material the Not-secure regression is about.
func selfSignedPEM(t *testing.T, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"HyperDNS Controller"}, CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// caSignedPEM produces a leaf signed by a freshly generated test CA — the
// shape a real Let's Encrypt deployment presents.
func caSignedPEM(t *testing.T, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	return caSignedPEMWithValidity(t, dnsName, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// caSignedPEMWithValidity is caSignedPEM with caller-chosen validity, so a test
// can present the exact stale material a failed renewal or an old backup leaves
// on disk: CA-signed (so it is not the self-signed fallback), correctly paired,
// and wrong only in its dates or its names.
func caSignedPEMWithValidity(t *testing.T, dnsName string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
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
		NotBefore:    notBefore,
		NotAfter:     notAfter,
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
}

// writePairFiles writes PEM material to disk and returns the two paths.
func writePairFiles(t *testing.T, dir, name string, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, name+".pem")
	keyPath := filepath.Join(dir, name+"-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write %s: %v", keyPath, err)
	}
	return certPath, keyPath
}

// TestLoadOrGenerateTLSConfigRefusesSelfSignedForDomain is the resolver-side
// half of the Not-secure fix. With a panel domain configured, the fallback
// self-signed pair must not be served on 8443 (DoH) or 853 (DoT) either: the
// old candidate loop accepted it because it parses and loads, and the daemon
// then answered DoT and DoH with a certificate every client refuses.
func TestLoadOrGenerateTLSConfigRefusesSelfSignedForDomain(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedPEM(t, "panel.example")
	certPath, keyPath := writePairFiles(t, dir, "cert", certPEM, keyPEM)

	cfg := &database.TLSSettings{
		Domain:   "panel.example",
		CertPath: certPath,
		KeyPath:  keyPath,
	}
	tlsCfg, err := LoadOrGenerateTLSConfig(cfg)
	if err == nil {
		t.Fatal("LoadOrGenerateTLSConfig served a self-signed pair for a configured domain")
	}
	if tlsCfg != nil {
		t.Error("a config was returned alongside the refusal; callers would serve it")
	}
}

// TestLoadOrGenerateTLSConfigAcceptsCASignedForDomain: the positive half — a
// CA-signed pair for the configured domain is loaded and returned.
func TestLoadOrGenerateTLSConfigAcceptsCASignedForDomain(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := caSignedPEM(t, "panel.example")
	certPath, keyPath := writePairFiles(t, dir, "cert", certPEM, keyPEM)

	cfg := &database.TLSSettings{
		Domain:   "panel.example",
		CertPath: certPath,
		KeyPath:  keyPath,
	}
	tlsCfg, err := LoadOrGenerateTLSConfig(cfg)
	if err != nil {
		t.Fatalf("LoadOrGenerateTLSConfig refused a CA-signed pair: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(tlsCfg.Certificates))
	}
}

// TestLoadOrGenerateTLSConfigRefusesExpiredCASignedForDomain is the resolver-side
// half of the expiry defect: a CA-signed pair whose NotAfter is in the past
// loads, pairs and is not self-signed, so the old loop served it on 853/8443 —
// and every TLS client refused, taking DoT and DoH dark with no error logged.
// The pair on disk is exactly what a silently failed renewal leaves behind.
func TestLoadOrGenerateTLSConfigRefusesExpiredCASignedForDomain(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := caSignedPEMWithValidity(t, "panel.example",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	certPath, keyPath := writePairFiles(t, dir, "expired", certPEM, keyPEM)

	cfg := &database.TLSSettings{
		Domain:   "panel.example",
		CertPath: certPath,
		KeyPath:  keyPath,
	}
	tlsCfg, err := LoadOrGenerateTLSConfig(cfg)
	if err == nil {
		t.Fatal("LoadOrGenerateTLSConfig served an EXPIRED CA-signed certificate for panel.example")
	}
	if tlsCfg != nil {
		t.Error("a config was returned alongside the refusal; callers would serve it")
	}
}

// TestLoadOrGenerateTLSConfigRefusesWrongHostCASignedForDomain: a date-valid
// CA-signed pair naming some other host is not the configured domain's
// certificate, and serving it on the encrypted DNS ports presents subscribers
// with a name their resolver did not ask for.
func TestLoadOrGenerateTLSConfigRefusesWrongHostCASignedForDomain(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := caSignedPEM(t, "attacker.example")
	certPath, keyPath := writePairFiles(t, dir, "wronghost", certPEM, keyPEM)

	cfg := &database.TLSSettings{
		Domain:   "panel.example",
		CertPath: certPath,
		KeyPath:  keyPath,
	}
	tlsCfg, err := LoadOrGenerateTLSConfig(cfg)
	if err == nil {
		t.Fatal("LoadOrGenerateTLSConfig served a CA-signed certificate for attacker.example while the configured domain is panel.example")
	}
	if tlsCfg != nil {
		t.Error("a config was returned alongside the refusal; callers would serve it")
	}
}

// TestLoadOrGenerateTLSConfigRefusesNotYetValidCASignedForDomain covers the
// other edge of the date window: a pair whose NotBefore is still in the future.
func TestLoadOrGenerateTLSConfigRefusesNotYetValidCASignedForDomain(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := caSignedPEMWithValidity(t, "panel.example",
		time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	certPath, keyPath := writePairFiles(t, dir, "future", certPEM, keyPEM)

	cfg := &database.TLSSettings{
		Domain:   "panel.example",
		CertPath: certPath,
		KeyPath:  keyPath,
	}
	tlsCfg, err := LoadOrGenerateTLSConfig(cfg)
	if err == nil {
		t.Fatal("LoadOrGenerateTLSConfig served a CA-signed certificate that is not valid yet")
	}
	if tlsCfg != nil {
		t.Error("a config was returned alongside the refusal; callers would serve it")
	}
}

// TestLoadOrGenerateTLSConfigFallsThroughToNextCandidate: one bad candidate must
// not poison the loop — an expired pair at the first candidate path is skipped
// and a good pair at the next one is loaded. This is the ACME-path behaviour:
// /etc/letsencrypt can hold a stale pair while the configured cert_path points
// at the live one.
func TestLoadOrGenerateTLSConfigFallsThroughToNextCandidate(t *testing.T) {
	dir := t.TempDir()
	expiredPEM, expiredKey := caSignedPEMWithValidity(t, "panel.example",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	letsEncryptDir := filepath.Join(dir, "letsencrypt", "live", "panel.example")
	if err := os.MkdirAll(letsEncryptDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(letsEncryptDir, "fullchain.pem"), expiredPEM, 0o600); err != nil {
		t.Fatalf("write fullchain: %v", err)
	}
	if err := os.WriteFile(filepath.Join(letsEncryptDir, "privkey.pem"), expiredKey, 0o600); err != nil {
		t.Fatalf("write privkey: %v", err)
	}

	goodPEM, goodKey := caSignedPEM(t, "panel.example")
	goodCert, goodKeyPath := writePairFiles(t, dir, "good", goodPEM, goodKey)

	cfg := &database.TLSSettings{
		Domain:   "panel.example",
		CertPath: goodCert,
		KeyPath:  goodKeyPath,
	}
	tlsCfg, err := LoadOrGenerateTLSConfig(cfg)
	if err != nil {
		t.Fatalf("LoadOrGenerateTLSConfig refused the valid pair after skipping the expired one: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(tlsCfg.Certificates))
	}
}

// TestLoadOrGenerateTLSConfigWithoutDomainFallsBack: with no panel domain the
// self-signed fallback is the documented behaviour (SSH-tunnel deployments)
// and must keep working — generate, persist, and return a config. The function
// writes certs/cert.pem relative to the working directory when /opt/hyperdns
// does not exist, so the test chdirs into a temp dir to keep the repository
// tree untouched.
func TestLoadOrGenerateTLSConfigWithoutDomainFallsBack(t *testing.T) {
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	tlsCfg, err := LoadOrGenerateTLSConfig(&database.TLSSettings{})
	if err != nil {
		t.Fatalf("LoadOrGenerateTLSConfig with no domain: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(tlsCfg.Certificates))
	}
	for _, p := range []string{"certs/cert.pem", "certs/key.pem"} {
		if _, err := os.Stat(filepath.Join(tmp, p)); err != nil {
			t.Errorf("fallback material %s was not written: %v", p, err)
		}
	}
}
