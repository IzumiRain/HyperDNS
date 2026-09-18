package web

// Integration tests for the HTTPS panel listener added in v2.1.
//
// These are the only tests in the package that call ws.Start rather than
// BuildHandler. They stand up a real listener on an ephemeral port and perform a
// real TLS handshake, which is what the Phase 1 exit gate demands: prove a valid
// handshake, prove HTTP redirects to HTTPS, prove a bad certificate fails closed,
// and prove no panel response is served over plaintext.
//
// The certificate helpers writeTestCertificatePair / writeTestCertificatePairFor
// are shared with the validator tests in security_test.go, so these tests reuse
// the same self-signed test material.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// tlsPanelConfig carries the TLS switchboard settings an integration test needs
// to stand the panel up on a real port. A RedirectPort of 0 leaves the redirect
// listener unbound.
type tlsPanelConfig struct {
	domain       string
	certPath     string
	keyPath      string
	panelHTTPS   bool
	redirectPort int
}

// startTLSPanel builds a web server wired for the given TLS configuration, picks
// free ports for the panel and (when requested) redirect listeners, and returns
// the server, the two chosen ports, and a cleanup that stops every background
// goroutine. It does not call Start: a test that expects Start to refuse a bad
// certificate must be handed its error, not have it swallowed.
func startTLSPanel(t *testing.T, cfg tlsPanelConfig) (*WebServer, int, int, func()) {
	t.Helper()
	ws, _, backendCleanup := setupTestWebServer(t)

	webPort := freePort(t)
	ws.settings.WebPort = webPort

	redirPort := 0
	if cfg.redirectPort != 0 {
		redirPort = freePort(t)
	}
	ws.tlsSettings = &database.TLSSettings{
		Domain:       cfg.domain,
		CertPath:     cfg.certPath,
		KeyPath:      cfg.keyPath,
		PanelHTTPS:   cfg.panelHTTPS,
		RedirectPort: redirPort,
	}

	cleanup := func() {
		ws.Stop()
		backendCleanup()
	}
	return ws, webPort, redirPort, cleanup
}

// freePort reserves an ephemeral TCP port on the loopback interface and returns
// it. The probe listener is closed before the caller binds it, so there is a
// tiny window in which another process could take the number, but for a test
// that binds immediately and is the only listener on loopback it is negligible.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestTLSPanelServesAValidHandshake proves the core of the panel HTTPS path: the
// listener presents a certificate the client trusts, the hostname verifies, and
// the response that comes back over that channel is a real dashboard response
// carrying HSTS.
func TestTLSPanelServesAValidHandshake(t *testing.T) {
	domain := "panel.example"
	certPath, keyPath, caPath := writeTestChainPair(t, domain)

	ws, port, _, cleanup := startTLSPanel(t, tlsPanelConfig{
		domain:     domain,
		certPath:   certPath,
		keyPath:    keyPath,
		panelHTTPS: true,
	})
	defer cleanup()

	if err := ws.Start(); err != nil {
		t.Fatalf("Start with a valid certificate returned an error: %v", err)
	}

	// Trust the test CA and verify the hostname, so this is a genuine
	// handshake — the client checks the presented certificate chains to a root
	// it trusts, names the domain, and is currently usable, not merely that TLS
	// bytes flowed.
	pool := x509.NewCertPool()
	certPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA certificate: %v", err)
	}
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("the test CA was not appended to the root pool")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: domain},
		},
		Timeout: 5 * time.Second,
	}
	// The dashboard lives below the generated admin path since v2.1 Phase 3, so
	// the handshake test requests the real login-page mount, not a retired root
	// route.
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/%s/dash/home", port, ws.AdminPath()))
	if err != nil {
		t.Fatalf("TLS request to the panel failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("dashboard over TLS returned status %d, want 200", resp.StatusCode)
	}
	// The panel was reached over TLS, so HSTS must be present; a panel that serves
	// the dashboard over HTTPS without it defeats the point of the listener.
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts == "" {
		t.Error("HTTPS panel response carries no Strict-Transport-Security header")
	}
}

// TestHTTPRedirectListenerRedirectsToHTTPS proves the HTTP-to-HTTPS migration
// path: a safe request bounces to the HTTPS panel, preserving path and query,
// and a non-safe method is refused rather than silently collapsed into a GET.
func TestHTTPRedirectListenerRedirectsToHTTPS(t *testing.T) {
	domain := "panel.example"
	certPath, keyPath, _ := writeTestChainPair(t, domain)

	ws, port, redirPort, cleanup := startTLSPanel(t, tlsPanelConfig{
		domain:       domain,
		certPath:     certPath,
		keyPath:      keyPath,
		panelHTTPS:   true,
		redirectPort: 1, // any non-zero value selects a free port
	})
	defer cleanup()
	if err := ws.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/some/path?x=1", redirPort))
	if err != nil {
		t.Fatalf("GET to the redirect listener failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("GET to the redirect listener returned %d, want 307", resp.StatusCode)
	}
	want := fmt.Sprintf("https://%s:%d/some/path?x=1", domain, port)
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	// A non-safe method must not be redirected into a GET that loses its body and
	// semantics.
	resp, err = client.Post(fmt.Sprintf("http://127.0.0.1:%d/", redirPort), "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("POST to the redirect listener failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST to the redirect listener returned %d, want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("POST Allow = %q, want %q", allow, "GET, HEAD")
	}
}

// TestTLSPanelRefusesACertificateForTheWrongDomain: HTTPS is required, so a
// certificate that does not name the configured domain must stop the panel from
// starting rather than serve one no browser will accept.
func TestTLSPanelRefusesACertificateForTheWrongDomain(t *testing.T) {
	// A perfectly usable pair, but for a different name.
	certPath, keyPath := writeTestCertificatePair(t, "other.example")

	ws, _, _, cleanup := startTLSPanel(t, tlsPanelConfig{
		domain:     "panel.example",
		certPath:   certPath,
		keyPath:    keyPath,
		panelHTTPS: true,
	})
	defer cleanup()

	err := ws.Start()
	if err == nil {
		t.Fatal("Start accepted a certificate that does not cover the configured domain; HTTPS must fail closed")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("the failure should name the certificate so an operator can act on it, got: %v", err)
	}
}

// TestTLSPanelRefusesAnExpiredCertificate: a certificate past its NotAfter is
// unservable, and the panel must not come up with it.
func TestTLSPanelRefusesAnExpiredCertificate(t *testing.T) {
	certPath, keyPath := writeTestCertificatePairFor(t, "panel.example", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	ws, _, _, cleanup := startTLSPanel(t, tlsPanelConfig{
		domain:     "panel.example",
		certPath:   certPath,
		keyPath:    keyPath,
		panelHTTPS: true,
	})
	defer cleanup()

	if err := ws.Start(); err == nil {
		t.Fatal("Start accepted an expired certificate; HTTPS must fail closed")
	}
}

// TestTLSPanelRefusesASelfSignedFallback is the regression test for the field
// failure behind the "Not secure" banner: the fallback generator names the
// configured domain in its SAN, so the old date-and-hostname-only check saw
// the self-signed pair as usable and the daemon served it — every browser then
// showed Not secure on a domain install. A self-signed certificate must now
// stop the panel exactly like a wrong-domain or expired one.
func TestTLSPanelRefusesASelfSignedFallback(t *testing.T) {
	// A perfectly date-valid, hostname-matching pair — but self-signed.
	certPath, keyPath := writeTestCertificatePair(t, "panel.example")

	ws, _, _, cleanup := startTLSPanel(t, tlsPanelConfig{
		domain:     "panel.example",
		certPath:   certPath,
		keyPath:    keyPath,
		panelHTTPS: true,
	})
	defer cleanup()

	err := ws.Start()
	if err == nil {
		t.Fatal("Start accepted a self-signed certificate for a configured domain; the panel would have shown Not secure")
	}
	if !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("the failure should name the self-signed condition so an operator can act on it, got: %v", err)
	}
}

// TestTLSPanelStartsOnASelfSignedPairWithoutADomain: the self-signed rejection
// is scoped to a configured domain. A no-domain install is an SSH-tunnel
// deployment by contract, where a hand-trusted self-signed pair is the
// documented way to carry TLS, and Start must still succeed there.
func TestTLSPanelStartsOnASelfSignedPairWithoutADomain(t *testing.T) {
	certPath, keyPath := writeTestCertificatePair(t, "panel.example")

	ws, _, _, cleanup := startTLSPanel(t, tlsPanelConfig{
		domain:     "",
		certPath:   certPath,
		keyPath:    keyPath,
		panelHTTPS: true,
	})
	defer cleanup()

	if err := ws.Start(); err != nil {
		t.Fatalf("Start refused a self-signed pair on a no-domain install: %v", err)
	}
}

// TestTLSPanelDoesNotAnswerPlaintext: with the panel listener in TLS mode, a
// plaintext HTTP request must not be answered with a panel response. The request
// fails, and it fails for the right reason — a TLS/plaintext mismatch — not a
// dial failure that would just mean the server was not up.
func TestTLSPanelDoesNotAnswerPlaintext(t *testing.T) {
	certPath, keyPath, _ := writeTestChainPair(t, "panel.example")

	ws, port, _, cleanup := startTLSPanel(t, tlsPanelConfig{
		domain:     "panel.example",
		certPath:   certPath,
		keyPath:    keyPath,
		panelHTTPS: true,
	})
	defer cleanup()
	if err := ws.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/dashboard", port))
	if err != nil {
		// A connection error is acceptable — the panel is refusing plaintext. The
		// only wrong failure is one that means the server was never listening.
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "timeout") {
			t.Fatalf("the plaintext request failed for the wrong reason: %v", err)
		}
		return
	}
	defer resp.Body.Close()
	// Go's http.Server detects an HTTP request aimed at a TLS listener and answers
	// it with a plaintext 400 ("client sent an HTTP request to an HTTPS server").
	// That response is generated by net/http, not by the panel, so it carries no
	// panel content — but it must never be a 200, which would mean the dashboard
	// was served in the clear.
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("the panel answered over plaintext HTTP (200, body %q); an HTTPS panel must not serve its content in the clear", body)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("plaintext request returned status %d, want 400", resp.StatusCode)
	}
}
