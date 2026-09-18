package web

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdns/internal/database"
	"hyperdns/internal/service/acme"
)

// The dedicated subscriber listener exists because the Subscription Portal's
// port field used to change only the text of the links it generated: an
// operator who set a portal port published a URL nothing was listening on. The
// tests below pin the two halves of the fix — that a saved port is actually
// bound, and that a rebind does not leak the socket it replaces.

// waitForListener polls until something accepts on the port, or the deadline
// passes. bindSubscriberListener serves from a goroutine, so the socket is
// listening by the time it returns but the accept loop may not be running yet.
func waitForListener(t *testing.T, port int) bool {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func TestSubscriberListenerBindsTheConfiguredPort(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetSubscriptionSettings(&database.SubscriptionSettings{})

	port := freePort(t)
	if err := ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, Port: port, URIPath: "/sub", Title: "Listener Test",
		UsePanelCertificate: true,
	}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := ws.bindSubscriberListener(context.Background(), false); err != nil {
		t.Fatalf("bindSubscriberListener: %v", err)
	}
	defer ws.Stop()

	if !waitForListener(t, port) {
		t.Fatalf("nothing is accepting on port %d — the port field would put a dead "+
			"URL in every subscriber link, which is the bug this listener fixes", port)
	}
}

// A rebind is a move, not a second listener: the old socket has to be released
// or the new bind races a port this same process still holds.
func TestSubscriberListenerRebindsOnPortChange(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetSubscriptionSettings(&database.SubscriptionSettings{})

	first, second := freePort(t), freePort(t)
	for i := 0; i < 40 && first == second; i++ {
		second = freePort(t)
	}
	if first == second {
		t.Skip("could not reserve two distinct ports")
	}

	ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, Port: first, URIPath: "/sub", Title: "First",
		UsePanelCertificate: true,
	}, nil)
	if err := ws.bindSubscriberListener(context.Background(), false); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if !waitForListener(t, first) {
		t.Fatalf("first listener never came up on %d", first)
	}

	ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, Port: second, URIPath: "/sub", Title: "Second",
		UsePanelCertificate: true,
	}, nil)
	if err := ws.bindSubscriberListener(context.Background(), false); err != nil {
		t.Fatalf("rebind to %d: %v — the old listener was not released", second, err)
	}
	defer ws.Stop()

	if !waitForListener(t, second) {
		t.Fatalf("the rebind reported success but nothing accepts on %d", second)
	}

	// The old port must be free. A listener left behind would keep answering
	// links the operator has already replaced.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(first)), 150*time.Millisecond)
		if err != nil {
			return // released, which is what we want
		}
		_ = conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("the old listener on port %d is still accepting after the rebind", first)
}

// Disabling the portal, or naming the panel's own port, must leave no
// dedicated listener behind.
func TestSubscriberListenerNotBoundWhenDisabledOrSamePort(t *testing.T) {
	cases := []struct {
		name     string
		snapshot database.SubscriptionSnapshot
	}{
		{"disabled", database.SubscriptionSnapshot{Enabled: false, Port: 0}},
		{"no port", database.SubscriptionSnapshot{Enabled: true, Port: 0}},
		// The panel's own port is already served by the panel listener; a second
		// bind there would fail the start for no gain.
		{"same as the panel", database.SubscriptionSnapshot{Enabled: true, Port: 8080}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws, _, cleanup := setupTestWebServer(t)
			defer cleanup()
			ws.subSettings.Apply(tc.snapshot, nil)
			if err := ws.bindSubscriberListener(context.Background(), false); err != nil {
				t.Fatalf("bindSubscriberListener: %v", err)
			}
			if ws.subServer != nil {
				t.Error("a dedicated subscriber listener was created for a record that " +
					"does not ask for one; the panel already serves those routes")
			}
		})
	}
}

// The endpoint the operator actually presses must report a port conflict rather
// than swallowing it: the save is persisted, so the honest answer is the error,
// and the card shows it.
func TestSubscriberListenerConflictIsReported(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetSubscriptionSettings(&database.SubscriptionSettings{})

	// Hold a port for the duration so binary binding it is guaranteed to fail.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blocker listen: %v", err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port

	if err := ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, Port: port, URIPath: "/sub", UsePanelCertificate: true,
	}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	err = ws.bindSubscriberListener(context.Background(), false)
	if err == nil {
		t.Fatal("binding an occupied port reported success — the operator would be told " +
			"the portal moved while nothing was listening on it")
	}
	if ws.subServer != nil {
		t.Error("a server was recorded despite the bind failing")
	}
}

// Panel and subscriber schemes must agree: the links are built from one flag
// and the listeners from the other, and a mismatch hands the subscriber a URL
// whose handshake fails.
func TestSubscriberTLSFollowsThePanelScheme(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetSubscriptionSettings(&database.SubscriptionSettings{})
	if err := ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", UsePanelCertificate: true,
	}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	ws.tlsSettings.PanelHTTPS = false
	if _, err := ws.subscriberTLSConfig(); err != nil {
		t.Fatalf("plain-HTTP panel must yield a plain-HTTP portal: %v", err)
	}

	// A domain forces HTTPS on the panel (see Start), so the portal follows and
	// now needs a certificate it does not have — which is an error, not a
	// silent fall back to the panel's cert for a name it does not cover.
	ws.tlsSettings.Domain = "portal.example"
	if _, err := ws.subscriberTLSConfig(); err == nil {
		t.Error("an HTTPS panel with no certificate produced a plain portal config; the " +
			"subscriber link says https and the handshake would fail")
	}
}

// A record that names a distinct subscription domain is HTTPS on its own
// terms, served by the ACME pair for that name — even when the panel itself
// is plain HTTP (the all-IP loopback deployment is exactly that). This was a
// real bug twice over: the panel's scheme used to win, and the field report
// had the listener serving the OLD domain's certificate after a domain
// change. v2.2.0 semantics: the pair is located from the live domain under
// the ACME directory, so the certificate always matches the name in the
// links. The test writes the pair where the ACME client would have.
func TestSubscriberOwnCertificateIsHTTPSOnAnHTTPPanel(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetSubscriptionSettings(&database.SubscriptionSettings{})
	ws.tlsSettings.PanelHTTPS = false
	// An isolated CertDir: the default acmeDir() is relative to the working
	// directory, and a leaked pair there would make every later test in the
	// package believe a certificate exists.
	ws.SetACMEManager(acme.NewManager("", "", filepath.Join(t.TempDir(), "acme"), nil))

	certPath, keyPath, _ := writeTestChainPair(t, "sub.example")
	acmeDir := ws.acmeDir()
	if err := os.MkdirAll(acmeDir, 0o700); err != nil {
		t.Fatalf("mkdir acme dir: %v", err)
	}
	acmeCert := filepath.Join(acmeDir, "sub.example.crt")
	acmeKey := filepath.Join(acmeDir, "sub.example.key")
	if err := os.Rename(certPath, acmeCert); err != nil {
		t.Fatalf("move cert: %v", err)
	}
	if err := os.Rename(keyPath, acmeKey); err != nil {
		t.Fatalf("move key: %v", err)
	}

	if err := ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", Domain: "sub.example",
		Port: 18443,
	}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !ws.subscriberHTTPS() {
		t.Error("a distinct subscription domain reports a plain-HTTP surface")
	}
	cfg, err := ws.subscriberTLSConfig()
	if err != nil {
		t.Fatalf("subscriberTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("a distinct subscription domain produced no TLS config — the " +
			"listener would speak plain HTTP while the links say https")
	}
	if origin := ws.subscriptionOrigin(); !strings.HasPrefix(origin, "https://sub.example:18443") {
		t.Errorf("subscriptionOrigin = %q, want an https origin naming the record's domain and port", origin)
	}
}

// The field-report bug, pinned: the domain changed from X (which had a cert)
// to Y (which had none), and the listener kept serving X's certificate for
// Y's name — "Not Secure" in every browser. v2.2.0 refuses instead: a
// distinct domain with no ACME pair under certs/acme is a hard error, never
// a fall back to the panel's or any other cached certificate.
func TestSubscriberDomainChangeRefusesWithoutTheNewPairsCert(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetSubscriptionSettings(&database.SubscriptionSettings{})
	ws.tlsSettings.PanelHTTPS = true
	ws.SetACMEManager(acme.NewManager("", "", filepath.Join(t.TempDir(), "acme"), nil))

	// X had a valid pair; the record rides it.
	acmeDir := ws.acmeDir()
	if err := os.MkdirAll(acmeDir, 0o700); err != nil {
		t.Fatalf("mkdir acme dir: %v", err)
	}
	certPath, keyPath, _ := writeTestChainPair(t, "x.example")
	if err := os.Rename(certPath, filepath.Join(acmeDir, "x.example.crt")); err != nil {
		t.Fatalf("move cert: %v", err)
	}
	if err := os.Rename(keyPath, filepath.Join(acmeDir, "x.example.key")); err != nil {
		t.Fatalf("move key: %v", err)
	}
	if err := ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", Domain: "x.example", Port: 18443,
	}, nil); err != nil {
		t.Fatalf("Apply X: %v", err)
	}
	if _, err := ws.subscriberTLSConfig(); err != nil {
		t.Fatalf("X's own pair must serve: %v", err)
	}

	// The operator switches the domain to Y without issuing a certificate.
	// The old record shape (manual paths pointing at X) is what the legacy
	// save produced; the new listener must not honor it for Y.
	if err := ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", Domain: "y.example", Port: 18443,
		UsePanelCertificate: false,
		CertPath:            filepath.Join(acmeDir, "x.example.crt"),
		KeyPath:             filepath.Join(acmeDir, "x.example.key"),
	}, nil); err != nil {
		t.Fatalf("Apply Y: %v", err)
	}
	if _, err := ws.subscriberTLSConfig(); err == nil {
		t.Fatal("a domain change to a name with no certificate produced a TLS config — " +
			"the listener would serve X's certificate for Y's name, the exact 'Not Secure' report")
	}
}
