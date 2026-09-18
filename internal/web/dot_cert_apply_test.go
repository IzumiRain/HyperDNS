package web

// Regression tests for the Mantis v2.2.0 findings A-1 and A-2 (DoT/DoH
// dedicated-certificate lifecycle).
//
// A-1: the first issuance for the DoH/DoT purpose had to take effect live.
// The old code read a `dotModeFlip` flag nothing ever set, so a fresh install
// whose boot found no valid pair left dotCertHolder nil, and the first
// successful issuance persisted the domain, skipped the nil holder, skipped
// the rebind, and logged that the listeners served the new certificate while
// they kept serving the panel's.
//
// A-2: clearing the domain had to detach the dedicated source. The old code
// rebinded without clearing the source, so the rebuilt listeners kept serving
// the old pair while the record and the log claimed the panel certificate
// applied.

import (
	"testing"
	"time"

	"hyperdns/internal/database"
)

// newDotHarness builds a test web server wired the way main wires a fresh
// install: no valid pair at boot, so the holder is nil and the rebind hook
// records what it is handed. The returned capture lets a test assert both the
// source installed and, via the slice, how many rebinds happened.
func newDotHarness(t *testing.T) (*WebServer, *[]*certHolder) {
	t.Helper()
	ws, _, cleanup := setupTestWebServer(t)
	t.Cleanup(cleanup)
	ws.tlsSettings = &database.TLSSettings{}
	var installed []*certHolder
	ws.SetDOTCertHolder(nil, func(src *certHolder) error {
		installed = append(installed, src)
		return nil
	})
	return ws, &installed
}

func TestDotFirstIssuanceConstructsHolderAndRebinds(t *testing.T) {
	ws, installed := newDotHarness(t)
	certPath, keyPath := newDotCertPair(t, "dot.example.com")

	if problem := ws.applyIssuedPurpose("dot.example.com", "dot", certPath, keyPath); problem != "" {
		t.Fatalf("first dot apply reported a problem: %s", problem)
	}
	if ws.dotCertHolder == nil {
		t.Fatal("first dot apply left dotCertHolder nil — the certificate would not go live until a restart (Mantis A-1)")
	}
	if len(*installed) != 1 || (*installed)[0] == nil {
		t.Fatalf("rebind hook was not invoked with the new holder: %d calls", len(*installed))
	}
}

func TestDotClearDetachesHolderAndSource(t *testing.T) {
	ws, installed := newDotHarness(t)
	certPath, keyPath := newDotCertPair(t, "dot.example.com")

	if problem := ws.applyIssuedPurpose("dot.example.com", "dot", certPath, keyPath); problem != "" {
		t.Fatalf("first dot apply reported a problem: %s", problem)
	}
	if problem := ws.applyIssuedPurpose("", "dot", "", ""); problem != "" {
		t.Fatalf("clear reported a problem: %s", problem)
	}
	if ws.dotCertHolder != nil {
		t.Fatal("clear left dotCertHolder set — a later issuance would hot-swap a holder the listeners no longer carry (Mantis A-2)")
	}
	if len(*installed) != 2 {
		t.Fatalf("expected two rebind calls (install + detach), got %d", len(*installed))
	}
	if last := (*installed)[1]; last != nil {
		t.Fatal("the clear rebind must install nil so the listeners fall back to the panel certificate")
	}
}

func TestDotRenewalHotSwapsWithoutRebind(t *testing.T) {
	ws, installed := newDotHarness(t)
	certPath, keyPath := newDotCertPair(t, "dot.example.com")

	if problem := ws.applyIssuedPurpose("dot.example.com", "dot", certPath, keyPath); problem != "" {
		t.Fatalf("first dot apply reported a problem: %s", problem)
	}
	if problem := ws.applyIssuedPurpose("dot.example.com", "dot", certPath, keyPath); problem != "" {
		t.Fatalf("renewal reported a problem: %s", problem)
	}
	// The renewal rides the holder's closure — exactly one rebind (the
	// original install), no listener rebuild for a same-name re-issue.
	if len(*installed) != 1 {
		t.Fatalf("renewal must not rebind the listeners, got %d rebind calls", len(*installed))
	}
}

func newDotCertPair(t *testing.T, domain string) (string, string) {
	t.Helper()
	return writeTestCertificatePairFor(t, domain, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}
