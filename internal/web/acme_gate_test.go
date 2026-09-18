package web

// Mantis PoC: the boot-path entry point StartACMEIfNeeded starts an issuance
// without taking the single-flight gate, so a Save arriving during boot
// observes a free gate and starts a second, concurrent run.
//
// internal/web/tls.go:657-678 StartACMEIfNeeded calls runEmbeddedACME
// directly, while every other caller goes through startACMEIssuance, which
// takes ws.acmeRunning with CompareAndSwap. The gate is therefore not held
// while the boot issuance is in flight, and internal/web/tls.go:382 also
// writes ws.acmeManager.ContactEmail without the manager's mutex while
// ensureClient reads it under that mutex at acme.go:411-412.
//
// Manager.Issue has an internal second gate that keeps the two runs from both
// placing an order, so the impact is a confused progress/status surface (the
// panel reports a failure for the run the boot path is performing) plus the
// unlocked ContactEmail write, rather than double quota spend.

import (
	"net"
	"strconv"
	"testing"
	"time"

	"hyperdns/internal/service/acme"
)

// TestMantisStartACMEIfNeededDoesNotHoldTheGate is the F7 reproducer. A
// hanging local ACME directory keeps the boot issuance inside Issue long
// enough to observe the gate state.
func TestMantisStartACMEIfNeededDoesNotHoldTheGate(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	// A directory server that accepts the connection and never answers, so
	// Issue blocks in account registration and never touches the network.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hang server: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			// Hold the connection open without writing anything.
			go func(c net.Conn) {
				buf := make([]byte, 64)
				for {
					if _, e := c.Read(buf); e != nil {
						return
					}
				}
			}(c)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	certDir := t.TempDir()
	ws.acmeManager = acme.NewManager("http://127.0.0.1:"+strconv.Itoa(addr.Port)+"/dir",
		"boot@example.com", certDir, nil)
	ws.tlsSettings.Domain = "panel.example"
	ws.tlsSettings.CertPath = ""
	ws.tlsSettings.KeyPath = ""

	// The boot path: no gate.
	go ws.StartACMEIfNeeded()

	// Wait until the boot issuance is genuinely inside the manager.
	deadline := time.Now().Add(5 * time.Second)
	running := false
	for time.Now().Before(deadline) {
		if ws.acmeManager.State().Running {
			running = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !running {
		t.Skip("the boot issuance did not reach Issue in time; PoC inconclusive")
	}

	// The single-flight gate must be held while an issuance is in flight. It
	// is not.
	if ws.acmeRunning.Load() {
		return // gate held: no defect under these conditions
	}

	// And the consequence is concrete: the panel's save path sees a free gate
	// and starts its own run for the same name.
	issuing, detail := ws.startACMEIssuance("panel.example", "panel@example.com", "panel")
	defer ws.acmeRunning.Store(false)
	if !issuing {
		t.Errorf("F7 partial: the gate was free while a boot issuance was in flight, but "+
			"startACMEIssuance still refused — detail: %s", detail)
		return
	}
	t.Errorf("F7 reproduced: StartACMEIfNeeded started an issuance for panel.example without "+
		"taking the single-flight gate (acmeRunning was false while Manager.State().Running was "+
		"true), and a concurrent Save then started a second run for the same name "+
		"(startACMEIssuance returned issuing=true, %q). The two runs race on "+
		"ws.acmeManager.ContactEmail, which runEmbeddedACME writes at tls.go:382 while "+
		"ensureClient reads it under the manager mutex.", detail)
}

// TestMantisBootAndSaveBothReachIssue is the benign-control half: the manager's
// own internal gate is what stops the second order, which bounds the severity
// of F7 to status confusion and the ContactEmail race rather than double
// quota spend.
func TestMantisBootAndSaveBothReachIssue(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hang server: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 64)
				for {
					if _, e := c.Read(buf); e != nil {
						return
					}
				}
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	ws.acmeManager = acme.NewManager("http://127.0.0.1:"+strconv.Itoa(addr.Port)+"/dir",
		"boot@example.com", t.TempDir(), nil)
	ws.tlsSettings.Domain = "panel.example"

	go ws.StartACMEIfNeeded()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ws.acmeManager.State().Running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The save path does take the gate; its run reaches Issue, which refuses.
	issuing, _ := ws.startACMEIssuance("panel.example", "panel@example.com", "panel")
	if issuing {
		defer ws.acmeRunning.Store(false)
	}
	if !issuing {
		t.Skip("the save path did not start a run; benign control inconclusive")
	}
	// Give the second runEmbeddedACME time to reach Issue and be refused.
	time.Sleep(300 * time.Millisecond)
	last, _ := ws.acmeManager.LastResult()
	if last == "" {
		t.Log("benign control: the second run is still blocked in the manager's internal " +
			"gate, which is what keeps F7 from becoming a double-order. The gate itself " +
			"remains unsynchronised with the panel's notion of what is running.")
	}

}
