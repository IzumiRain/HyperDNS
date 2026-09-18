package web

// Mantis PoC: a live subscriber-portal rebind takes the running portal down
// before it tries the new port, and nothing puts it back.
//
// internal/web/server.go:1064-1071 shuts the existing subscriber listener down
// unconditionally, sets ws.subServer = nil, and only then attempts
// net.Listen for the new port. When that listen fails — the port is already
// held by any other process on the box, which the new port-collision guard in
// subscription.go does not and cannot detect — bindSubscriberListener returns
// an error and leaves ws.subServer nil. The caller in the live save path
// (internal/web/auth.go:798) logs the error and returns success to the
// operator, so the portal that was serving subscribers on the old port a
// moment ago is now dark, with no rollback to the working listener.
//
// The correct order is bind-new, then close-old, or restore the old listener
// when the new one cannot be had.

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// TestMantisRebindToTakenPortKillsTheRunningPortal is the F3 reproducer. A
// working portal is up on port A; the operator saves port B, which an
// unrelated listener already holds. After the save the portal must still be
// reachable on A (or the error must be one the handler surfaces and rolls
// back from). In the unfixed code it is gone.
func TestMantisRebindToTakenPortKillsTheRunningPortal(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetSubscriptionSettings(&database.SubscriptionSettings{})

	upPort := freePort(t)
	ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, Port: upPort, URIPath: "/sub", Title: "Live",
		UsePanelCertificate: false, // plaintext listener, no certs needed
	}, nil)
	if err := ws.bindSubscriberListener(context.Background(), false); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	defer ws.Stop()
	if !waitForListener(t, upPort) {
		t.Fatalf("the portal never came up on %d", upPort)
	}

	// A port held by a foreign listener — the situation the collision guard
	// cannot see, because nothing in this process owns it.
	takenPort := freePort(t)
	foreign, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(takenPort)))
	if err != nil {
		t.Fatalf("could not occupy the collision port: %v", err)
	}
	defer func() { _ = foreign.Close() }()

	ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, Port: takenPort, URIPath: "/sub", Title: "Moved",
		UsePanelCertificate: false,
	}, nil)
	rebindErr := ws.bindSubscriberListener(context.Background(), false)
	if rebindErr == nil {
		t.Fatal("the rebind to an occupied port unexpectedly succeeded")
	}

	// The save must not be a regression: the old listener is the one every
	// subscriber link in the field still points at.
	deadline := time.Now().Add(2 * time.Second)
	gone := true
	for time.Now().Before(deadline) {
		conn, derr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(upPort)), 150*time.Millisecond)
		if derr == nil {
			_ = conn.Close()
			gone = false
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if gone {
		t.Errorf("F3 reproduced: saving a port the box already had in use shut the working "+
			"subscriber portal down on %d and nothing restored it (rebind error: %v). Every link "+
			"the operator's subscribers already have now points at a closed socket, and the save "+
			"handler reported the failure without rolling back to the listener that worked.",
			upPort, rebindErr)
	}
}
