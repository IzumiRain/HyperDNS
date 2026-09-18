package main

import (
	"errors"
	"fmt"
	"testing"

	"hyperdns/internal/control"
)

// The control plane is a Linux-only, root-local management transport by design:
// there is deliberately no TCP or unauthenticated Unix fallback. That is a
// correct security decision about the CONTROL SOCKET, and it was wrongly applied
// to the whole process — a non-Linux daemon refused to start at all:
//
//	[Main] Failed to start local control server: HyperDNS control server
//	       requires Linux Unix peer credentials
//
// The resolver, the SNI relay and the dashboard have nothing to do with that
// socket. Refusing to boot turns "this host cannot offer the `hdns` console"
// into "this host cannot run HyperDNS", which is a regression for every
// Windows/macOS/BSD install and for the cross-builds this repo ships. The
// invariant that must hold is narrower: never fall back to a weaker transport.
func TestControlStartupUnsupportedPlatformIsNotFatal(t *testing.T) {
	if controlStartupFatal(control.ErrUnsupported) {
		t.Fatal("an unsupported-platform control error stopped the daemon; the resolver must still start")
	}
	if controlStartupFatal(fmt.Errorf("start control: %w", control.ErrUnsupported)) {
		t.Fatal("a wrapped unsupported-platform error stopped the daemon")
	}
}

// Every other failure IS fatal: a bind refusal, a hostile runtime directory, a
// lock already held. Those mean the daemon cannot own the management surface on
// a host where it is supposed to, and starting anyway would leave an operator
// with a service whose console silently does not exist.
func TestControlStartupRealFailuresStayFatal(t *testing.T) {
	for _, err := range []error{
		errors.New("bind control socket: permission denied"),
		errors.New("control directory must be owned by root"),
		errors.New("lock control socket lifecycle: resource temporarily unavailable"),
		errors.New("control socket is already active"),
	} {
		if !controlStartupFatal(err) {
			t.Errorf("controlStartupFatal(%v) = false, want true", err)
		}
	}
}

// No error at all is not a failure.
func TestControlStartupNilIsNotFatal(t *testing.T) {
	if controlStartupFatal(nil) {
		t.Fatal("controlStartupFatal(nil) = true")
	}
}
