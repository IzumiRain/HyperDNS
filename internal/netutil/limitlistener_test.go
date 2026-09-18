package netutil

import (
	"net"
	"testing"
	"time"
)

// dialTo opens a client connection and registers its cleanup. The client side is
// never used for anything: what these tests care about is whether the listener
// hands the server side out at all.
func dialTo(t *testing.T, ln net.Listener) {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestLimitListenerStopsAcceptingAtTheCap(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	lim := LimitListener(base, 1)
	t.Cleanup(func() { _ = lim.Close() })

	dialTo(t, lim)
	first, err := lim.Accept()
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}

	dialTo(t, lim)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := lim.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	// The second connection is sitting in the kernel backlog: connected, as far
	// as the peer can tell, but never handed to a handler.
	select {
	case c := <-accepted:
		_ = c.Close()
		t.Fatal("accepted a second connection while the cap was full")
	case <-time.After(150 * time.Millisecond):
	}

	// Closing the accepted connection is what returns the slot — not closing the
	// client's end, which the server cannot see until it reads.
	_ = first.Close()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("closing the accepted connection did not free a slot")
	}
}

func TestLimitListenerCloseUnblocksAWaitingAccept(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	lim := LimitListener(base, 1)

	dialTo(t, lim)
	held, err := lim.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })

	failed := make(chan error, 1)
	go func() {
		_, err := lim.Accept()
		failed <- err
	}()

	// Without the done channel this Accept would still be waiting on a semaphore
	// nobody is going to release, and Shutdown would hang behind it.
	_ = lim.Close()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("expected the blocked Accept to fail once the listener closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock a waiting Accept")
	}
}

func TestLimitListenerToleratesADoubleClose(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	lim := LimitListener(base, 1)
	t.Cleanup(func() { _ = lim.Close() })

	dialTo(t, lim)
	conn, err := lim.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_ = conn.Close()
		_ = conn.Close() // net/http and miekg/dns both do this on error paths
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the second Close blocked on the semaphore")
	}

	// And the slot was returned exactly once, so the cap still admits one.
	dialTo(t, lim)
	next, err := lim.Accept()
	if err != nil {
		t.Fatalf("accept after double close: %v", err)
	}
	_ = next.Close()
}

func TestLimitListenerPassesThroughWhenUnbounded(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	for _, n := range []int{0, -1} {
		if got := LimitListener(base, n); got != base {
			t.Errorf("LimitListener(ln, %d) wrapped the listener; a nonsensical cap must not silently become a cap of its own", n)
		}
	}
	if LimitListener(nil, 10) != nil {
		t.Error("LimitListener(nil, 10) should stay nil rather than wrap nothing")
	}
}
