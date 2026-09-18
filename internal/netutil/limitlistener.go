package netutil

import (
	"net"
	"sync"
)

// LimitListener bounds how many accepted connections may be open at once.
//
// This exists as the counterweight to keeping connections alive. A DoT client
// pays a TLS handshake — two round trips plus certificate verification and a key
// exchange — before it can ask anything, so closing its connection after eight
// idle seconds means a phone that queries every ten seconds re-handshakes for
// every single name it looks up. Raising the idle timeout removes that cost, and
// in exchange lets a hostile peer hold a connection open far longer than before;
// without a cap the daemon's memory becomes a function of how many sockets
// somebody feels like opening.
//
// When the cap is reached the wrapped Accept simply stops accepting, so further
// connections wait in the kernel's listen backlog and are refused by the OS once
// that fills. That is deliberately different from accepting and immediately
// closing: on the DoT listener, accepting first means completing the TLS
// handshake — the most expensive thing the daemon does — only to say no, which
// turns the cap itself into the cheapest way to burn the server's CPU. Making the
// peer time out its connect attempt costs this process nothing, and every
// subscriber already connected keeps being served.
func LimitListener(l net.Listener, n int) net.Listener {
	if l == nil || n <= 0 {
		return l
	}
	return &limitListener{
		Listener: l,
		sem:      make(chan struct{}, n),
		done:     make(chan struct{}),
	}
}

type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// acquire takes a slot, or reports false once the listener has been closed.
// Without the done channel a blocked Accept would keep waiting on a semaphore
// nobody will ever release, and Shutdown would hang instead of returning.
func (l *limitListener) acquire() bool {
	select {
	case <-l.done:
		return false
	case l.sem <- struct{}{}:
		return true
	}
}

func (l *limitListener) release() { <-l.sem }

func (l *limitListener) Accept() (net.Conn, error) {
	acquired := l.acquire()
	// Call through even when the slot was not acquired: the listener is closed,
	// so this returns the error that ends the accept loop rather than blocking.
	conn, err := l.Listener.Accept()
	if err != nil {
		if acquired {
			l.release()
		}
		return nil, err
	}
	return &limitListenerConn{Conn: conn, release: l.release}, nil
}

func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

// limitListenerConn returns its slot when closed. releaseOnce matters because
// both net/http and miekg/dns can call Close on the same connection more than
// once on the error paths, and release is a receive from the semaphore: a second
// one for the same slot would block until some later connection happened to take
// a slot, hanging that goroutine inside Close for as long as the listener stayed
// quiet.
type limitListenerConn struct {
	net.Conn
	release     func()
	releaseOnce sync.Once
}

func (c *limitListenerConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}
