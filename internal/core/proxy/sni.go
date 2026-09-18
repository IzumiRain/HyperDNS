package proxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"hyperdns/internal/database"
)

const (
	// handshakeBufSize holds the opening TLS record or HTTP request line. A
	// ClientHello carrying post-quantum key shares runs past 2 KiB, and it may
	// arrive split across TCP segments, so the buffer covers a full TLS record
	// and the read below loops until the record is complete.
	handshakeBufSize = 16 * 1024
	relayBufSize     = 32 * 1024

	// maxConcurrentRelays caps how many relays run at once. Each one holds two
	// sockets, two goroutines and a relay buffer, and nothing in the protocol
	// stops a client from opening connections until the host runs out of file
	// descriptors.
	maxConcurrentRelays = 4096

	// handshakeTimeout bounds how long a connection may sit without producing a
	// parseable ClientHello or Host header.
	handshakeTimeout = 5 * time.Second

	// defaultIdleTimeout applies when settings.Timeout is unset, so a relay is
	// never left without a deadline.
	defaultIdleTimeout = 120 * time.Second

	// meterFlushBytes is how much one direction of a relay accumulates before it
	// reports usage. Accounting only at close would leave a long-lived stream
	// invisible until it ended, so a quota could be overshot by however much a
	// single connection managed to carry.
	meterFlushBytes = 1 << 20

	// unreadableLogSample is how often a connection that named no destination is
	// logged. One line per connection would let a port scanner — or a load
	// balancer's TCP health check, which connects and says nothing — fill the log,
	// so the event is sampled instead of dropped or reported in full.
	unreadableLogSample = 64
)

var (
	handshakeBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, handshakeBufSize)
			return &b
		},
	}
	relayBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, relayBufSize)
			return &b
		},
	}
)

type AccessValidator interface {
	IsIPAllowed(ip string) (*database.Client, bool)
	IsAllowAll() bool
}

// TrafficMeter accounts relayed bytes against a client and reports whether that
// client has spent its allowance. It is optional: NewServer asks the access
// validator for it by type assertion, so a validator that only knows about IP
// checks keeps compiling and simply meters nothing.
type TrafficMeter interface {
	AddTraffic(clientID string, n uint64)
	QuotaExceeded(c *database.Client) bool
}

// ChallengeResponder answers an ACME HTTP-01 challenge on the proxy's plain
// HTTP port. SetChallengeResponder wires it (nil on installs with no ACME);
// the narrowness is deliberate — it is the only thing this interface can do,
// so wiring it can never widen into a general "answer HTTP locally" backdoor.
//
// The host of the validation request is passed through: the responder (the
// ACME manager) is the authority on which domain an in-flight token is
// proving, because a domain saved from the dashboard changes the name mid-
// process while this proxy's own captured copy would go stale.
type ChallengeResponder interface {
	// ChallengeResponse returns the body for a challenge token presented to
	// the named host, or ok=false when no issuance is proving that pair.
	ChallengeResponse(host, token string) (string, bool)
}

// acmeChallengePrefix is the path prefix HTTP-01 validators request. Kept as a
// constant beside the code that compares it, not imported from a package the
// relay has no other reason to depend on.
const acmeChallengePrefix = "/.well-known/acme-challenge/"

type Server struct {
	settings     database.SNIProxySettings
	bindHost     string
	domain       string
	access       AccessValidator
	meter        TrafficMeter
	acme         ChallengeResponder
	acmeAnswered atomic.Uint64
	activeRelays atomic.Int64
	totalRelays  atomic.Uint64
	bytesSent    atomic.Uint64
	bytesRecv    atomic.Uint64
	// refused and unreadable are disjoint drop counters, so their sum is every
	// connection that was accepted and never relayed. refused covers the decisions
	// this proxy makes about a destination it managed to read (quota spent, relay
	// table full, target blocked or pointing back at this host); unreadable covers
	// the connections whose opening bytes named no destination at all. See
	// GuardStats for why the distinction is the one an operator needs.
	refused    atomic.Uint64
	unreadable atomic.Uint64
	listeners  []net.Listener
	mu         sync.Mutex
	cancel     context.CancelFunc

	guard *targetGuard
	// slots is a counting semaphore: a relay takes one for its lifetime.
	slots chan struct{}
}

// SetChallengeResponder attaches the ACME challenge source. Called once at
// wiring time, before listeners accept.
func (s *Server) SetChallengeResponder(r ChallengeResponder) {
	s.acme = r
}

func NewServer(
	settings database.SNIProxySettings,
	bindHost string,
	domain string,
	access AccessValidator,
) *Server {
	s := &Server{
		settings: settings,
		bindHost: bindHost,
		domain:   domain,
		access:   access,
		guard:    newTargetGuard(),
		slots:    make(chan struct{}, maxConcurrentRelays),
	}
	if m, ok := access.(TrafficMeter); ok {
		s.meter = m
	}
	return s
}

// idleTimeout is the per-direction inactivity deadline for a relay.
// settings.Timeout was parsed from the config and stored but never applied, so a
// client could open a relay, fall silent and hold two sockets open forever.
func (s *Server) idleTimeout() time.Duration {
	if s.settings.Timeout > 0 {
		return s.settings.Timeout
	}
	return defaultIdleTimeout
}

func (s *Server) Start() error {
	if !s.settings.Enabled {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	host := s.bindHost
	if host == "" {
		host = "0.0.0.0"
	}

	ports := []struct {
		port  int
		isTLS bool
		name  string
	}{
		{s.settings.HTTPSPort, true, "HTTPS SNI Proxy"},
		{s.settings.HTTPPort, false, "HTTP Proxy"},
		{s.settings.GameChatTLSPort, true, "Gaming Chat TLS"},
		{s.settings.GameChatXMPPPort, false, "Gaming Chat XMPP"},
		{s.settings.RiotRTMPort, true, "Riot PVP.net RTM"},
		{s.settings.RiotPatcherPort, false, "Riot Patcher"},
	}

	for _, p := range ports {
		if p.port <= 0 {
			continue
		}
		addr := net.JoinHostPort(host, strconv.Itoa(p.port))
		// Dual-stack: an unspecified "0.0.0.0" binds IPv4 only, but a host
		// with AAAA records is validated over IPv6 by ACME (and reached over
		// IPv6 by every client whose resolver prefers it). The wildcard "::"
		// accepts both families on every mainstream stack, so an operator who
		// pointed both record types at this server — the normal v2.2 setup —
		// gets port 80/443 reachable on both. A host that explicitly names an
		// address family keeps exactly what it asked for.
		listenHost := host
		if host == "0.0.0.0" {
			listenHost = "::"
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(listenHost, strconv.Itoa(p.port)))
		if err != nil {
			log.Printf("[SNI Proxy] Warning: Failed to bind %s on %s: %v", p.name, addr, err)
			continue
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, ln)
		s.mu.Unlock()

		go s.acceptLoop(ctx, ln, p.isTLS, p.port)
	}

	return nil
}

func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.listeners = nil
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, isTLS bool, listenPort int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// A closed listener never recovers, so the old unconditional retry
			// spun this goroutine at 20 Hz for the life of the process whenever
			// Stop() raced ahead of the context check above.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		go s.handleConnection(ctx, conn, isTLS, listenPort)
	}
}

// readHandshake fills buf until the opening message is complete: a whole TLS
// record for TLS, or the end of the request headers for plain HTTP. A single
// Read was assumed to deliver the entire ClientHello, so a hello split across
// TCP segments — routine once post-quantum key shares push it past one segment —
// failed to parse and the connection was silently dropped.
func readHandshake(conn net.Conn, buf []byte, isTLS bool) (int, error) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if total > 0 && handshakeComplete(buf[:total], isTLS) {
			return total, nil
		}
		if err != nil {
			if total > 0 {
				return total, nil
			}
			return 0, err
		}
	}
	return total, nil
}

// handleConnection relays one accepted connection. listenPort is the port this
// connection arrived on, and is also the port the relay dials on the far side: an
// SNI proxy substitutes the address, not the service, so a client that connected
// to 443 is talking to the real host's 443. That is why a name whose traffic runs
// on any other port cannot be proxied by this daemon at all.
func (s *Server) handleConnection(ctx context.Context, clientConn net.Conn, isTLS bool, listenPort int) {
	defer clientConn.Close()

	tuneTCP(clientConn)

	// ACME HTTP-01 challenge serving (v2.2.0), before the access gate.
	//
	// The CA's validator is not a subscriber and never can be — it connects to
	// port 80 from wherever the CA validates from, moments after an issuance
	// was requested from the dashboard. Everything else this proxy does for a
	// connection still requires a registered, in-quota source; this is the one
	// deliberately carved-out path, and it is as narrow as the protocol allows:
	// plain HTTP, on the configured HTTP port, GET, a Host matching the
	// configured domain, and a token the ACME manager is actively proving (the
	// mapping exists only for the seconds a validation is in flight). A scanner
	// hitting the path gets the same relay-or-drop it always got, because no
	// token matches.
	//
	// The handshake is read here once; on a miss the bytes are handed to the
	// relay path below through earlyHandshake, so nothing is read twice.
	var earlyHandshake []byte
	var earlyN int
	if !isTLS && s.acme != nil && listenPort == s.settings.HTTPPort {
		bufPtr := handshakeBufPool.Get().(*[]byte)
		buf := *bufPtr
		n, err := readHandshake(clientConn, buf, isTLS)
		if err != nil || n == 0 {
			handshakeBufPool.Put(bufPtr)
			return
		}
		if s.maybeServeACMEChallenge(clientConn, buf[:n]) {
			handshakeBufPool.Put(bufPtr)
			return
		}
		earlyHandshake = buf[:n]
		earlyN = n
		defer func() { handshakeBufPool.Put(bufPtr) }()
	}

	// Access control. The client is resolved even in allow_all mode — where
	// IsIPAllowed reports true for everyone — because a recognised account still
	// has to be metered and quota-checked. An unknown source in that mode gets a
	// nil client and is relayed unmetered, which is what allow_all means.
	clientIP, _, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	var client *database.Client
	if s.access != nil {
		c, allowed := s.access.IsIPAllowed(clientIP)
		if !allowed {
			return
		}
		client = c
	}

	// A client that has spent its allowance is dropped before any work is done on
	// its behalf. Refusing rather than disabling the account keeps the block
	// reversible: raising the limit or resetting the counter restores service
	// without an operator re-enabling anything by hand.
	if client != nil && s.meter != nil && s.meter.QuotaExceeded(client) {
		s.refused.Add(1)
		return
	}

	// Take a relay slot before doing any work on behalf of the client, so an
	// overloaded proxy sheds load at accept time instead of after paying for a
	// handshake parse and a DNS lookup.
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.refused.Add(1)
		return
	}

	bufPtr := handshakeBufPool.Get().(*[]byte)
	defer handshakeBufPool.Put(bufPtr)
	buf := *bufPtr

	var n int
	if earlyHandshake != nil {
		// The ACME pre-check already read the handshake; reuse those exact
		// bytes rather than reading (and consuming) a second time.
		n = earlyN
		copy(buf, earlyHandshake)
		earlyHandshake = nil
	} else {
		var err error
		n, err = readHandshake(clientConn, buf, isTLS)
		if err != nil || n == 0 {
			return
		}
	}

	var hostname string
	var err error
	if isTLS {
		hostname, err = ExtractSNI(buf[:n])
	} else {
		hostname, err = ExtractHTTPHost(buf[:n])
	}
	if err != nil || hostname == "" {
		// This used to return in complete silence: no counter, no log line. That
		// silence is how a preset can advertise a proxy path for a service whose
		// protocol this relay cannot read and have nobody find out — DNS answered,
		// TCP connected, and the client sits waiting for a peer that will never
		// speak. cm.steampowered.com was exactly that case (see
		// matcher/realtime.go), and it took a code audit to notice rather than a log.
		//
		// Counted here and *not* also in s.refused, so the two are disjoint and can
		// be added: every other drop site is a decision this proxy made about a
		// destination it knew, whereas this one never learned a destination at all.
		// Folding it into refused would leave an operator unable to tell "the guards
		// are working" from "a name is sending clients somewhere I cannot carry them".
		if s.unreadable.Add(1)%unreadableLogSample == 1 {
			log.Printf("[SNI Proxy] Port %d: %s sent no readable destination (%s, opens with %s); "+
				"a name resolving here whose traffic is not %s cannot be relayed",
				listenPort, clientIP, describeProto(isTLS), openingBytes(buf[:n]), describeProto(isTLS))
		}
		return
	}

	// Resolve and vet before dialling, then dial the vetted address rather than
	// the name. The old code string-matched the hostname and handed the name to
	// the dialer, so any name that resolved to a private address — DNS rebinding,
	// or simply "internal.corp.example" — turned the relay into an SSRF pivot.
	dialCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	_, addrs, err := s.guard.resolve(dialCtx, hostname)
	cancel()
	if err != nil {
		s.refused.Add(1)
		if !errors.Is(err, ErrTargetMalformed) {
			log.Printf("[SNI Proxy] Refused relay from %s: %v", clientIP, err)
		}
		return
	}

	targetConn, err := s.dialVetted(ctx, addrs, listenPort)
	if err != nil {
		return
	}
	defer targetConn.Close()
	tuneTCP(targetConn)

	s.activeRelays.Add(1)
	s.totalRelays.Add(1)
	defer s.activeRelays.Add(-1)

	idle := s.idleTimeout()
	_ = targetConn.SetWriteDeadline(time.Now().Add(idle))
	if isTLS && s.settings.EnableFragmentation && s.settings.FragmentSize > 0 {
		err = SendFragmented(targetConn, buf[:n], s.settings.FragmentSize, s.settings.FragmentDelayMs)
	} else {
		_, err = targetConn.Write(buf[:n])
	}
	_ = targetConn.SetWriteDeadline(time.Time{})
	if err != nil {
		return
	}
	// The handshake is the first thing the client spent, so it is counted like
	// any other relayed byte rather than being absorbed silently.
	s.bytesSent.Add(uint64(n))

	var report func(uint64)
	if client != nil && s.meter != nil {
		report = func(delta uint64) {
			s.meter.AddTraffic(client.ID, delta)

			// Enforce mid-relay as well. The check at connection time cannot
			// bound a single long-lived stream, so without this one connection
			// could carry an unlimited amount past the limit. The account is
			// re-resolved instead of reusing the pointer captured above: a flush
			// replaces the entries in the access table, and the captured copy
			// would keep reporting the total as it stood when the relay opened.
			cur := client
			if fresh, ok := s.access.IsIPAllowed(clientIP); ok && fresh != nil {
				cur = fresh
			}
			if s.meter.QuotaExceeded(cur) {
				// Closing both sockets makes the next read and write in each
				// direction fail, so both copies unwind on their own.
				_ = clientConn.Close()
				_ = targetConn.Close()
			}
		}
		report(uint64(n))
	}

	s.relay(clientConn, targetConn, idle, report)
}

// dialVetted connects to the first reachable vetted address. Passing an address
// rather than a hostname closes the window in which a second lookup — the one
// the dialer would perform — could return an address the guard never saw.
func (s *Server) dialVetted(ctx context.Context, addrs []netip.Addr, port int) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: handshakeTimeout, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, addr := range addrs {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("proxy: no target addresses to dial")
	}
	return nil, lastErr
}

// relay shuttles bytes in both directions until either side finishes or falls
// idle. Each direction half-closes its peer on completion, so a server that
// replies and hangs up does not leave the opposite copy blocked on a socket that
// will never produce another byte. report, when non-nil, is called from both
// directions with each chunk of accounted traffic and must be safe for concurrent
// use.
func (s *Server) relay(clientConn, targetConn net.Conn, idle time.Duration, report func(uint64)) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		b := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(b)
		s.bytesSent.Add(copyIdle(targetConn, clientConn, *b, idle, report))
		closeWrite(targetConn)
	}()

	go func() {
		defer wg.Done()
		b := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(b)
		s.bytesRecv.Add(copyIdle(clientConn, targetConn, *b, idle, report))
		closeWrite(clientConn)
	}()

	wg.Wait()
}

// copyIdle is io.CopyBuffer with an inactivity deadline refreshed per chunk. It
// reports progress to report every meterFlushBytes so that accounting for a
// long-lived connection does not wait for the connection to end.
func copyIdle(dst, src net.Conn, buf []byte, idle time.Duration, report func(uint64)) uint64 {
	var total, unreported uint64
	// Whatever is still unreported when the copy ends has to be handed over, on
	// every exit path.
	defer func() {
		if report != nil && unreported > 0 {
			report(unreported)
		}
	}()

	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if idle > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
			}
			written, werr := dst.Write(buf[:n])
			if written > 0 {
				total += uint64(written)
				unreported += uint64(written)
				if report != nil && unreported >= meterFlushBytes {
					report(unreported)
					unreported = 0
				}
			}
			if werr != nil {
				return total
			}
		}
		if rerr != nil {
			return total
		}
	}
}

func closeWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// describeProto names what a listener expects to read, for the log line above.
func describeProto(isTLS bool) string {
	if isTLS {
		return "TLS with SNI"
	}
	return "HTTP with a Host header"
}

// openingBytes renders the first few bytes of a connection that named no
// destination. It is the one piece of evidence that separates "a scanner
// connected" from "a real service is speaking a protocol this relay cannot read":
// a TLS handshake opens 16 03 01, an HTTP request opens with a method, and
// anything else is a binary protocol that has no destination to extract. Hex, and
// four bytes of it, so nothing from the wire reaches the log as text.
func openingBytes(buf []byte) string {
	if len(buf) == 0 {
		return "no bytes"
	}
	return hex.EncodeToString(buf[:min(len(buf), 4)])
}

func tuneTCP(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// handshakeComplete reports whether buf already holds everything the parsers
// need, so readHandshake can stop instead of blocking for the full deadline.
func handshakeComplete(buf []byte, isTLS bool) bool {
	if isTLS {
		if len(buf) < 5 {
			return false
		}
		// TLS record header: type, version(2), length(2).
		recordLen := int(buf[3])<<8 | int(buf[4])
		return len(buf) >= 5+recordLen
	}
	return bytes.Contains(buf, []byte("\r\n\r\n")) || bytes.Contains(buf, []byte("\n\n"))
}

// GetStats reports active relays, the lifetime relay count and bytes relayed in
// each direction.
func (s *Server) GetStats() (int64, uint64, uint64, uint64) {
	return s.activeRelays.Load(),
		s.totalRelays.Load(),
		s.bytesSent.Load(),
		s.bytesRecv.Load()
}

// GuardStats reports the two ways a connection reaches this proxy and leaves
// again without ever becoming a relay, neither of which appears in GetStats. The
// two are disjoint, so their sum is every accepted-but-not-relayed connection:
//
//   - refused: this proxy read a destination and declined it — the client's quota
//     was spent, the relay table was already at maxConcurrentRelays, or the target
//     was blocked, malformed, or resolved back to this host. Mostly evidence that
//     the guards are working.
//   - unreadable: the opening bytes named no destination, so there was nothing to
//     dial. A port scanner looks exactly like this, so a handful on a public IP is
//     background noise. A count that climbs with real traffic is not: it means a
//     name is being answered with this server's address and the client then speaks
//     something this relay cannot read a destination out of — traffic that is UDP,
//     or TCP on a port this relay does not accept on, or TCP that is neither TLS
//     nor HTTP. The client cannot diagnose it either, because the substitution
//     happened in DNS.
//
// Both are lifetime totals since start.
func (s *Server) GuardStats() (refused, unreadable uint64) {
	return s.refused.Load(), s.unreadable.Load()
}
