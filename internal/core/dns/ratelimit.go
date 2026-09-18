package dns

import (
	"hash/maphash"
	"net"
	"sync"
	"time"
)

// rateLimitBuckets is the size of the token-bucket table, a power of two so the
// index is a mask. A fixed table is used instead of a map keyed by source address
// because the source of a UDP query is spoofable: a per-IP map grows to however
// many addresses an attacker cares to forge, which makes the limiter itself the
// memory-exhaustion vector it was added to prevent. Two sources sharing a bucket
// lose some fairness, never safety, and because the hash seed is drawn per process
// the pairing cannot be chosen from outside.
const rateLimitBuckets = 1 << 13

// defaultRateLimitQPS applies when config.json says nothing about rate limiting.
// An unmetered resolver answers a 60-byte question with a response many times
// larger, so it amplifies whatever source address a flood claims to come from —
// and allow_all defaults to true, so "known clients only" is not the shape most
// installs run in. Real subscribers, including a whole office behind one NAT
// address, sit far below this.
const defaultRateLimitQPS = 200

// minRateLimitBurst keeps a low configured rate from clipping the burst a browser
// produces when one page pulls in a dozen third-party domains at once.
const minRateLimitBurst = 20

// rateLimitLogSample is how many drops share one query-log entry. Logging every
// drop would let a flood drive a ring-buffer write and an SSE fan-out per packet,
// so only every nth is recorded — enough to identify the source.
const rateLimitLogSample = 128

type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	qps     float64
	burst   float64
	seed    maphash.Seed
	buckets []tokenBucket
	now     func() time.Time
}

// newRateLimiter caps each source address to qps queries per second, allowing a
// burst of twice that. A qps of zero or less means the operator turned limiting
// off, and nil is returned so the check on the query path costs one nil compare.
func newRateLimiter(qps int) *rateLimiter {
	if qps <= 0 {
		return nil
	}
	burst := float64(qps) * 2
	if burst < minRateLimitBurst {
		burst = minRateLimitBurst
	}
	return &rateLimiter{
		qps:     float64(qps),
		burst:   burst,
		seed:    maphash.MakeSeed(),
		buckets: make([]tokenBucket, rateLimitBuckets),
		now:     time.Now,
	}
}

// allow consumes one token for ip and reports whether the query may proceed.
// peer is the immediate transport peer: the loopback exemption keys on IT, not
// on ip, because ip may be a forwarding-header value a declared proxy passed
// through — a client claiming "127.0.0.1" through the proxy must still be
// throttled like any other outside source (v2.1.0 A-01 remediation).
func (l *rateLimiter) allow(ip string, peer ...string) bool {
	if l == nil {
		return true
	}
	// The operator's own tooling — the TUI, health checks, the dashboard's
	// diagnostics — resolves over loopback and must not be throttled by traffic
	// that has nothing to do with it. The exemption keys on the immediate peer:
	// a header-derived client address is exactly what an attacker behind a
	// declared proxy can choose, so it must never unlock the exemption.
	peerAddr := ip
	if len(peer) > 0 && peer[0] != "" {
		peerAddr = peer[0]
	}
	if isLoopback(peerAddr) {
		return true
	}

	b := &l.buckets[maphash.String(l.seed, ip)&(rateLimitBuckets-1)]
	now := l.now()

	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.last.IsZero():
		// First query through this bucket: start full rather than empty, so a
		// fresh client is not penalised for the process having just started.
		b.tokens = l.burst
	default:
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = min(l.burst, b.tokens+elapsed*l.qps)
		}
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// isLoopback reports whether ip is this machine talking to itself. An unparseable
// value is not loopback: it arrives from a header on the DoH path and must not be
// able to buy an exemption.
func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}
