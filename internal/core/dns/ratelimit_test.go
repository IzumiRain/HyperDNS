package dns

import (
	"fmt"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/database"
)

// fakeClock drives the limiter's refill without sleeping, so a refill test is
// deterministic rather than dependent on how long the test process was scheduled.
type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.at
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	f.at = f.at.Add(d)
	f.mu.Unlock()
}

// limiterAt returns a limiter whose clock the caller controls.
func limiterAt(qps int, clk *fakeClock) *rateLimiter {
	l := newRateLimiter(qps)
	if l != nil {
		l.now = clk.now
	}
	return l
}

func TestRateLimiterDisabledIsNil(t *testing.T) {
	for _, qps := range []int{0, -1, -1000} {
		if l := newRateLimiter(qps); l != nil {
			t.Fatalf("newRateLimiter(%d) = %v, want nil so the query path can skip it", qps, l)
		}
	}

	// A nil limiter must behave as "no limit" rather than panicking, because that
	// is the value the handler holds when an operator turns limiting off.
	var l *rateLimiter
	if !l.allow("203.0.113.7") {
		t.Fatal("nil limiter denied a query; limiting-off must allow everything")
	}
}

func TestRateLimiterBurstThenDeny(t *testing.T) {
	clk := newFakeClock()
	l := limiterAt(10, clk) // burst = max(2*10, 20) = 20
	const ip = "203.0.113.10"

	for i := 0; i < 20; i++ {
		if !l.allow(ip) {
			t.Fatalf("query %d of the burst was denied; burst should be 20", i+1)
		}
	}
	if l.allow(ip) {
		t.Fatal("query 21 was allowed with no time elapsed; the bucket should be empty")
	}
}

func TestRateLimiterRefills(t *testing.T) {
	clk := newFakeClock()
	l := limiterAt(10, clk)
	const ip = "203.0.113.11"

	for i := 0; i < 20; i++ {
		l.allow(ip)
	}
	if l.allow(ip) {
		t.Fatal("bucket was not empty after draining the burst")
	}

	// One second at 10 qps buys exactly ten more queries.
	clk.advance(time.Second)
	for i := 0; i < 10; i++ {
		if !l.allow(ip) {
			t.Fatalf("query %d after a 1s refill was denied; 10 tokens should have accrued", i+1)
		}
	}
	if l.allow(ip) {
		t.Fatal("refill produced more than the configured 10 tokens per second")
	}
}

func TestRateLimiterRefillCapsAtBurst(t *testing.T) {
	clk := newFakeClock()
	l := limiterAt(10, clk)
	const ip = "203.0.113.12"

	l.allow(ip)
	// An hour idle must not bank an hour's worth of queries: a client that goes
	// quiet and comes back should get a burst, not a free flood.
	clk.advance(time.Hour)

	allowed := 0
	for i := 0; i < 100; i++ {
		if l.allow(ip) {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("allowed %d queries after an hour idle, want the 20-token burst cap", allowed)
	}
}

func TestRateLimiterBurstFloor(t *testing.T) {
	clk := newFakeClock()
	// At 1 qps a literal 2x burst would be 2, which a single page load exceeds.
	l := limiterAt(1, clk)
	if l.burst != minRateLimitBurst {
		t.Fatalf("burst = %v for qps=1, want the %d floor", l.burst, minRateLimitBurst)
	}

	const ip = "203.0.113.13"
	for i := 0; i < minRateLimitBurst; i++ {
		if !l.allow(ip) {
			t.Fatalf("query %d denied below the burst floor", i+1)
		}
	}
}

func TestRateLimiterLoopbackExempt(t *testing.T) {
	clk := newFakeClock()
	l := limiterAt(1, clk)

	// The dashboard's diagnostics, health checks and the TUI all resolve over
	// loopback; unrelated traffic must not be able to throttle them.
	for _, ip := range []string{"127.0.0.1", "127.0.0.53", "::1"} {
		for i := 0; i < minRateLimitBurst*5; i++ {
			if !l.allow(ip) {
				t.Fatalf("loopback %s was rate limited on query %d", ip, i+1)
			}
		}
	}
}

func TestRateLimiterUnparseableIsNotExempt(t *testing.T) {
	clk := newFakeClock()
	l := limiterAt(1, clk)

	// This value reaches the limiter from a header on the DoH path, so it must not
	// be able to buy the loopback exemption by being unparseable.
	const bogus = "127.0.0.1, 203.0.113.9"
	if isLoopback(bogus) {
		t.Fatalf("isLoopback(%q) = true; a header value must not pass as loopback", bogus)
	}

	allowed := 0
	for i := 0; i < minRateLimitBurst*3; i++ {
		if l.allow(bogus) {
			allowed++
		}
	}
	if allowed != minRateLimitBurst {
		t.Fatalf("allowed %d queries for %q, want the %d burst", allowed, bogus, minRateLimitBurst)
	}
}

func TestRateLimiterSourcesAreIndependent(t *testing.T) {
	clk := newFakeClock()
	l := limiterAt(10, clk)
	const victim = "203.0.113.20"

	// Find a source that hashes to a different bucket. Two addresses sharing a
	// bucket is by design — the table is fixed so a spoofed source cannot grow it
	// — so the test picks a non-colliding pair rather than asserting no collisions
	// ever happen.
	bucketOf := func(ip string) uint64 { return bucketIndex(l, ip) }
	var flooder string
	for i := 0; i < 64; i++ {
		candidate := fmt.Sprintf("198.51.100.%d", i+1)
		if bucketOf(candidate) != bucketOf(victim) {
			flooder = candidate
			break
		}
	}
	if flooder == "" {
		t.Skip("no non-colliding source found in the probe range")
	}

	for i := 0; i < 100; i++ {
		l.allow(flooder)
	}
	if !l.allow(victim) {
		t.Fatalf("%s was denied after %s drained its own bucket", victim, flooder)
	}
}

func TestRateLimiterConcurrentAllowIsBounded(t *testing.T) {
	clk := newFakeClock()
	l := limiterAt(10, clk)
	const ip = "203.0.113.30"

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if l.allow(ip) {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	// The clock never moves, so no tokens accrue: the burst is the whole budget
	// however many goroutines race for it.
	if got := allowed.Load(); got != 20 {
		t.Fatalf("allowed %d of 1600 concurrent queries, want exactly the 20-token burst", got)
	}
}

// bucketIndex mirrors the index computation in allow so a test can reason about
// collisions without exporting anything.
func bucketIndex(l *rateLimiter, ip string) uint64 {
	return maphash.String(l.seed, ip) & (rateLimitBuckets - 1)
}

func TestHandlerRateLimitDropsUDPAndRefusesTCP(t *testing.T) {
	c := cache.NewCache(1000, 60, 3600)
	defer c.Close()
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"1.1.1.1:53"}, 2*time.Second, true, "")
	h := NewHandler(&dummyAccess{}, c, m, u, nil, "198.51.100.1")

	clk := newFakeClock()
	h.limiter = limiterAt(1, clk)

	// A non-loopback source, so the exemption does not apply. The name is one the
	// default Riot preset proxies, so draining the burst is answered from the
	// PROXY branch and the test never depends on a reachable upstream.
	const ip = "203.0.113.40"
	req := new(dns.Msg)
	req.SetQuestion("playvalorant.com.", dns.TypeA)

	for i := 0; i < minRateLimitBurst; i++ {
		if resp := h.ProcessQuery(req, ip, "UDP"); resp == nil {
			t.Fatalf("query %d of the burst was dropped; the burst must pass", i+1)
		}
	}

	// Over the limit on UDP: no reply at all. A refusal would still be a packet
	// aimed at whatever source a flood forged.
	if resp := h.ProcessQuery(req, ip, "UDP"); resp != nil {
		t.Fatalf("rate-limited UDP query answered with rcode %v, want a silent drop", resp.Rcode)
	}

	// Over the limit on a connection-oriented transport: an explicit REFUSED,
	// because the DoH bridge turns a nil response into HTTP 500.
	for _, proto := range []string{"TCP", "DoT", "DoH"} {
		resp := h.ProcessQuery(req, ip, proto)
		if resp == nil {
			t.Fatalf("%s query returned nil; the DoH bridge maps that to HTTP 500", proto)
		}
		if resp.Rcode != dns.RcodeRefused {
			t.Errorf("%s query rcode = %v, want REFUSED", proto, dns.RcodeToString[resp.Rcode])
		}
	}

	if h.RateLimited() == 0 {
		t.Error("RateLimited() = 0 after queries were dropped")
	}
}

// quotaAccess is an access provider that also reports quota state, so the handler
// resolves the optional QuotaEnforcer interface off it.
type quotaAccess struct {
	client   *database.Client
	exceeded bool
}

func (q *quotaAccess) IsIPAllowed(string) (*database.Client, bool) { return q.client, true }
func (q *quotaAccess) IsAllowAll() bool                            { return true }
func (q *quotaAccess) QuotaExceeded(*database.Client) bool         { return q.exceeded }

func TestHandlerRefusesOverQuotaClient(t *testing.T) {
	c := cache.NewCache(1000, 60, 3600)
	defer c.Close()
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"1.1.1.1:53"}, 2*time.Second, true, "")

	access := &quotaAccess{client: &database.Client{ID: "c1", Name: "Metered"}, exceeded: true}
	h := NewHandler(access, c, m, u, nil, "198.51.100.1")
	if h.quota == nil {
		t.Fatal("NewHandler did not pick up the QuotaEnforcer the access provider implements")
	}

	req := new(dns.Msg)
	req.SetQuestion("playvalorant.com.", dns.TypeA)

	resp := h.ProcessQuery(req, "203.0.113.50", "TCP")
	if resp == nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("over-quota client got %v, want REFUSED", resp)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("over-quota response carried %d answers, want none", len(resp.Answer))
	}

	// Raising the limit or resetting the counter has to restore service without
	// anyone re-enabling the account, so the refusal must not be sticky.
	access.exceeded = false
	if resp := h.ProcessQuery(req, "203.0.113.50", "TCP"); resp == nil || resp.Rcode == dns.RcodeRefused {
		t.Fatalf("client still refused after the quota cleared: %v", resp)
	}
}

func TestHandlerQuotaDoesNotApplyToUnknownSource(t *testing.T) {
	c := cache.NewCache(1000, 60, 3600)
	defer c.Close()
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"1.1.1.1:53"}, 2*time.Second, true, "")

	// allow_all with no matching account: there is no allowance to exceed, so the
	// quota check must not refuse the query.
	access := &quotaAccess{client: nil, exceeded: true}
	h := NewHandler(access, c, m, u, nil, "198.51.100.1")

	req := new(dns.Msg)
	req.SetQuestion("playvalorant.com.", dns.TypeA)

	resp := h.ProcessQuery(req, "203.0.113.51", "TCP")
	if resp == nil || resp.Rcode == dns.RcodeRefused {
		t.Fatalf("unidentified source refused on a quota it cannot have: %v", resp)
	}
}
