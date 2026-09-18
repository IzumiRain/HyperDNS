package cache

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Serve-stale and prefetch are the two places where the cache answers with
// something other than "a live entry or nothing", so they are the two places where
// a defect turns into a wrong answer served confidently. These tests pin the
// contract: nothing stale is served unless something is going to replace it,
// nothing is served past its grace window, one expiring name produces at most one
// upstream query no matter how many clients ask, and a refresh that fails leaves
// the old answer in place instead of a hole.

// refreshedAnswer is the shape a background refresh returns. The address differs
// from answerFor's on purpose: it is how a test proves the entry was replaced
// rather than merely still present.
const refreshedIP = "198.51.100.99"

func refreshedAnswer(q dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.Question = []dns.Question{q}
	rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN A %s", q.Name, refreshedIP))
	if err != nil {
		panic(err) // a malformed literal is a bug in the test, not the cache
	}
	m.Answer = []dns.RR{rr}
	return m
}

// waitFor polls a condition the background refresher satisfies. The refresh runs
// on its own goroutine, so there is no handle to join; the alternative to polling
// is a fixed sleep, which is either flaky or slow.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// servedAddress is the A record a lookup returns, or "" for a miss.
func servedAddress(c *Cache, q dns.Question) string {
	msg, _ := c.Lookup(q)
	if msg == nil || len(msg.Answer) == 0 {
		return ""
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		return ""
	}
	return a.A.String()
}

// TestLookupServesFreshEntry is the baseline: with no refresher wired, Lookup is
// Get with a second return value.
func TestLookupServesFreshEntry(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerFor("fresh.example")
	c.Put(q, msg)

	got, stale := c.Lookup(q)
	if got == nil {
		t.Fatal("live entry reported as a miss")
	}
	if stale {
		t.Error("a live entry was reported as stale")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 300 {
		t.Errorf("served TTL = %d, want 300", ttl)
	}
}

// TestLookupWithoutRefresherIsStrict pins the guard that makes serve-stale safe to
// leave on by default: with nothing able to replace an expired entry, serving it
// would only hand out an answer that never improves, so Lookup misses and reclaims
// exactly as Get does.
func TestLookupWithoutRefresherIsStrict(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerFor("no-refresher.example")
	c.Put(q, msg)
	backdate(t, c, q, 310*time.Second) // 10s past a 300s expiry, inside the window

	got, stale := c.Lookup(q)
	if got != nil || stale {
		t.Error("an expired entry was served with no refresher configured")
	}
	if n := c.Count(); n != 0 {
		t.Errorf("entry count = %d, want 0 — the expired entry was not reclaimed", n)
	}
}

// TestStaleWindowZeroDisablesServeStale is the operator's off switch. Prefetch
// keeps working; nothing past its expiry is ever served.
func TestStaleWindowZeroDisablesServeStale(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) { return refreshedAnswer(q), nil })
	c.SetStaleWindow(0)

	q, msg := answerFor("no-stale.example")
	c.Put(q, msg)
	backdate(t, c, q, 310*time.Second)

	if got, _ := c.Lookup(q); got != nil {
		t.Error("an expired entry was served with the stale window turned off")
	}
	if n := c.Count(); n != 0 {
		t.Errorf("entry count = %d, want 0", n)
	}
}

// TestServeStaleAnswersImmediatelyAndRefreshes is the whole point of the feature:
// the client that arrives just after an entry lapses is answered from memory
// instead of waiting on an upstream, and the replacement lands behind them.
func TestServeStaleAnswersImmediatelyAndRefreshes(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) { return refreshedAnswer(q), nil })

	q, msg := answerFor("stale.example")
	c.Put(q, msg)
	backdate(t, c, q, 310*time.Second)

	got, stale := c.Lookup(q)
	if got == nil {
		t.Fatal("an entry inside the grace window was reported as a miss")
	}
	if !stale {
		t.Error("a stale answer was not reported as stale")
	}
	// The short TTL is what brings the client back for the refreshed record. The
	// original 300 would pin them to a lapsed answer for five minutes.
	if ttl := got.Answer[0].Header().Ttl; ttl != staleAnswerTTL {
		t.Errorf("stale TTL = %d, want %d", ttl, staleAnswerTTL)
	}
	if a := got.Answer[0].(*dns.A).A.String(); a != "198.51.100.7" {
		t.Errorf("stale answer = %s, want the entry that was already there", a)
	}

	waitFor(t, "the background refresh to replace the entry", func() bool {
		return servedAddress(c, q) == refreshedIP
	})

	// The refreshed entry has to be live, not stale: a refresh that stored an
	// already-expired answer would serve stale for ever.
	if _, stillStale := c.Lookup(q); stillStale {
		t.Error("the refreshed entry is still being served as stale")
	}

	served, started, failed, _ := c.PrefetchStats()
	if served == 0 {
		t.Error("the stale serve was not counted")
	}
	if started == 0 {
		t.Error("no refresh was started")
	}
	if failed != 0 {
		t.Errorf("failed refreshes = %d, want 0", failed)
	}
}

// TestLookupDropsEntryPastStaleWindow pins the far edge: the grace window is a
// bounded promise, not "serve the last answer for ever".
func TestLookupDropsEntryPastStaleWindow(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) { return refreshedAnswer(q), nil })

	q, msg := answerFor("long-gone.example")
	c.Put(q, msg)
	backdate(t, c, q, 300*time.Second+c.StaleWindow()+time.Second)

	if got, _ := c.Lookup(q); got != nil {
		t.Error("an entry past its grace window was served")
	}
	if n := c.Count(); n != 0 {
		t.Errorf("entry count = %d, want 0", n)
	}
}

// TestStaleAnswerLeavesOPTAlone covers the record a real upstream answer always
// carries. EDNS0 keeps the extended rcode and flags in the OPT record's TTL field,
// so rewriting it to the stale TTL would corrupt the header of every stale answer
// the resolver serves.
func TestStaleAnswerLeavesOPTAlone(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) { return nil, errors.New("upstream down") })

	q, msg := answerFor("edns-stale.example")
	msg.SetEdns0(1232, true)
	before := msg.IsEdns0().Hdr.Ttl
	c.Put(q, msg)
	backdate(t, c, q, 310*time.Second)

	got, stale := c.Lookup(q)
	if got == nil || !stale {
		t.Fatal("the stale entry was not served")
	}
	opt := got.IsEdns0()
	if opt == nil {
		t.Fatal("the OPT record did not survive the cache")
	}
	if opt.Hdr.Ttl != before {
		t.Errorf("OPT TTL field = %d, want %d unchanged", opt.Hdr.Ttl, before)
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != staleAnswerTTL {
		t.Errorf("answer TTL = %d, want %d", ttl, staleAnswerTTL)
	}
}

// TestPrefetchRenewsBeforeExpiry is the case that matters most in a game: the
// entry is renewed while it is still live, so the expiry never arrives and nobody
// ever pays the upstream round trip.
func TestPrefetchRenewsBeforeExpiry(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	entered := make(chan struct{}, 1)
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		return refreshedAnswer(q), nil
	})

	q, msg := answerFor("prefetch.example")
	c.Put(q, msg)
	// A 300-second life means the last thirty seconds are the prefetch window.
	backdate(t, c, q, 275*time.Second)

	got, stale := c.Lookup(q)
	if got == nil {
		t.Fatal("a live entry reported as a miss")
	}
	if stale {
		t.Error("an entry inside its prefetch window was served as stale")
	}
	// The client still gets the live answer with its real remaining TTL. The
	// renewal happens behind them, not instead of their answer.
	if ttl := got.Answer[0].Header().Ttl; ttl > 26 || ttl < 24 {
		t.Errorf("served TTL = %d, want 25 (±1)", ttl)
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no refresh started for an entry inside its prefetch window")
	}
	waitFor(t, "the prefetched answer to replace the entry", func() bool {
		return servedAddress(c, q) == refreshedIP
	})
}

// TestNoPrefetchInTheMiddleOfLife is the other half of the prefetch contract.
// Refreshing on every hit would double this resolver's upstream traffic and
// undo the reason a cache exists.
func TestNoPrefetchInTheMiddleOfLife(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	var calls atomic.Int64
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) {
		calls.Add(1)
		return refreshedAnswer(q), nil
	})

	q, msg := answerFor("midlife.example")
	c.Put(q, msg)
	backdate(t, c, q, 100*time.Second) // 200 seconds still to run

	for range 20 {
		if got, _ := c.Lookup(q); got == nil {
			t.Fatal("a live entry reported as a miss")
		}
	}
	// Give a stray goroutine time to run before concluding none was started.
	time.Sleep(20 * time.Millisecond)

	if n := calls.Load(); n != 0 {
		t.Errorf("upstream refreshes = %d, want 0 — a mid-life hit must not query upstream", n)
	}
	if _, started, _, _ := c.PrefetchStats(); started != 0 {
		t.Errorf("refreshes started = %d, want 0", started)
	}
}

// TestRefreshIsSingleFlighted is the bound that keeps this feature from becoming an
// amplifier. A popular name expiring during a match is asked for by every client at
// once; without the single-flight claim each of those queries would start its own
// upstream refresh.
func TestRefreshIsSingleFlighted(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	var calls atomic.Int64
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) {
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return refreshedAnswer(q), nil
	})

	q, msg := answerFor("thundering-herd.example")
	c.Put(q, msg)
	backdate(t, c, q, 310*time.Second)

	// Block inside the refresher first, so the burst below cannot race ahead of the
	// single-flight claim and make the test pass for the wrong reason.
	if got, stale := c.Lookup(q); got == nil || !stale {
		t.Fatal("the first lookup did not serve the stale entry")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the refresher was never called")
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if got, _ := c.Lookup(q); got == nil {
				t.Error("a concurrent lookup was refused an answer that was still in the cache")
			}
		})
	}
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Errorf("upstream refreshes = %d, want 1 — a burst on one name fanned out", n)
	}
	close(release)
	waitFor(t, "the in-flight refresh to land", func() bool {
		return servedAddress(c, q) == refreshedIP
	})
}

// TestFailedRefreshKeepsServingStale is the resilience case, and the reason
// serve-stale is worth having at all: when the upstream stops answering, clients
// keep getting the last known-good address instead of SERVFAIL.
func TestFailedRefreshKeepsServingStale(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	var calls atomic.Int64
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) {
		calls.Add(1)
		return nil, errors.New("upstream unreachable")
	})

	q, msg := answerFor("resilient.example")
	c.Put(q, msg)
	backdate(t, c, q, 310*time.Second)

	for i := range 3 {
		got, stale := c.Lookup(q)
		if got == nil || !stale {
			t.Fatalf("lookup %d: the entry was dropped after a failed refresh", i+1)
		}
		if a := got.Answer[0].(*dns.A).A.String(); a != "198.51.100.7" {
			t.Fatalf("lookup %d: served %s, want the last known-good address", i+1, a)
		}
	}

	waitFor(t, "a failed refresh to be recorded", func() bool {
		_, _, failed, _ := c.PrefetchStats()
		return failed >= 1
	})
	if n := c.Count(); n != 1 {
		t.Errorf("entry count = %d, want 1 — a failed refresh deleted the answer it could not replace", n)
	}
	if calls.Load() == 0 {
		t.Error("no refresh was attempted")
	}
}

// TestRefreshHonoursCachingPolicy pins that a refresh goes through the same door a
// client-driven answer does. A SERVFAIL is not an answer, so it must not overwrite
// a working entry — that would turn one upstream hiccup into a poisoned cache.
func TestRefreshHonoursCachingPolicy(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	done := make(chan struct{}, 1)
	c.SetRefresher(func(q dns.Question) (*dns.Msg, error) {
		bad := refreshedAnswer(q)
		bad.Rcode = dns.RcodeServerFailure
		select {
		case done <- struct{}{}:
		default:
		}
		return bad, nil
	})

	q, msg := answerFor("servfail-refresh.example")
	c.Put(q, msg)
	backdate(t, c, q, 310*time.Second)

	if got, stale := c.Lookup(q); got == nil || !stale {
		t.Fatal("the stale entry was not served")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the refresher was never called")
	}
	// The Put happens after the refresher returns, so give it a moment to land
	// before asserting that it did not.
	time.Sleep(20 * time.Millisecond)

	got, stale := c.Lookup(q)
	if got == nil || !stale {
		t.Fatal("the entry stopped being served after a SERVFAIL refresh")
	}
	if a := got.Answer[0].(*dns.A).A.String(); a != "198.51.100.7" {
		t.Errorf("served %s, want the original address — a SERVFAIL overwrote a good entry", a)
	}
}

// TestPrefetchLeadBounds pins the arithmetic that decides when a refresh starts.
func TestPrefetchLeadBounds(t *testing.T) {
	cases := []struct {
		ttl  uint32
		want time.Duration
	}{
		{0, 0},                      // nothing to renew
		{1, 500 * time.Millisecond}, // half a one-second life, not the 2s floor
		{4, 2 * time.Second},        // the floor, which is also half this life
		{60, 6 * time.Second},       // the plain last tenth
		{300, 30 * time.Second},     // a tenth, exactly at the ceiling
		{86400, 30 * time.Second},   // the ceiling
	}
	for _, tc := range cases {
		if got := prefetchLead(tc.ttl); got != tc.want {
			t.Errorf("prefetchLead(%d) = %v, want %v", tc.ttl, got, tc.want)
		}
	}
}
