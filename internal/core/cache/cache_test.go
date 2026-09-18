package cache

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The cache answers before anything else in the resolver runs, so a defect here
// is not a slow path — it is a wrong answer served fast. These tests pin the
// properties the rest of the daemon depends on: a key identifies a question
// exactly, a TTL leaves the cache no longer than the configured window allows,
// an entry past its expiry is never served, and the entry count stays inside the
// configured budget no matter how many distinct names arrive.
//
// On the race detector: it is unavailable in this environment (no C compiler),
// so TestConcurrentAccess is a stress substitute. It can surface a crash or a
// corrupted count; it cannot certify the cache race-free.

// answerWithTTL builds a single-A-record answer carrying an explicit TTL, for the
// tests that care what the cache does to the number rather than what it stores.
func answerWithTTL(name string, ttl uint32) (dns.Question, *dns.Msg) {
	fqdn := dns.Fqdn(name)
	q := dns.Question{Name: fqdn, Qtype: dns.TypeA, Qclass: dns.ClassINET}

	m := new(dns.Msg)
	m.Question = []dns.Question{q}
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A 198.51.100.7", fqdn, ttl))
	if err != nil {
		panic(err) // a malformed literal is a bug in the test, not the cache
	}
	m.Answer = []dns.RR{rr}
	return q, m
}

// backdate moves an entry's clock into the past so expiry and TTL countdown can
// be tested without sleeping. The smallest window the constructor accepts is one
// second, and the suite should not spend seconds proving arithmetic.
func backdate(t *testing.T, c *Cache, q dns.Question, age time.Duration) {
	t.Helper()

	key := c.cacheKey(q)
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.entries[key]
	if !ok {
		t.Fatalf("no entry to backdate for %q", q.Name)
	}
	entry.cachedAt = entry.cachedAt.Add(-age)
	entry.expireAt = entry.expireAt.Add(-age)
}

func TestPutGetRoundTrip(t *testing.T) {
	c := NewCache(1024, 30, 3600)
	defer c.Close()
	q, msg := answerFor("round-trip.example")

	if got := c.Get(q); got != nil {
		t.Fatal("empty cache returned an answer")
	}
	c.Put(q, msg)

	got := c.Get(q)
	if got == nil {
		t.Fatal("stored answer reported as a miss")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(got.Answer))
	}
	a, ok := got.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", got.Answer[0])
	}
	if a.A.String() != "198.51.100.7" {
		t.Errorf("address = %s, want 198.51.100.7", a.A)
	}
}

// A flood of case-varied spellings of one domain must occupy one entry, not one
// per spelling — the reason cacheKey folds case at all.
func TestGetIsCaseInsensitive(t *testing.T) {
	c := NewCache(1024, 30, 3600)
	defer c.Close()
	q, msg := answerFor("Mixed-Case.Example")
	c.Put(q, msg)

	for _, spelling := range []string{
		"mixed-case.example.",
		"MIXED-CASE.EXAMPLE.",
		"MiXeD-cAsE.eXaMpLe.",
	} {
		probe := dns.Question{Name: spelling, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		if got := c.Get(probe); got == nil {
			t.Errorf("%q reported as a miss", spelling)
		}
	}
	if n := c.Count(); n != 1 {
		t.Errorf("entry count = %d, want 1", n)
	}
}

// Type and class are part of a question's identity. Serving an A answer to an
// AAAA query would be a cache-poisoning primitive reachable by any client.
func TestKeyDistinguishesTypeAndClass(t *testing.T) {
	c := NewCache(1024, 30, 3600)
	defer c.Close()
	q, msg := answerFor("types.example")
	c.Put(q, msg)

	aaaa := dns.Question{Name: q.Name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	if got := c.Get(aaaa); got != nil {
		t.Error("AAAA query served from an A entry")
	}
	chaos := dns.Question{Name: q.Name, Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}
	if got := c.Get(chaos); got != nil {
		t.Error("CHAOS-class query served from an INET entry")
	}
}

// cacheKey writes type and class as four raw bytes in front of the name. Putting
// them in front rather than behind is what makes the encoding unambiguous: no
// name, however crafted, can shift the boundary so that two different questions
// derive one key. The escaped-byte spellings below are the shapes that would
// collide if the four bytes were appended instead.
func TestKeyIsUnambiguous(t *testing.T) {
	c := NewCache(1024, 30, 3600)
	defer c.Close()

	questions := []dns.Question{
		{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "a.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		{Name: "aa.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "a.example", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "\x00\x01\x00\x01a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "a.example.\x00\x01\x00\x01", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "a.example.", Qtype: 0, Qclass: 0},
	}

	seen := make(map[string]dns.Question, len(questions))
	for _, q := range questions {
		key := c.cacheKey(q)
		if prev, dup := seen[key]; dup && prev != q {
			t.Errorf("%+v and %+v derive the same key", prev, q)
		}
		seen[key] = q
	}
}

// A name longer than the RFC 1035 limit takes the heap fallback in cacheKey. It
// cannot arrive over the wire, but it can arrive from a config file or an
// internal caller, and it must not run off the stack scratch buffer.
func TestKeyHandlesOversizeName(t *testing.T) {
	c := NewCache(1024, 30, 3600)
	defer c.Close()
	long := strings.Repeat("a", maxNameLen+50) + "."
	q := dns.Question{Name: long, Qtype: dns.TypeA, Qclass: dns.ClassINET}

	key := c.cacheKey(q)
	if want := len(long) + 4; len(key) != want {
		t.Fatalf("key length = %d, want %d", len(key), want)
	}
	if shard := c.getShard(key); shard == nil {
		t.Fatal("shard selection returned nil for an oversize name")
	}
}

// The configured window is a promise the cache makes to the operator and to every
// downstream resolver: nothing is advertised for longer than maxTTL, and nothing
// is advertised for less time than the cache will actually hold it.
func TestTTLIsClampedToConfiguredWindow(t *testing.T) {
	const minTTL, maxTTL = 60, 300
	c := NewCache(1024, minTTL, maxTTL)
	defer c.Close()

	tests := []struct {
		desc string
		ttl  uint32
		want uint32
	}{
		{"below the floor is raised", 5, minTTL},
		{"inside the window is untouched", 120, 120},
		{"above the ceiling is lowered", 86400, maxTTL},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			q, msg := answerWithTTL(fmt.Sprintf("clamp-%d.example", tc.ttl), tc.ttl)
			c.Put(q, msg)

			got := c.Get(q)
			if got == nil {
				t.Fatal("stored answer reported as a miss")
			}
			if ttl := got.Answer[0].Header().Ttl; ttl != tc.want {
				t.Errorf("served TTL = %d, want %d", ttl, tc.want)
			}
			// Put takes a copy; the caller's message must come back untouched.
			if ttl := msg.Answer[0].Header().Ttl; ttl != tc.ttl {
				t.Errorf("Put rewrote the caller's TTL to %d, want %d left alone", ttl, tc.ttl)
			}
		})
	}
}

// EDNS0 keeps the extended rcode and version in the OPT record's TTL field, so
// clamping one corrupts the header rather than shortening a lifetime.
func TestClampLeavesOPTAlone(t *testing.T) {
	c := NewCache(1024, 60, 300)
	defer c.Close()
	_, msg := answerWithTTL("edns.example", 86400)
	msg.SetEdns0(1232, true)

	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("SetEdns0 did not attach an OPT record")
	}
	before := opt.Hdr.Ttl

	c.ClampTTLs(msg)
	if after := opt.Hdr.Ttl; after != before {
		t.Errorf("OPT TTL field = %d, want %d unchanged", after, before)
	}
}

// A client that asks again halfway through an entry's life must be told the
// remaining time, not the original. Serving a constant TTL would pin downstream
// caches to a record this one has already let go.
func TestServedTTLCountsDown(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerWithTTL("countdown.example", 300)
	c.Put(q, msg)

	backdate(t, c, q, 100*time.Second)

	got := c.Get(q)
	if got == nil {
		t.Fatal("live entry reported as a miss")
	}
	// One second of slack: the elapsed value is derived from a wall clock read
	// taken inside Get, not from the value handed to backdate.
	if ttl := got.Answer[0].Header().Ttl; ttl > 200 || ttl < 199 {
		t.Errorf("served TTL = %d, want 200 (±1)", ttl)
	}
}

// An entry whose remaining TTL has run out but which has not yet expired is
// served with TTL 1 rather than 0: a zero TTL tells some stub resolvers not to
// use the answer at all.
func TestServedTTLFloorsAtOne(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerWithTTL("floor.example", 3600)
	c.Put(q, msg)

	// Age past the record's own TTL while leaving the entry itself unexpired.
	key := c.cacheKey(q)
	shard := c.getShard(key)
	shard.mu.Lock()
	shard.entries[key].cachedAt = time.Now().Add(-2 * time.Hour)
	shard.mu.Unlock()

	got := c.Get(q)
	if got == nil {
		t.Fatal("unexpired entry reported as a miss")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 1 {
		t.Errorf("served TTL = %d, want 1", ttl)
	}
}

// An expired entry must miss, and the lookup must reclaim it — otherwise a name
// queried once and never again occupies a slot until the 30-second sweep, and a
// flood of one-shot names holds the cache at its ceiling.
func TestExpiredEntryMissesAndIsReclaimed(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerFor("expired.example")
	c.Put(q, msg)

	if c.Count() != 1 {
		t.Fatalf("entry count after Put = %d, want 1", c.Count())
	}
	backdate(t, c, q, 2*time.Hour)

	if got := c.Get(q); got != nil {
		t.Error("expired entry was served")
	}
	if n := c.Count(); n != 0 {
		t.Errorf("entry count after expired lookup = %d, want 0", n)
	}
}

// Caching a failure would turn one upstream hiccup into minutes of outage for
// every client asking that name. NXDOMAIN is the exception: it is an
// authoritative answer, and not caching it made every miss for a nonexistent
// name a fresh upstream round trip.
func TestRcodeCachingPolicy(t *testing.T) {
	tests := []struct {
		desc  string
		rcode int
		want  bool
	}{
		{"NOERROR is cached", dns.RcodeSuccess, true},
		{"NXDOMAIN is cached", dns.RcodeNameError, true},
		{"SERVFAIL is not cached", dns.RcodeServerFailure, false},
		{"REFUSED is not cached", dns.RcodeRefused, false},
		{"FORMERR is not cached", dns.RcodeFormatError, false},
		{"NOTIMP is not cached", dns.RcodeNotImplemented, false},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			c := NewCache(1024, 60, 3600)
			defer c.Close()
			q, msg := answerFor(fmt.Sprintf("rcode-%d.example", tc.rcode))
			msg.Rcode = tc.rcode
			c.Put(q, msg)

			if cached := c.Get(q) != nil; cached != tc.want {
				t.Errorf("cached = %v, want %v", cached, tc.want)
			}
		})
	}
}

// A TTL of zero means "use this answer once and ask again", so it must not be
// stored at all — not even raised to the configured floor.
func TestZeroTTLIsNotCached(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerWithTTL("no-cache.example", 0)
	c.Put(q, msg)

	if got := c.Get(q); got != nil {
		t.Error("a zero-TTL answer was cached")
	}
}

func TestPutRejectsMalformedMessages(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerFor("malformed.example")

	c.Put(q, nil)

	noQuestion := msg.Copy()
	noQuestion.Question = nil
	c.Put(q, noQuestion)

	if n := c.Count(); n != 0 {
		t.Errorf("entry count = %d, want 0", n)
	}
}

// The bound this test asserts is the one an attacker attacks. Before eviction was
// bounded, a stream of unique names grew the cache past maxSize without limit —
// a memory-exhaustion primitive available to any client allowed to query, and the
// deployment target is a 1 GB VPS.
func TestEvictionKeepsCountWithinBudget(t *testing.T) {
	const maxSize = 640 // 10 per shard across the 64 shards
	c := NewCache(maxSize, 60, 3600)
	defer c.Close()

	for i := range 20000 {
		q, msg := answerFor(fmt.Sprintf("flood%d.example", i))
		c.Put(q, msg)
	}

	// Each shard evicts down below its own ceiling before admitting the new
	// entry, so the global bound is the sum of the per-shard caps.
	if n, limit := c.Count(), c.shardCap()*numShards; n > limit {
		t.Errorf("entry count = %d, want at most %d", n, limit)
	}
	if c.Count() == 0 {
		t.Error("eviction emptied the cache instead of bounding it")
	}
}

// A cache configured smaller than its shard count must still answer from cache.
// With an integer division and no floor, shardCap reached zero and every Put
// evicted the entry it had just made room for.
func TestTinyCacheStillServes(t *testing.T) {
	c := NewCache(1, 60, 3600)
	defer c.Close()
	q, msg := answerFor("tiny.example")
	c.Put(q, msg)

	if got := c.Get(q); got == nil {
		t.Error("a one-entry cache stored nothing")
	}
}

func TestFlushEmptiesEveryShard(t *testing.T) {
	c := NewCache(4096, 60, 3600)
	defer c.Close()
	for i := range 500 {
		q, msg := answerFor(fmt.Sprintf("flush%d.example", i))
		c.Put(q, msg)
	}
	if c.Count() == 0 {
		t.Fatal("nothing was stored to flush")
	}

	c.Flush()

	if n := c.Count(); n != 0 {
		t.Errorf("entry count after Flush = %d, want 0", n)
	}
}

func TestStatsCountHitsAndMisses(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerFor("stats.example")
	absent, _ := answerFor("absent.example")

	c.Put(q, msg)
	c.Get(q)
	c.Get(q)
	c.Get(absent)

	items, hits, misses := c.GetStats()
	if items != 1 {
		t.Errorf("items = %d, want 1", items)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
}

// The handler mutates every answer it serves — it rewrites the transaction ID,
// the question section and the RD flag before the packet goes out. If Get handed
// back the stored message rather than a copy, the first client's transaction ID
// would be baked into the entry and served to everyone after it.
func TestGetReturnsAnIsolatedCopy(t *testing.T) {
	c := NewCache(1024, 60, 3600)
	defer c.Close()
	q, msg := answerWithTTL("isolated.example", 300)
	c.Put(q, msg)

	first := c.Get(q)
	if first == nil {
		t.Fatal("stored answer reported as a miss")
	}
	first.Id = 0xBEEF
	first.Answer[0].Header().Ttl = 7
	first.Answer[0].(*dns.A).A = nil
	first.Answer = nil

	second := c.Get(q)
	if second == nil {
		t.Fatal("second lookup reported as a miss")
	}
	if len(second.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 — the stored entry was mutated", len(second.Answer))
	}
	if ttl := second.Answer[0].Header().Ttl; ttl < 299 {
		t.Errorf("served TTL = %d, want ~300 — the stored TTL was mutated", ttl)
	}
	if a := second.Answer[0].(*dns.A); a.A == nil || a.A.String() != "198.51.100.7" {
		t.Errorf("address = %v, want 198.51.100.7 — the stored record was mutated", a.A)
	}
}

// The cache is sharded so that concurrent readers do not serialise on one lock,
// which means correctness under concurrency is a property of the design rather
// than an accident. The race detector is unavailable in this environment (no C
// compiler), so this is a stress substitute: it can surface a panic, a torn read
// or a lost counter, but it cannot certify the cache race-free.
func TestConcurrentAccess(t *testing.T) {
	const (
		workers = 32
		rounds  = 400
		names   = 64
	)
	c := NewCache(4096, 60, 3600)
	defer c.Close()

	questions := make([]dns.Question, names)
	messages := make([]*dns.Msg, names)
	for i := range names {
		questions[i], messages[i] = answerFor(fmt.Sprintf("concurrent%d.example", i))
	}

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := range rounds {
				i := (w*rounds + r) % names
				switch r % 4 {
				case 0:
					c.Put(questions[i], messages[i])
				case 3:
					if w == 0 && r%100 == 3 {
						c.Flush()
					}
					c.Count()
				default:
					if got := c.Get(questions[i]); got != nil && len(got.Answer) != 1 {
						t.Errorf("torn answer: %d records, want 1", len(got.Answer))
						return
					}
				}
			}
		}(w)
	}
	wg.Wait()

	if _, hits, misses := c.GetStats(); hits+misses == 0 {
		t.Error("no lookups were counted")
	}
}
