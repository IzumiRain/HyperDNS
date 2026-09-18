package cache

import (
	"encoding/binary"
	"hash/maphash"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const numShards = 64

// maxNameLen is the RFC 1035 limit on a presentation-format domain name. It sizes
// the stack scratch buffer in cacheKey.
const maxNameLen = 255

// shardSeed spreads keys across the shards. A per-process seed, rather than a
// fixed one, means an attacker cannot precompute a set of names that all land in
// the same shard and turn the sharding into a single contended lock.
//
// This replaced crypto/sha256, which cost ~120ns of the ~440ns a cache hit took
// and bought nothing: shard selection needs uniform spread and unpredictability,
// not collision resistance against an adversary who already knows the key.
var shardSeed = maphash.MakeSeed()

type cacheEntry struct {
	msg      *dns.Msg
	cachedAt time.Time
	expireAt time.Time
	origTTL  uint32
}

type cacheShard struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

type Cache struct {
	shards  [numShards]*cacheShard
	maxSize int
	minTTL  uint32
	maxTTL  uint32
	hits    atomic.Uint64
	misses  atomic.Uint64

	// staleFor is how long past its expiry an entry may still be served while a
	// replacement is fetched behind it. Written by SetStaleWindow during startup,
	// read on every lookup. See prefetch.go.
	staleFor time.Duration

	// refresh is the upstream re-resolution hook installed by SetRefresher.
	refresh atomic.Pointer[RefreshFunc]

	// inflight is the single-flight set for background refreshes, keyed by cache
	// key; refreshSem bounds how many run at once.
	flightMu   sync.Mutex
	inflight   map[string]struct{}
	refreshSem chan struct{}

	// generation is bumped by Flush and checked by runRefresh before it puts a
	// refreshed answer back (v2.1.0 B-14 remediation): an in-flight refresh that
	// completes after the flush used to re-insert the pre-flush answer, letting
	// it survive a full TTL — precisely when the operator flushed to make a
	// change take effect.
	generation atomic.Uint64

	staleServed    atomic.Uint64
	refreshes      atomic.Uint64
	refreshFailed  atomic.Uint64
	refreshDropped atomic.Uint64

	// stop ends cleanupLoop. The loop used to be a bare `for range ticker.C` with
	// no way out, which is harmless for the daemon's single long-lived cache but
	// leaks a goroutine and a live 1-per-30s timer for every other Cache ever
	// constructed. The web package's test helper builds one per test: fifty-four
	// immortal sweepers is how a package that passes in seconds takes minutes
	// under -race. closeOnce keeps a second Close from panicking on a closed
	// channel, so callers may pair it with defer without tracking ownership.
	stop      chan struct{}
	closeOnce sync.Once
}

func NewCache(maxSize int, minTTL, maxTTL uint32) *Cache {
	if minTTL == 0 {
		minTTL = 60
	}
	if maxTTL == 0 {
		maxTTL = 86400
	}
	if maxSize <= 0 {
		maxSize = 20000
	}

	c := &Cache{
		maxSize:    maxSize,
		minTTL:     minTTL,
		maxTTL:     maxTTL,
		staleFor:   defaultStaleWindow,
		inflight:   make(map[string]struct{}),
		refreshSem: make(chan struct{}, maxRefreshWorkers),
		stop:       make(chan struct{}),
	}

	for i := range c.shards {
		c.shards[i] = &cacheShard{
			entries: make(map[string]*cacheEntry),
		}
	}

	go c.cleanupLoop()

	return c
}

func (c *Cache) getShard(key string) *cacheShard {
	return c.shards[maphash.String(shardSeed, key)%numShards]
}

// cacheKey normalizes the name to lower case. DNS names are case-insensitive,
// so keying on the raw name let a flood of case-varied spellings of one domain
// occupy an unbounded number of distinct entries.
//
// Type and class are written as their raw 16-bit values rather than looked up in
// dns.TypeToString/dns.ClassToString: two map lookups per query bought nothing
// but a human-readable key that nothing ever reads. They go in front of the name,
// not after it, so the four fixed-width bytes can never be confused with part of
// a name and two different (name, type, class) triples can never derive the same
// key. strings.ToLower returns the original string untouched when there is no
// uppercase to fold. The scratch array is sized for the 255-byte DNS name limit
// plus the four prefix bytes, so on the lookup path — where the key is not
// retained — it stays on the stack.
func (c *Cache) cacheKey(q dns.Question) string {
	name := strings.ToLower(q.Name)

	var scratch [maxNameLen + 4]byte
	var buf []byte
	if len(name) <= maxNameLen {
		buf = scratch[:0]
	} else {
		buf = make([]byte, 0, len(name)+4)
	}

	buf = binary.BigEndian.AppendUint16(buf, q.Qtype)
	buf = binary.BigEndian.AppendUint16(buf, q.Qclass)
	buf = append(buf, name...)
	return string(buf)
}

// Get returns a cached DNS message if present and unexpired, with adjusted TTLs.
//
// This is the strict lookup: an expired entry is a miss and is reclaimed on the
// spot. The resolver uses Lookup instead, which will serve an expired entry for a
// short grace window while a replacement is fetched — see prefetch.go.
func (c *Cache) Get(q dns.Question) *dns.Msg {
	key := c.cacheKey(q)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, ok := shard.entries[key]
	if !ok {
		shard.mu.RUnlock()
		c.misses.Add(1)
		return nil
	}

	now := time.Now()
	if now.After(entry.expireAt) {
		shard.mu.RUnlock()
		c.reclaimExpired(shard, key, now)
		c.misses.Add(1)
		return nil
	}

	elapsed := uint32(now.Sub(entry.cachedAt).Seconds())
	// Clone while still holding the read lock so the stored message is never
	// read outside the shard's synchronization.
	resp := entry.msg.Copy()
	shard.mu.RUnlock()

	c.hits.Add(1)

	adjustRRs(resp.Answer, elapsed)
	adjustRRs(resp.Ns, elapsed)
	adjustRRs(resp.Extra, elapsed)

	return resp
}

// Put caches a DNS message
func (c *Cache) Put(q dns.Question, msg *dns.Msg) {
	if msg == nil || len(msg.Question) == 0 {
		return
	}
	// Do not cache errors except NXDOMAIN
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}

	minTTL := c.getMinTTL(msg)
	if minTTL == 0 {
		return
	}

	// Clamp into the configured [minTTL, maxTTL] window.
	minTTL = min(max(minTTL, c.minTTL), c.maxTTL)

	key := c.cacheKey(q)
	shard := c.getShard(key)

	// Copy before clamping: the caller's message is the one being sent to the
	// client, and Put must not rewrite it as a side effect.
	stored := msg.Copy()
	c.ClampTTLs(stored)

	now := time.Now()
	entry := &cacheEntry{
		msg:      stored,
		cachedAt: now,
		expireAt: now.Add(time.Duration(minTTL) * time.Second),
		origTTL:  minTTL,
	}

	shard.mu.Lock()
	if _, exists := shard.entries[key]; !exists {
		c.evictLocked(shard, now)
	}
	shard.entries[key] = entry
	shard.mu.Unlock()
}

// ClampTTLs pins every record's TTL into the configured [minTTL, maxTTL] window.
//
// Without this the cache served the TTL the authoritative server published while
// enforcing its own, much shorter, expiry: a record refreshed every maxTTL
// seconds was handed to the client carrying a 24-hour TTL, so every downstream
// stub and forwarder went on using a value this cache had already discarded, and
// maxTTL protected nothing beyond this process. Clamping upward matters too — an
// answer held for minTTL seconds must not tell the client to come back in five,
// because the re-query only re-reads the same entry.
//
// OPT records are skipped: EDNS0 stores the extended rcode and version in the
// TTL field, so "clamping" one corrupts the header.
func (c *Cache) ClampTTLs(msg *dns.Msg) {
	if msg == nil {
		return
	}
	c.clampRRs(msg.Answer)
	c.clampRRs(msg.Ns)
	c.clampRRs(msg.Extra)
}

func (c *Cache) clampRRs(rrs []dns.RR) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		// Zero-TTL exception (v2.1.0 B-10 remediation): TTL 0 is the source
		// saying "do not reuse this answer at all". Clamping it UP to minTTL
		// told clients to hold an answer the authority disowned (and handed
		// DoH clients a max-age instead of no-store). Down-clamping only.
		if h.Ttl == 0 {
			continue
		}
		h.Ttl = min(max(h.Ttl, c.minTTL), c.maxTTL)
	}
}

// shardCap is the per-shard entry ceiling. maxSize is a global budget, so each
// of the numShards maps gets an equal slice of it, with a floor of 1 so a very
// small configured cache still stores answers instead of evicting on every Put.
func (c *Cache) shardCap() int {
	return max(c.maxSize/numShards, 1)
}

// evictLocked frees room for one new entry. Expired entries are dropped first;
// if the shard is still at capacity the entries closest to expiry are removed.
// Without this the previous code deleted at most one *expired* entry and
// inserted regardless, so a stream of unique names grew the cache past maxSize
// without bound. Caller must hold shard.mu for writing.
func (c *Cache) evictLocked(shard *cacheShard, now time.Time) {
	limit := c.shardCap()
	if len(shard.entries) < limit {
		return
	}

	for k, e := range shard.entries {
		if now.After(e.expireAt) {
			delete(shard.entries, k)
		}
	}

	for len(shard.entries) >= limit {
		var victim string
		var victimAt time.Time
		for k, e := range shard.entries {
			if victim == "" || e.expireAt.Before(victimAt) {
				victim, victimAt = k, e.expireAt
			}
		}
		if victim == "" {
			return
		}
		delete(shard.entries, victim)
	}
}

func (c *Cache) getMinTTL(msg *dns.Msg) uint32 {
	var minTTL uint32 = 0xFFFFFFFF
	found := false

	check := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl < minTTL {
				minTTL = h.Ttl
				found = true
			}
		}
	}

	check(msg.Answer)
	check(msg.Ns)
	check(msg.Extra)

	// Negative answers carry their lifetime in the SOA (RFC 2308 §5): the
	// effective negative TTL is min(SOA header TTL, SOA.MINIMUM). Reading only
	// the header TTL cached an NXDOMAIN for min(SOA TTL)=86400 — clamped up to
	// maxTTL — so a freshly created domain could stay "does not exist" for a
	// day (v2.1.0 B-11 remediation).
	if msg.Rcode == dns.RcodeNameError || len(msg.Answer) == 0 {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				neg := min(soa.Hdr.Ttl, soa.Minttl)
				if !found || neg < minTTL {
					minTTL = neg
					found = true
				}
			}
		}
	}

	if !found {
		return c.minTTL
	}
	return minTTL
}

func adjustRRs(rrs []dns.RR, elapsed uint32) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		if h.Ttl > elapsed {
			h.Ttl -= elapsed
		} else {
			h.Ttl = 1
		}
	}
}

func (c *Cache) Flush() {
	// Bump first, then clear: any refresh already past its generation check
	// still loses, because its Put re-checks and drops. A refresh that started
	// before the flush cannot resurrect a pre-flush answer.
	c.generation.Add(1)
	for i := range c.shards {
		c.shards[i].mu.Lock()
		c.shards[i].entries = make(map[string]*cacheEntry)
		c.shards[i].mu.Unlock()
	}
}

func (c *Cache) Count() int {
	total := 0
	for i := range c.shards {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].entries)
		c.shards[i].mu.RUnlock()
	}
	return total
}

// cleanupLoop reclaims entries nothing will ask for again. It drops an entry only
// once it is past its expiry *and* past the serve-stale grace window: a sweep that
// went by expiry alone would delete an entry that Lookup was still entitled to
// serve, so a name that expired seconds before the sweep lost its grace window
// entirely and cost the next client a full upstream round trip.
func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
		}

		cutoff := time.Now().Add(-c.staleFor)
		for i := range c.shards {
			shard := c.shards[i]
			shard.mu.Lock()
			for k, e := range shard.entries {
				if cutoff.After(e.expireAt) {
					delete(shard.entries, k)
				}
			}
			shard.mu.Unlock()
		}
	}
}

// Close stops the background sweeper. The cache stays fully usable afterwards —
// entries are still served, stored and evicted on the Put path — it simply stops
// reclaiming in the background, which is the right trade for a cache whose owner
// is going away. Safe to call more than once, and safe to call concurrently with
// lookups.
//
// In-flight prefetch goroutines are deliberately not waited on: they hold only
// their own key and the semaphore slot they release on the way out, and blocking
// a shutdown on an upstream that is timing out is worse than letting them finish.
func (c *Cache) Close() {
	c.closeOnce.Do(func() { close(c.stop) })
}

func (c *Cache) GetStats() (int, uint64, uint64) {
	return c.Count(), c.hits.Load(), c.misses.Load()
}
