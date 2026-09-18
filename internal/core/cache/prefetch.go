// Serve-stale and prefetch: the two things that keep an expiring cache entry from
// turning into a latency spike on someone's screen.
//
// A plain expiring cache has a failure mode that matters more in a game than in a
// browser. The entry for the name a client is about to use runs out, and whoever
// asks next pays the whole upstream round trip — twenty milliseconds on a good
// day, a timeout on a bad one — while everyone before and after them was answered
// in microseconds. Two mechanisms remove that, both standard resolver practice
// and the second one specified by RFC 8767:
//
//   - Prefetch. An entry inside the last tenth of its life is renewed in the
//     background while it is still being served fresh, so the expiry never
//     arrives for a name anyone is actually using.
//   - Serve-stale. An entry that did expire is still served for a short grace
//     window, with a short TTL, while its replacement is fetched behind it. The
//     client gets an answer immediately and the fresh record a few seconds later.
//
// Both are single-flighted per cache key and share a bounded pool of background
// workers, so a flood of names entering their prefetch window cannot become a
// flood of upstream queries or an unbounded pile of goroutines.
package cache

import (
	"log"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultStaleWindow is how long past expiry an answer may still be served
	// while its replacement is fetched. Long enough to cover an upstream hiccup,
	// short enough that nobody is connecting to an address that moved a minute
	// ago.
	defaultStaleWindow = 30 * time.Second

	// staleAnswerTTL is the TTL on a stale answer, in seconds. It has to be small
	// — the point is that the client comes back soon and gets the refreshed record
	// — but not 1, because a one-second TTL turns a chatty stub resolver into a
	// query flood.
	staleAnswerTTL = 5

	// maxRefreshWorkers bounds the background refreshes in flight at once. Past
	// this a refresh is skipped rather than queued: the entry it would have
	// replaced is still being served, and the next query for that name tries
	// again.
	maxRefreshWorkers = 64

	// prefetchFraction is the share of an entry's lifetime, at the end, during
	// which a lookup also starts a refresh: the last tenth.
	prefetchFraction = 10
)

// RefreshFunc re-resolves one question. The cache calls it from a background
// goroutine and stores whatever comes back through the normal Put path, so a
// refreshed answer is held to the same rcode and TTL policy as a client-driven
// one.
type RefreshFunc func(q dns.Question) (*dns.Msg, error)

// SetRefresher installs the function the cache uses to renew entries. Until one
// is set, Lookup behaves exactly like Get: with nothing to replace a stale entry,
// serving one would only hand out an answer that never improves.
//
// Call it during startup, before any listener is accepting.
func (c *Cache) SetRefresher(f RefreshFunc) {
	if f == nil {
		c.refresh.Store(nil)
		return
	}
	c.refresh.Store(&f)
}

func (c *Cache) refresher() RefreshFunc {
	if p := c.refresh.Load(); p != nil {
		return *p
	}
	return nil
}

// SetStaleWindow overrides how long an expired entry may still be served. Zero
// turns serve-stale off and leaves prefetch running. Call it during startup only:
// the value is read on every lookup without synchronisation.
func (c *Cache) SetStaleWindow(d time.Duration) {
	c.staleFor = max(d, 0)
}

// StaleWindow is the grace period in effect, or zero when serve-stale is off.
func (c *Cache) StaleWindow() time.Duration {
	return c.staleFor
}

// Lookup is the resolver's cache read: a fresh answer when there is one, a stale
// answer when that beats making the client wait, and a report of which it gave
// back.
//
// The second return value is true only for a stale answer. Callers log the two
// apart because "answered in forty microseconds from an entry that expired eight
// seconds ago" and "answered in forty microseconds from a live entry" are
// different facts about the resolver, even though they are the same experience
// for the client.
func (c *Cache) Lookup(q dns.Question) (*dns.Msg, bool) {
	key := c.cacheKey(q)
	shard := c.getShard(key)
	now := time.Now()

	shard.mu.RLock()
	entry, ok := shard.entries[key]
	if !ok {
		shard.mu.RUnlock()
		c.misses.Add(1)
		return nil, false
	}

	expireAt := entry.expireAt
	origTTL := entry.origTTL
	expired := now.After(expireAt)
	servable := !expired || now.Before(expireAt.Add(c.staleFor))

	var (
		elapsed uint32
		resp    *dns.Msg
	)
	if servable {
		if !expired {
			elapsed = uint32(now.Sub(entry.cachedAt).Seconds())
		}
		// Copy while still holding the read lock, so the stored message is never
		// read outside the shard's synchronisation.
		resp = entry.msg.Copy()
	}
	shard.mu.RUnlock()

	// The refresher is only consulted when this lookup might start a refresh, so a
	// hit in the middle of an entry's life pays nothing for the machinery.
	var refresh RefreshFunc
	if expired || expireAt.Sub(now) <= prefetchLead(origTTL) {
		refresh = c.refresher()
	}

	// Past the grace window, or inside it with nothing that could replace the
	// entry: either way this is a miss and the slot is reclaimed.
	if !servable || (expired && refresh == nil) {
		c.reclaimExpired(shard, key, now)
		c.misses.Add(1)
		return nil, false
	}

	c.hits.Add(1)

	if expired {
		c.staleServed.Add(1)
		setTTLs(resp, staleAnswerTTL)
		c.startRefresh(q, key, refresh)
		return resp, true
	}

	adjustRRs(resp.Answer, elapsed)
	adjustRRs(resp.Ns, elapsed)
	adjustRRs(resp.Extra, elapsed)

	if refresh != nil {
		c.startRefresh(q, key, refresh)
	}
	return resp, false
}

// prefetchLead is how long before expiry a lookup starts a background refresh:
// the last tenth of the entry's lifetime, at least two seconds so a short-TTL
// record still gets renewed before it lapses, at most thirty so a day-long record
// is not re-resolved half a day early — and never more than half the lifetime, so
// a very short TTL does not put every single lookup on the prefetch path.
func prefetchLead(origTTL uint32) time.Duration {
	life := time.Duration(origTTL) * time.Second
	lead := min(max(life/prefetchFraction, 2*time.Second), 30*time.Second)
	return min(lead, life/2)
}

// setTTLs pins every record in a message to one TTL. OPT is skipped for the same
// reason clampRRs skips it: EDNS0 keeps the extended rcode and version in that
// field, so writing a lifetime there corrupts the header.
func setTTLs(msg *dns.Msg, ttl uint32) {
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			h.Ttl = ttl
		}
	}
}

// reclaimExpired drops a key whose entry is past its expiry, re-checking under the
// write lock because another goroutine may have replaced it with a fresh answer
// while the read lock was released.
//
// Without the reclaim, a name queried once and never again holds its slot until
// the thirty-second sweep, and a flood of one-shot names pins the cache at its
// ceiling.
func (c *Cache) reclaimExpired(shard *cacheShard, key string, now time.Time) {
	shard.mu.Lock()
	if cur, still := shard.entries[key]; still && now.After(cur.expireAt) {
		delete(shard.entries, key)
	}
	shard.mu.Unlock()
}

// startRefresh runs one background re-resolution for a key, if one is not already
// running and a worker slot is free. It reports whether it started one.
//
// The single-flight set is what keeps a burst on one expiring name from becoming a
// burst of identical upstream queries: the first caller claims the key and every
// other caller for the duration is served from the entry and skips, so at most one
// upstream query per name is ever outstanding.
func (c *Cache) startRefresh(q dns.Question, key string, refresh RefreshFunc) bool {
	c.flightMu.Lock()
	if _, busy := c.inflight[key]; busy {
		c.flightMu.Unlock()
		return false
	}
	c.inflight[key] = struct{}{}
	c.flightMu.Unlock()

	select {
	case c.refreshSem <- struct{}{}:
	default:
		// Every slot is taken. Give the key back and skip rather than queue: the
		// entry is still being served, and the next query for it tries again.
		c.releaseFlight(key)
		c.refreshDropped.Add(1)
		return false
	}

	c.refreshes.Add(1)
	go c.runRefresh(q, key, refresh)
	return true
}

func (c *Cache) runRefresh(q dns.Question, key string, refresh RefreshFunc) {
	// The generation this refresh was born into (v2.1.0 B-14 remediation).
	gen := c.generation.Load()
	defer func() {
		<-c.refreshSem
		c.releaseFlight(key)
		// A panic in an upstream exchange would otherwise take the whole resolver
		// down from a goroutine nobody is waiting on. Losing one refresh costs a
		// stale answer for a few more seconds; losing the process costs every
		// client their connection.
		if r := recover(); r != nil {
			c.refreshFailed.Add(1)
			log.Printf("[Cache] Background refresh for %s panicked: %v", q.Name, r)
		}
	}()

	resp, err := refresh(q)
	if err != nil || resp == nil {
		c.refreshFailed.Add(1)
		return
	}
	// A flush that landed between the query and this point must win: putting
	// the pre-flush answer back would survive a full TTL, exactly when the
	// operator flushed to make a change take effect.
	if c.generation.Load() != gen {
		return
	}
	// Put applies the same rcode and TTL policy a client-driven answer gets, so a
	// SERVFAIL refresh stores nothing and the stale entry goes on being served
	// until its window closes — which is the resilience serve-stale exists for.
	c.Put(q, resp)
}

func (c *Cache) releaseFlight(key string) {
	c.flightMu.Lock()
	delete(c.inflight, key)
	c.flightMu.Unlock()
}

// PrefetchStats reports the background-refresh machinery: answers served past
// their expiry, refreshes started, refreshes that came back with nothing usable,
// and refreshes skipped because every worker slot was busy.
func (c *Cache) PrefetchStats() (staleServed, started, failed, dropped uint64) {
	return c.staleServed.Load(), c.refreshes.Load(), c.refreshFailed.Load(), c.refreshDropped.Load()
}
