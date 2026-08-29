package dns

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const numShards = 64

type cacheEntry struct {
	msg       *dns.Msg
	cachedAt  time.Time
	expireAt  time.Time
	origTTL   uint32
}

type cacheShard struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

type Cache struct {
	shards    [numShards]*cacheShard
	maxSize   int
	minTTL    uint32
	maxTTL    uint32
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
		maxSize: maxSize,
		minTTL:  minTTL,
		maxTTL:  maxTTL,
	}

	for i := 0; i < numShards; i++ {
		c.shards[i] = &cacheShard{
			entries: make(map[string]*cacheEntry),
		}
	}

	go c.cleanupLoop()

	return c
}

func (c *Cache) getShard(key string) *cacheShard {
	h := sha256.Sum256([]byte(key))
	val := binary.BigEndian.Uint64(h[:8])
	return c.shards[val%numShards]
}

func (c *Cache) cacheKey(q dns.Question) string {
	return q.Name + ":" + dns.TypeToString[q.Qtype] + ":" + dns.ClassToString[q.Qclass]
}

// Get returns a cached DNS message if present and unexpired, with adjusted TTLs
func (c *Cache) Get(q dns.Question) *dns.Msg {
	key := c.cacheKey(q)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, ok := shard.entries[key]
	if !ok {
		shard.mu.RUnlock()
		return nil
	}

	now := time.Now()
	if now.After(entry.expireAt) {
		shard.mu.RUnlock()
		// Lazy eviction
		shard.mu.Lock()
		delete(shard.entries, key)
		shard.mu.Unlock()
		return nil
	}

	elapsed := uint32(now.Sub(entry.cachedAt).Seconds())
	shard.mu.RUnlock()

	// Clone message and adjust TTLs
	resp := entry.msg.Copy()
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

	if minTTL < c.minTTL {
		minTTL = c.minTTL
	}
	if minTTL > c.maxTTL {
		minTTL = c.maxTTL
	}

	key := c.cacheKey(q)
	shard := c.getShard(key)

	now := time.Now()
	entry := &cacheEntry{
		msg:      msg.Copy(),
		cachedAt: now,
		expireAt: now.Add(time.Duration(minTTL) * time.Second),
		origTTL:  minTTL,
	}

	shard.mu.Lock()
	if len(shard.entries) > c.maxSize/numShards {
		// Evict an expired or random entry
		for k, e := range shard.entries {
			if now.After(e.expireAt) {
				delete(shard.entries, k)
				break
			}
		}
	}
	shard.entries[key] = entry
	shard.mu.Unlock()
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
	for i := 0; i < numShards; i++ {
		c.shards[i].mu.Lock()
		c.shards[i].entries = make(map[string]*cacheEntry)
		c.shards[i].mu.Unlock()
	}
}

func (c *Cache) Count() int {
	total := 0
	for i := 0; i < numShards; i++ {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].entries)
		c.shards[i].mu.RUnlock()
	}
	return total
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		now := time.Now()
		for i := 0; i < numShards; i++ {
			shard := c.shards[i]
			shard.mu.Lock()
			for k, e := range shard.entries {
				if now.After(e.expireAt) {
					delete(shard.entries, k)
				}
			}
			shard.mu.Unlock()
		}
	}
}
