package cache

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// The resolver consults this cache before anything else on every query, so its
// per-hit cost lands directly in the latency a gamer sees. These benchmarks exist
// to keep the published figures honest and to catch a regression in the key
// derivation or the copy-on-read path.

// answerFor builds the shape the resolver actually stores: a question plus a
// single A record with a 300-second TTL.
func answerFor(name string) (dns.Question, *dns.Msg) {
	fqdn := dns.Fqdn(name)
	q := dns.Question{Name: fqdn, Qtype: dns.TypeA, Qclass: dns.ClassINET}

	m := new(dns.Msg)
	m.Question = []dns.Question{q}
	rr, err := dns.NewRR(fqdn + " 300 IN A 198.51.100.7")
	if err != nil {
		panic(err) // a malformed literal is a bug in the benchmark, not the cache
	}
	m.Answer = []dns.RR{rr}
	return q, m
}

// warmCache fills the cache with n distinct names and returns their questions in
// insertion order.
func warmCache(b *testing.B, n int) (*Cache, []dns.Question) {
	b.Helper()

	c := NewCache(n*2, 30, 3600)
	b.Cleanup(c.Close)
	questions := make([]dns.Question, n)
	for i := range n {
		q, msg := answerFor(fmt.Sprintf("host%d.benchmark.example", i))
		c.Put(q, msg)
		questions[i] = q
	}
	return c, questions
}

// BenchmarkCacheGetHit is the hot path: every cached query pays this.
func BenchmarkCacheGetHit(b *testing.B) {
	c, questions := warmCache(b, 1024)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if got := c.Get(questions[i%len(questions)]); got == nil {
			b.Fatal("warm entry reported as a miss")
		}
	}
}

// BenchmarkCacheGetMiss is what an uncached name costs before the upstream race
// even starts.
func BenchmarkCacheGetMiss(b *testing.B) {
	c, _ := warmCache(b, 1024)
	absent, _ := answerFor("not-present.benchmark.example")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if got := c.Get(absent); got != nil {
			b.Fatal("absent name reported as a hit")
		}
	}
}

// BenchmarkCachePut measures the write side, including the eviction check.
func BenchmarkCachePut(b *testing.B) {
	c := NewCache(4096, 30, 3600)
	defer c.Close()
	q, msg := answerFor("write.benchmark.example")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c.Put(q, msg)
	}
}

// BenchmarkCacheGetHitParallel is the reason the cache is sharded at all: it
// shows whether concurrent readers actually scale or serialise on one lock.
func BenchmarkCacheGetHitParallel(b *testing.B) {
	c, questions := warmCache(b, 4096)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if got := c.Get(questions[i%len(questions)]); got == nil {
				b.Error("warm entry reported as a miss")
				return
			}
			i++
		}
	})
}

// BenchmarkCacheKey isolates the key derivation and shard selection from the
// lookup itself, so a regression can be attributed to one or the other.
func BenchmarkCacheKey(b *testing.B) {
	c := NewCache(64, 30, 3600)
	defer c.Close()
	q := dns.Question{Name: "auth.riotgames.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = c.getShard(c.cacheKey(q))
	}
}
