package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCache(t *testing.T) {
	c := NewCache(100, 10, 300)

	q := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	rr, _ := dns.NewRR("example.com. 120 IN A 93.184.216.34")
	msg.Answer = append(msg.Answer, rr)

	// Put in cache
	c.Put(q, msg)

	if c.Count() != 1 {
		t.Fatalf("expected 1 cached entry, got %d", c.Count())
	}

	// Retrieve
	hit := c.Get(q)
	if hit == nil {
		t.Fatalf("expected cache hit for %v", q.Name)
	}

	if len(hit.Answer) == 0 {
		t.Fatalf("expected answer in cached response")
	}

	// Flush test
	c.Flush()
	if c.Count() != 0 {
		t.Fatalf("expected 0 entries after flush, got %d", c.Count())
	}

	hitAfterFlush := c.Get(q)
	if hitAfterFlush != nil {
		t.Fatalf("expected nil after flush")
	}
}

func TestCacheTTLDecay(t *testing.T) {
	c := NewCache(100, 2, 10)

	q := dns.Question{
		Name:   "decay.test.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	rr, _ := dns.NewRR("decay.test. 2 IN A 1.2.3.4")
	msg.Answer = append(msg.Answer, rr)

	c.Put(q, msg)

	time.Sleep(3 * time.Second)

	// Should be expired now
	if hit := c.Get(q); hit != nil {
		t.Fatalf("expected entry to expire after 3s with TTL 2")
	}
}
