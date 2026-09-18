package cache

import (
	"testing"

	"github.com/miekg/dns"
)

// B-10: a 0-TTL record must not be inflated to minTTL for the client.
func TestClampTTLsLeavesZeroTTLAlone(t *testing.T) {
	c := NewCache(16, 60, 3600)
	m := new(dns.Msg)
	rr, err := dns.NewRR("zero.example.test. 0 IN A 203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	m.Answer = append(m.Answer, rr)
	c.ClampTTLs(m)
	if got := m.Answer[0].Header().Ttl; got != 0 {
		t.Errorf("0-TTL record clamped to %d, want it left at 0", got)
	}
	// Down-clamping still applies to non-zero TTLs.
	rr2, _ := dns.NewRR("high.example.test. 99999 IN A 203.0.113.2")
	m.Answer[0] = rr2
	c.ClampTTLs(m)
	if got := m.Answer[0].Header().Ttl; got != 3600 {
		t.Errorf("TTL 99999 clamped to %d, want maxTTL 3600", got)
	}
}

// B-11: the negative TTL is min(SOA header TTL, SOA.MINIMUM) per RFC 2308.
func TestGetMinTTLObeysSOAMinimum(t *testing.T) {
	c := NewCache(16, 60, 3600)
	m := new(dns.Msg)
	m.SetRcode(&dns.Msg{Question: []dns.Question{{Name: "gone.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}, dns.RcodeNameError)
	soa, err := dns.NewRR("gone.example.test. 86400 IN SOA ns1.example.test. host.example.test. 1 7200 900 1209600 300")
	if err != nil {
		t.Fatal(err)
	}
	m.Ns = append(m.Ns, soa)

	got := c.getMinTTL(m)
	if got != 300 {
		t.Errorf("getMinTTL = %d, want SOA MINIMUM 300 (RFC 2308), not the header TTL 86400", got)
	}
}
