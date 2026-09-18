package dns

import (
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/database"
)

// The guards in ProcessQuery that answer without ever consulting an upstream: the
// two shape checks, the ANY refusal, the IPv6 paths that exist so a rule cannot be
// walked around by asking for AAAA, and the datagram clamp in serve(). Every
// assertion here is about a reply this resolver writes on its own, so none of these
// tests can reach the network.

// captureWriter is a dns.ResponseWriter that keeps the message instead of putting
// it on a wire, so serve() can be exercised without a listener.
type captureWriter struct {
	// Embedded and left nil deliberately: serve() is only expected to ask for the
	// peer address and write one message, and any other call should panic the test
	// rather than be quietly satisfied.
	dns.ResponseWriter

	remote net.Addr
	msg    *dns.Msg
}

func (c *captureWriter) RemoteAddr() net.Addr { return c.remote }

func (c *captureWriter) WriteMsg(m *dns.Msg) error {
	c.msg = m
	return nil
}

// newGuardHandler builds a handler whose upstream pool is never meant to be
// reached. The address is a documentation range rather than a resolver, so a test
// that falls through to the upstream step by mistake fails on a short timeout
// instead of quietly depending on the developer's network.
func newGuardHandler(t *testing.T) (*Handler, *cache.Cache, *matcher.Matcher) {
	t.Helper()
	c := cache.NewCache(1000, 60, 3600)
	t.Cleanup(c.Close)
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"192.0.2.1:53"}, 200*time.Millisecond, true, "")
	return NewHandler(&dummyAccess{}, c, m, u, nil, "198.51.100.1"), c, m
}

// rcodeOf names a reply's rcode for a failure message, including the case where
// there is no reply at all.
func rcodeOf(m *dns.Msg) string {
	if m == nil {
		return "no reply"
	}
	return dns.RcodeToString[m.Rcode]
}

// answerIPs is every address in a reply's answer section, in order.
func answerIPs(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		}
	}
	return out
}

func TestHandlerRefusesANYBeforeAnyLookup(t *testing.T) {
	h, _, m := newGuardHandler(t)
	// One sinkholed name and one pinned name, because the block branch answers ANY
	// with an empty NOERROR if it is reached at all. RFC 8482 refuses ANY because it
	// produces the largest reply a small query can buy, which is the whole of a
	// reflection attack's amplification factor.
	m.SetCustomRules(nil, []string{"ads.internal.test"}, nil,
		map[string]string{"pin.internal.test": "203.0.113.77"})

	for _, name := range []string{"ads.internal.test.", "pin.internal.test.", "playvalorant.com."} {
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeANY)

		resp := h.ProcessQuery(req, "127.0.0.1", "UDP")
		if resp == nil {
			t.Fatalf("%s: ANY got no reply; a stub reads silence as a timeout and retries", name)
		}
		if resp.Rcode != dns.RcodeRefused {
			t.Errorf("%s: rcode = %s, want REFUSED", name, dns.RcodeToString[resp.Rcode])
		}
		if n := len(resp.Answer) + len(resp.Ns) + len(resp.Extra); n != 0 {
			t.Errorf("%s: refusal carried %d records; sending nothing back is the point", name, n)
		}
		if resp.Id != req.Id {
			t.Errorf("%s: reply id %d does not match the query's %d", name, resp.Id, req.Id)
		}
	}
}

func TestHandlerRejectsMalformedQueryShapes(t *testing.T) {
	h, _, _ := newGuardHandler(t)

	// No question section: a reflector's favourite probe, and the one shape where
	// even naming the query in a log line has nothing to read.
	empty := new(dns.Msg)
	empty.Id = dns.Id()
	empty.RecursionDesired = true
	if resp := h.ProcessQuery(empty, "127.0.0.1", "UDP"); resp == nil || resp.Rcode != dns.RcodeFormatError {
		t.Errorf("a question-less query got %s, want FORMERR", rcodeOf(resp))
	}

	// Two questions. No deployed client sends this; the second question is where a
	// query that means one thing to the parser and another to the resolver hides.
	pair := new(dns.Msg)
	pair.Id = dns.Id()
	pair.Question = []dns.Question{
		{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	if resp := h.ProcessQuery(pair, "127.0.0.1", "UDP"); resp == nil || resp.Rcode != dns.RcodeFormatError {
		t.Errorf("a two-question query got %s, want FORMERR", rcodeOf(resp))
	}

	// Anything that is not a QUERY. Treating an UPDATE or a NOTIFY as a lookup is how
	// a forwarder ends up acting on a message addressed to an authoritative server.
	for _, opcode := range []int{dns.OpcodeIQuery, dns.OpcodeStatus, dns.OpcodeNotify, dns.OpcodeUpdate} {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		req.Opcode = opcode

		resp := h.ProcessQuery(req, "127.0.0.1", "UDP")
		if resp == nil || resp.Rcode != dns.RcodeNotImplemented {
			t.Errorf("opcode %s got %s, want NOTIMPL", dns.OpcodeToString[opcode], rcodeOf(resp))
		}
	}
}

func TestUDPSizeIsWhatTheClientSaidItCanReceive(t *testing.T) {
	cases := []struct {
		name string
		adv  uint16 // 0 stands for a query with no OPT record at all
		want int
	}{
		{"no EDNS0 at all", 0, dns.MinMsgSize},
		{"the advertisement a modern stub sends", 1232, 1232},
		{"a 4096-byte advertisement", 4096, 4096},

		// Under the RFC 1035 floor: a resolver that believed this would clip every
		// answer it sends to a client whose EDNS0 implementation is simply wrong.
		{"an advertisement below the floor", 200, dns.MinMsgSize},

		// A 64 KB advertisement over UDP is either a broken client or a request for
		// fragmented traffic on demand, which is a reflection amplifier.
		{"an absurd advertisement", 65535, 4096},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeA)
			if tc.adv > 0 {
				req.SetEdns0(tc.adv, false)
			}
			if got := udpSize(req); got != tc.want {
				t.Errorf("udpSize = %d, want %d", got, tc.want)
			}
		})
	}
}

// docRanges are the three /24s RFC 5737 reserves for documentation, so no address
// bulkAnswer puts in an answer can name a real host if one of these records ever escaped
// a test. Hosts .1 to .254 of each are usable, which is 762 records in total.
var docRanges = []string{"198.51.100", "203.0.113", "192.0.2"}

// bulkAnswer is a reply too large for a 512-byte datagram: many A records for one
// name, which is what a large round-robin set looks like from a resolver's side.
//
// The addresses walk docRanges in turn rather than filling one /24, because one range
// caps the fixture at 254 records and 254 is not enough to be oversized in the sense
// that matters. Every record here repeats the same owner name, which miekg/dns
// compresses to a 2-byte pointer, so a set that measures ~8.8 KB uncompressed is only
// ~4.1 KB on the wire — a caller that needs a 4096-byte ceiling to actually drop
// something needs more records than a single range can supply.
func bulkAnswer(t *testing.T, name string, n int) *dns.Msg {
	t.Helper()
	if maxRecords := len(docRanges) * 254; n > maxRecords {
		t.Fatalf("bulkAnswer was asked for %d records but only %d documentation addresses "+
			"exist; add a range to docRanges rather than emitting an invalid octet", n, maxRecords)
	}
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Response = true
	for i := range n {
		addr := fmt.Sprintf("%s.%d", docRanges[i/254], i%254+1)
		rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN A %s", name, addr))
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		msg.Answer = append(msg.Answer, rr)
	}
	return msg
}

func TestServeClampsADatagramToTheClientsBuffer(t *testing.T) {
	h, c, _ := newGuardHandler(t)

	const name = "bulk.internal.test."
	q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	// Seeded rather than fetched: what is under test is what serve() does to a reply
	// on its way out, and the cache is the only way to hand it a large one without
	// an upstream. A 300-second TTL is a plain fresh hit for this cache.
	c.Put(q, bulkAnswer(t, name, 120))

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	w := &captureWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}}

	h.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("nothing was written")
	}
	if !w.msg.Truncated {
		t.Error("TC bit unset: a client with no way to know the answer was clipped will not retry over TCP")
	}
	if got := w.msg.Len(); got > dns.MinMsgSize {
		t.Errorf("wrote %d bytes to a client that can receive %d", got, dns.MinMsgSize)
	}
	if len(w.msg.Answer) == 0 {
		t.Error("clamped to nothing; a partial answer plus TC is what a stub can act on")
	}
	if len(w.msg.Answer) >= 120 {
		t.Errorf("answer still carries %d records, so nothing was dropped", len(w.msg.Answer))
	}
}

func TestServeLeavesALargeAnswerWholeWhenTheClientCanTakeIt(t *testing.T) {
	h, c, _ := newGuardHandler(t)

	const name = "roomy.internal.test."
	q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Put(q, bulkAnswer(t, name, 120))

	// The same records, to a client that advertised a 4096-byte buffer. Clipping this
	// one would cost a round trip on every large answer for no reason.
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.SetEdns0(4096, false)
	w := &captureWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}}

	h.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("nothing was written")
	}
	if w.msg.Truncated {
		t.Error("clipped an answer the client said it could receive")
	}
	if len(w.msg.Answer) != 120 {
		t.Errorf("answer carries %d records, want all 120", len(w.msg.Answer))
	}
}

func TestServeDoesNotClampAStreamTransport(t *testing.T) {
	h, c, _ := newGuardHandler(t)

	const name = "stream.internal.test."
	q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Put(q, bulkAnswer(t, name, 120))

	// No EDNS0, so the datagram path would clamp this to 512 bytes. Over TCP the
	// two-byte length prefix carries up to 64 KB, and clamping here would surface
	// only as clients retrying queries they had already been answered.
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	w := &captureWriter{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40003}}

	h.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("nothing was written")
	}
	if w.msg.Truncated || len(w.msg.Answer) != 120 {
		t.Errorf("TCP reply truncated=%v with %d of 120 records", w.msg.Truncated, len(w.msg.Answer))
	}
}

func TestHandlerDoesNotLeakTheRealHostOverAAAA(t *testing.T) {
	h, _, m := newGuardHandler(t)
	m.SetCustomRules(nil, []string{"ads.internal.test"}, nil,
		map[string]string{"pin.internal.test": "203.0.113.77"})

	cases := []struct {
		name    string
		qname   string
		qtype   uint16
		wantIPs []string
	}{
		// A pinned record that intercepted A only would send a client that prefers
		// IPv6 straight to the real host, which is the one thing pinning prevents.
		{"pinned record over A", "pin.internal.test.", dns.TypeA, []string{"203.0.113.77"}},
		{"pinned record over AAAA", "pin.internal.test.", dns.TypeAAAA, nil},

		// A proxied name must resolve to this server over A and to nothing over AAAA,
		// or the client's own address selection prefers the real IPv6 address and the
		// relay — the entire point of the rule — is bypassed.
		{"proxied name over A", "playvalorant.com.", dns.TypeA, []string{"198.51.100.1"}},
		{"proxied name over AAAA", "playvalorant.com.", dns.TypeAAAA, nil},

		// A sinkholed name answers 0.0.0.0 over A and empty over AAAA. An AAAA that
		// fell through to the upstream would resolve a name the operator blocked.
		{"blocked name over A", "ads.internal.test.", dns.TypeA, []string{"0.0.0.0"}},
		{"blocked name over AAAA", "ads.internal.test.", dns.TypeAAAA, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tc.qname, tc.qtype)

			resp := h.ProcessQuery(req, "127.0.0.1", "UDP")
			if resp == nil {
				t.Fatal("no reply")
			}
			// NOERROR with an empty answer is the reply that keeps a client on IPv4.
			// An error rcode teaches the stub to ask its next resolver instead.
			if resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
			}
			if got := answerIPs(resp); !slices.Equal(got, tc.wantIPs) {
				t.Errorf("answers = %v, want %v", got, tc.wantIPs)
			}
		})
	}
}

// strictAccess is a server with subscribers configured and allow_all switched off:
// an address matching no account has no business receiving an answer.
type strictAccess struct{}

func (s *strictAccess) IsIPAllowed(string) (*database.Client, bool) { return nil, false }

func (s *strictAccess) IsAllowAll() bool { return false }

func TestHandlerRefusesAnUnrecognisedSourceWhenAllowAllIsOff(t *testing.T) {
	c := cache.NewCache(1000, 60, 3600)
	defer c.Close()
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"192.0.2.1:53"}, 200*time.Millisecond, true, "")
	h := NewHandler(&strictAccess{}, c, m, u, nil, "198.51.100.1")

	// A proxied name, so a reply of any kind would mean the access check was skipped
	// and the rule engine ran for a stranger.
	req := new(dns.Msg)
	req.SetQuestion("playvalorant.com.", dns.TypeA)

	resp := h.ProcessQuery(req, "203.0.113.99", "UDP")
	if resp == nil {
		t.Fatal("no reply at all; this is the check that keeps the resolver from being open")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("refusal carried %d answers", len(resp.Answer))
	}
}

// TestRefusalCarriesProhibitedEDEForOptQueries: a client that sent OPT must
// learn WHY it was refused (RFC 8914 "Prohibited" — the address is not
// registered), while a plain query still sees the bare REFUSED it always saw,
// because a reply may never introduce an OPT record the query did not carry.
func TestRefusalCarriesProhibitedEDEForOptQueries(t *testing.T) {
	c := cache.NewCache(1000, 60, 3600)
	defer c.Close()
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"192.0.2.1:53"}, 200*time.Millisecond, true, "")
	h := NewHandler(&strictAccess{}, c, m, u, nil, "198.51.100.1")

	req := new(dns.Msg)
	req.SetQuestion("playvalorant.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	resp := h.ProcessQuery(req, "203.0.113.99", "UDP")
	if resp == nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("OPT query was not refused: %v", resp)
	}
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("reply lost the OPT record the query carried (RFC 6891 forbids dropping it here)")
	}
	var ede *dns.EDNS0_EDE
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			ede = e
		}
	}
	if ede == nil {
		t.Fatal("refusal to an OPT client carried no Extended DNS Error — the client cannot tell 'not registered' from any other refusal")
	}
	if ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("EDE info code = %d, want Prohibited (%d)", ede.InfoCode, dns.ExtendedErrorCodeProhibited)
	}
	if ede.ExtraText == "" {
		t.Error("EDE carried no human-readable text")
	}

	// The plain-query half: no OPT in, no OPT out.
	plain := new(dns.Msg)
	plain.SetQuestion("playvalorant.com.", dns.TypeA)
	plainResp := h.ProcessQuery(plain, "203.0.113.99", "UDP")
	if plainResp == nil || plainResp.Rcode != dns.RcodeRefused {
		t.Fatalf("plain query was not refused: %v", plainResp)
	}
	if plainResp.IsEdns0() != nil {
		t.Error("plain query was answered with an OPT record it never sent (RFC 6891 §6.1.1)")
	}
}

// TestOtherRefusalsDoNotClaimProhibited: quota and rate-limit refusals have
// different causes; labelling them "Prohibited" would misstate both.
func TestOtherRefusalsDoNotClaimProhibited(t *testing.T) {
	c := cache.NewCache(1000, 60, 3600)
	defer c.Close()
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"192.0.2.1:53"}, 200*time.Millisecond, true, "")
	// A recognised client with a spent allowance — quotaAccess implements the
	// optional QuotaEnforcer the handler resolves off the access provider.
	h := NewHandler(&quotaAccess{client: &database.Client{ID: "c1", Name: "Metered"}, exceeded: true}, c, m, u, nil, "198.51.100.1")
	if h.quota == nil {
		t.Fatal("NewHandler did not pick up the QuotaEnforcer the access provider implements")
	}

	req := new(dns.Msg)
	req.SetQuestion("playvalorant.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	resp := h.ProcessQuery(req, "203.0.113.7", "TCP")
	if resp == nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("quota query was not refused: %v", resp)
	}
	if opt := resp.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_EDE); ok && e.InfoCode == dns.ExtendedErrorCodeProhibited {
				t.Error("quota refusal was labelled Prohibited — the client paid, its allowance is spent; that is a different cause")
			}
		}
	}
}
