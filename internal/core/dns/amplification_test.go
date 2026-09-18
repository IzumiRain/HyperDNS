package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/database"
)

// An open resolver is worth something to an attacker for exactly one reason: the number
// of bytes it sends for each byte it receives. A 30-byte query that buys a 3 KB answer
// turns a 1 Gbps botnet into a 100 Gbps flood aimed at whatever source address the
// queries forged — and the abuse report goes to this resolver's operator, who never saw
// the traffic that left their own machine.
//
// guards_test.go pins the guards one at a time: ANY is refused (RFC 8482), a malformed
// shape is answered as malformed, an unrecognised source is refused when allow_all is
// off, a datagram is clamped to what the client said it can receive. This file measures
// the thing all of them exist to bound — the ratio itself, on the wire, in bytes.
//
// Nothing here reaches the network. Every reply measured is one the resolver composes on
// its own, without consulting an upstream.

// floodSource is the address the rate-limited case drains its bucket with. Deliberately
// not loopback, which the limiter exempts.
const floodSource = "203.0.113.66"

// wireLen is a message's length as it goes out, which is the only length a reflection
// attack cares about. Compression is left off — the package default — so a reply is
// measured pessimistically rather than in the way that flatters the resolver most.
func wireLen(t *testing.T, m *dns.Msg) int {
	t.Helper()
	buf, err := m.Pack()
	if err != nil {
		t.Fatalf("packing a message in order to measure it: %v", err)
	}
	return len(buf)
}

// compressedWireLen is the same measurement with name compression on, taken on a copy so
// the caller's message keeps the Compress setting it had.
//
// This is the length (*dns.Msg).Truncate decides against: it packs uncompressed first and
// leaves the message alone if that already fits, and only when it does not does it turn
// compression on and start dropping records. So a fixture that is oversized only
// uncompressed is not oversized at all as far as the clamp is concerned.
func compressedWireLen(t *testing.T, m *dns.Msg) int {
	t.Helper()
	c := m.Copy()
	c.Compress = true
	return wireLen(t, c)
}

// newPool is the unreachable upstream every handler here is given. The address is a
// documentation range rather than a resolver, so a case that falls through to the
// upstream step by mistake fails on a short timeout instead of quietly depending on
// whoever runs the suite having a working network.
func newPool() *upstream.UpstreamPool {
	return upstream.NewUpstreamPool([]string{"192.0.2.1:53"}, 200*time.Millisecond, true, "")
}

// guardHandler answers with the package's ordinary permissive access provider, which is
// what the ANY, FORMERR and NOTIMPL guards stand in front of.
func guardHandler(t *testing.T) *Handler {
	t.Helper()
	h, _, _ := newGuardHandler(t)
	return h
}

// strictHandler recognises nobody: allow_all is off and every source is unknown. This is
// the configuration an operator running a private resolver has, and the one where a
// forged source address must get nothing usable back.
func strictHandler(t *testing.T) *Handler {
	t.Helper()
	c := cache.NewCache(1000, 60, 3600)
	t.Cleanup(c.Close)
	return NewHandler(&strictAccess{}, c, matcher.NewMatcher(),
		newPool(), nil, "198.51.100.1")
}

// overQuotaHandler recognises the source and then refuses it on quota, which is a
// refusal composed one guard further in than the others.
func overQuotaHandler(t *testing.T) *Handler {
	t.Helper()
	access := &quotaAccess{client: &database.Client{ID: "spent", Name: "Spent"}, exceeded: true}
	c := cache.NewCache(1000, 60, 3600)
	t.Cleanup(c.Close)
	return NewHandler(access, c, matcher.NewMatcher(),
		newPool(), nil, "198.51.100.1")
}

// drainedLimiterHandler has floodSource's bucket already empty, so the next query from
// that address is refused by the limiter before any other guard sees it. The clock is
// fake, so nothing here depends on wall time.
func drainedLimiterHandler(t *testing.T) *Handler {
	t.Helper()
	h, _, _ := newGuardHandler(t)
	h.limiter = limiterAt(1, newFakeClock())

	for range minRateLimitBurst {
		h.limiter.allow(floodSource)
	}
	if h.limiter.allow(floodSource) {
		t.Fatalf("%s still has tokens after %d of them were spent, so this case would be "+
			"measuring an ordinary answer rather than a refusal", floodSource, minRateLimitBurst)
	}
	return h
}

// The queries. Each builder hands back a fresh message, since ProcessQuery is given the
// request and derives the reply from it.

// bareQuery is the cheapest thing an attacker can send: a header, one question, and no
// EDNS0 at all. It is the smallest denominator available, so a ratio measured against it
// is the worst case rather than a convenient one.
func bareQuery(name string, qtype uint16) func() *dns.Msg {
	return func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		return m
	}
}

// paddedQuery is the same question carrying a 400-byte EDNS0 padding option. SetReply
// copies the header flags and the question and nothing else, so a refusal must come back
// strictly smaller than this: the OPT record is not echoed, and neither is the padding.
// A handler that called SetEdns0 on its own refusals would fail here.
func paddedQuery(name string, qtype uint16) func() *dns.Msg {
	return func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		m.SetEdns0(4096, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 400)})
		return m
	}
}

// questionlessQuery is a bare 12-byte header, and the smallest thing this resolver can be
// asked anything by. The refusal it earns is a bare 12-byte header too.
func questionlessQuery() *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	return m
}

// twoQuestionQuery pays for two questions and is answered with one.
func twoQuestionQuery() *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.Question = []dns.Question{
		{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	return m
}

// updateQuery is a message a forwarder has no business acting on, answered NOTIMPL.
func updateQuery() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Opcode = dns.OpcodeUpdate
	return m
}

// requireNoAmplification is the whole measurement: a refusal must carry no records, and it
// must not be longer than the query that provoked it. The second half is the number an
// attacker cares about. A factor at or below 1.0 means forging this resolver's clients
// buys nothing over sending the packets directly, so there is no reason to pick it.
func requireNoAmplification(t *testing.T, req, resp *dns.Msg, wantRcode int) {
	t.Helper()
	if resp == nil {
		t.Fatal("no reply at all, so there is nothing to measure; this case is meant to be answered")
	}
	if resp.Rcode != wantRcode {
		t.Errorf("rcode = %s, want %s", rcodeOf(resp), dns.RcodeToString[wantRcode])
	}
	if n := len(resp.Answer) + len(resp.Ns) + len(resp.Extra); n != 0 {
		t.Errorf("the refusal carries %d record(s), and every one of them is a byte the attacker "+
			"did not have to send", n)
	}
	if resp.Id != req.Id {
		t.Errorf("reply id %d does not match the query's %d", resp.Id, req.Id)
	}

	in, out := wireLen(t, req), wireLen(t, resp)
	if out > in {
		t.Errorf("%d bytes in, %d bytes out — an amplification factor of %.2f. The source address on "+
			"a flood's queries is forged, so every byte above a ratio of 1.0 lands on somebody who "+
			"never sent anything, and the abuse report arrives here.", in, out, float64(out)/float64(in))
	}
}

// Every reply in this table is one the resolver writes without asking anyone: seven
// refusals reached by seven different guards. None of them may be larger than what it
// answers, or the guard that produced it has turned into a reflector with a rate limit.
func TestNoSelfComposedRefusalCanAmplify(t *testing.T) {
	cases := []struct {
		name    string
		handler func(*testing.T) *Handler
		req     func() *dns.Msg
		proto   string
		client  string
		rcode   int
	}{
		// RFC 8482's whole reason for existing: ANY is the largest reply the smallest
		// query can buy, so it is the query a reflection attack sends.
		{
			name:    "ANY",
			handler: guardHandler,
			req:     bareQuery("playvalorant.com.", dns.TypeANY),
			proto:   "UDP",
			client:  "203.0.113.10",
			rcode:   dns.RcodeRefused,
		},

		// The same question with 400 bytes of padding attached. Strictly smaller, because
		// the reply carries neither the OPT record nor the padding back.
		{
			name:    "ANY carrying 400 bytes of EDNS0 padding",
			handler: guardHandler,
			req:     paddedQuery("playvalorant.com.", dns.TypeANY),
			proto:   "UDP",
			client:  "203.0.113.11",
			rcode:   dns.RcodeRefused,
		},

		{
			name:    "no question section",
			handler: guardHandler,
			req:     questionlessQuery,
			proto:   "UDP",
			client:  "203.0.113.12",
			rcode:   dns.RcodeFormatError,
		},

		{
			name:    "two questions, answered with one",
			handler: guardHandler,
			req:     twoQuestionQuery,
			proto:   "UDP",
			client:  "203.0.113.13",
			rcode:   dns.RcodeFormatError,
		},

		{
			name:    "an opcode this resolver does not implement",
			handler: guardHandler,
			req:     updateQuery,
			proto:   "UDP",
			client:  "203.0.113.14",
			rcode:   dns.RcodeNotImplemented,
		},

		// The refusal that matters most to a stranger's resolver: allow_all is off and
		// this source is not on the list, so nothing is looked up on its behalf.
		{
			name:    "a source the operator never registered",
			handler: strictHandler,
			req:     bareQuery("playvalorant.com.", dns.TypeA),
			proto:   "UDP",
			client:  "203.0.113.99",
			rcode:   dns.RcodeRefused,
		},

		// A client the access provider does recognise, refused one guard further in.
		{
			name:    "a recognised client that has spent its quota",
			handler: overQuotaHandler,
			req:     bareQuery("playvalorant.com.", dns.TypeA),
			proto:   "UDP",
			client:  "203.0.113.55",
			rcode:   dns.RcodeRefused,
		},

		// Over the rate limit on a stream transport, where the limiter answers rather than
		// dropping, because the DoH bridge turns a nil into HTTP 500. A refusal is the right
		// answer there, and still must not be a larger packet than the request.
		{
			name:    "over the rate limit on a stream transport",
			handler: drainedLimiterHandler,
			req:     bareQuery("playvalorant.com.", dns.TypeA),
			proto:   "TCP",
			client:  floodSource,
			rcode:   dns.RcodeRefused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Measured at ProcessQuery rather than through serve(), because serve() adds an
			// edns-tcp-keepalive OPT record on stream transports — legitimately, since a
			// stream's source address cannot be forged and there is no reflection there to
			// bound. What is under test is the message the guards compose.
			h := tc.handler(t)
			req := tc.req()
			requireNoAmplification(t, req, h.ProcessQuery(req, tc.client, tc.proto), tc.rcode)
		})
	}
}

// ProcessQuery returning nil is one hop short of the wire, and that hop is where the
// property actually lives. A fallback write added to serve() for the nil case would leave
// ratelimit_test.go green and restore the reflector: a REFUSED datagram sent to a forged
// source is still a packet aimed at somebody who did not ask for it, and answering a
// flood at all is what makes the flood worth aiming here.
func TestARateLimitedUDPQueryPutsNothingOnTheWire(t *testing.T) {
	h := drainedLimiterHandler(t)

	req := new(dns.Msg)
	req.SetQuestion("playvalorant.com.", dns.TypeA)
	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP(floodSource), Port: 40010}}

	h.ServeDNS(w, req)

	if w.msg != nil {
		t.Errorf("a rate-limited datagram was answered with %s and %d record(s); over the limit on "+
			"UDP the only safe reply is no packet at all", rcodeOf(w.msg), len(w.msg.Answer))
	}
}

// guards_test.go pins udpSize's 4096-byte ceiling as arithmetic, but no test drives a
// reply larger than that through serve() with an advertisement above it — so deleting the
// min(size, 4096) would break nothing in the suite while letting a client ask to be sent
// 65 535 bytes for a 47-byte query. The ceiling is not about the client's buffer, which it
// is entitled to state; it is about what one forged query is allowed to cost a third
// party, and about staying inside an ordinary path MTU instead of being fragmented.
func TestAUDPReplyIsCappedAt4096HoweverMuchTheClientAdvertises(t *testing.T) {
	h, c, _ := newGuardHandler(t)

	const name = "flood.internal.test."
	q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}

	// Seeded, because the cache is the only way to hand serve() a large reply without an
	// upstream. 400 A records for this name, drawn from bulkAnswer's documentation ranges.
	seed := bulkAnswer(t, name, 400)

	// The precondition, asserted rather than assumed: an answer that was already inside the
	// ceiling would let this test pass whether or not the ceiling existed.
	//
	// Both lengths are checked because Truncate measures twice, and only the second
	// measurement decides whether a record is dropped. Every record here repeats one owner
	// name, so compression replaces that name with a 2-byte pointer and the reply shrinks to
	// roughly a fifth: 250 records clear 4096 uncompressed but pack into ~4.05 KB
	// compressed, which is inside the ceiling — Truncate then fits the whole set, drops
	// nothing, and correctly leaves TC clear, so the assertion below failed against a
	// resolver that was behaving exactly as intended.
	if n := wireLen(t, seed); n <= 4096 {
		t.Fatalf("the seeded answer is %d bytes, already inside the 4096-byte ceiling, so nothing "+
			"here would be clamped and the test would prove nothing", n)
	}
	if n := compressedWireLen(t, seed); n <= 4096 {
		t.Fatalf("the seeded answer compresses to %d bytes, inside the 4096-byte ceiling, so "+
			"Truncate fits it whole and drops nothing — raise the record count in bulkAnswer's "+
			"caller until the compressed length exceeds the ceiling too", n)
	}
	c.Put(q, seed)

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.SetEdns0(65535, false) // the largest buffer a client can claim to have
	w := &captureWriter{remote: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 40011}}

	h.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("nothing was written")
	}
	if out := wireLen(t, w.msg); out > 4096 {
		t.Errorf("wrote %d bytes to a client that advertised 65535 — a factor of %.0f on a %d-byte "+
			"query, and a datagram that fragments on any ordinary path", out,
			float64(out)/float64(wireLen(t, req)), wireLen(t, req))
	}
	if !w.msg.Truncated {
		t.Error("TC bit unset on a clipped answer, so the client has no reason to retry over TCP")
	}
	if len(w.msg.Answer) == 0 {
		t.Error("clamped to nothing; a partial answer with TC set is what a stub can act on")
	}
	// The other side of the TC assertion: the bit has to be set because records were left
	// out, not because something set it on a reply that was sent whole.
	if len(w.msg.Answer) >= 400 {
		t.Errorf("answer still carries %d records, so the ceiling dropped none of them",
			len(w.msg.Answer))
	}
}

// maxAnsweredOverhead is the budget a reply the resolver composes itself is allowed to add
// to the query it answers. One A record costs the owner name again — the same name the
// question already carried — plus a 10-byte record header and 4 bytes of address, and 64
// leaves room for that and an OPT record besides.
const maxAnsweredOverhead = 64

// The three paths this resolver answers on its own instead of refusing: a sinkholed name,
// a pinned record, and a proxied name. Each is one A record, so none of them is any use as
// the large end of a reflection — and a path that started answering with a set instead of a
// single record would be the first place that changed. The bound is stated in bytes rather
// than as a ratio because bytes are what the resolver controls; the ratio that follows from
// it is under 3 for any name a client can put in a question.
func TestAnAnsweredNameCarriesAtMostOneRecord(t *testing.T) {
	h, _, m := newGuardHandler(t)
	m.SetCustomRules(nil, []string{"ads.internal.test"}, nil,
		map[string]string{"pin.internal.test": "203.0.113.77"})

	for _, name := range []string{"ads.internal.test.", "pin.internal.test.", "playvalorant.com."} {
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)

		resp := h.ProcessQuery(req, "203.0.113.20", "UDP")
		if resp == nil {
			t.Fatalf("%s: no reply, and this name is one the resolver answers", name)
		}
		if n := len(resp.Answer); n > 1 {
			t.Errorf("%s: %d records in the answer section, want at most 1", name, n)
		}
		if n := len(resp.Ns) + len(resp.Extra); n != 0 {
			t.Errorf("%s: %d record(s) in the authority and additional sections, which this "+
				"resolver has no reason to send and an attacker would be paying nothing for", name, n)
		}

		in, out := wireLen(t, req), wireLen(t, resp)
		if out-in > maxAnsweredOverhead {
			t.Errorf("%s: %d bytes in, %d bytes out — %d bytes added for what should be a single A "+
				"record, an amplification factor of %.2f", name, in, out, out-in, float64(out)/float64(in))
		}
	}
}
