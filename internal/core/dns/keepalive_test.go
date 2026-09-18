package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// queryAsking builds a query that carries a client-side edns-tcp-keepalive
// option: zero-length, which is how RFC 7828 says a client asks without
// proposing a number of its own.
func queryAsking(do bool) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("store.steampowered.com.", dns.TypeA)
	req.SetEdns0(dns.DefaultMsgSize, do)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE})
	return req
}

// keepaliveIn returns the timeout the response advertises, and whether the option
// is there at all.
func keepaliveIn(t *testing.T, msg *dns.Msg) (uint16, bool) {
	t.Helper()
	opt := msg.IsEdns0()
	if opt == nil {
		return 0, false
	}
	var found *dns.EDNS0_TCP_KEEPALIVE
	for _, o := range opt.Option {
		ka, ok := o.(*dns.EDNS0_TCP_KEEPALIVE)
		if !ok {
			continue
		}
		if found != nil {
			t.Fatal("response carries two edns-tcp-keepalive options; a client reading the first would be told one thing and a client reading the last another")
		}
		found = ka
	}
	if found == nil {
		return 0, false
	}
	return found.Timeout, true
}

func TestKeepaliveIsSentOnlyToClientsThatAskedOverAStreamTransport(t *testing.T) {
	cases := []struct {
		name  string
		proto string
		req   *dns.Msg
		want  uint16
	}{
		{"TCP asked", "TCP", queryAsking(false), keepaliveUnits(tcpIdleTimeout)},
		{"DoT asked", "DoT", queryAsking(false), keepaliveUnits(dotIdleTimeout)},
		// RFC 7828 §3.3 forbids the option over UDP: there is no connection to
		// hold open, and the reply can be aimed at a spoofed source.
		{"UDP asked", "UDP", queryAsking(false), 0},
		// DoH keeps its connection alive at the HTTP layer, so the DNS-level
		// option would be advice about a lifetime this code does not control.
		{"DoH asked", "DoH", queryAsking(false), 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := new(dns.Msg)
			resp.SetReply(tc.req)

			attachTCPKeepalive(resp, tc.req, tc.proto)

			got, present := keepaliveIn(t, resp)
			if tc.want == 0 {
				if present {
					t.Fatalf("%s: sent a keepalive of %d units where none is allowed", tc.proto, got)
				}
				return
			}
			if !present {
				t.Fatalf("%s: no keepalive option, so the client is left guessing how long it may hold the connection", tc.proto)
			}
			if got != tc.want {
				t.Errorf("%s: advertised %d units, want %d", tc.proto, got, tc.want)
			}
		})
	}
}

func TestKeepaliveIsNotVolunteeredToAClientThatDidNotAsk(t *testing.T) {
	// Plain EDNS0, no keepalive option: an older stub that has no idea what the
	// option means, and should not be handed one.
	req := new(dns.Msg)
	req.SetQuestion("cm.steampowered.com.", dns.TypeA)
	req.SetEdns0(dns.DefaultMsgSize, false)

	resp := new(dns.Msg)
	resp.SetReply(req)
	attachTCPKeepalive(resp, req, "DoT")

	if units, present := keepaliveIn(t, resp); present {
		t.Errorf("advertised %d units to a client that never asked", units)
	}
}

func TestKeepaliveLeavesANonEDNSQueryAlone(t *testing.T) {
	// No OPT at all. RFC 6891 §6.1.1 forbids an OPT in the reply to such a query,
	// and a bare-DNS client that gets one may treat the answer as malformed.
	req := new(dns.Msg)
	req.SetQuestion("riotgames.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	attachTCPKeepalive(resp, req, "TCP")

	if resp.IsEdns0() != nil {
		t.Error("added an OPT record to the reply to a query that carried none")
	}
}

func TestKeepaliveAddsTheOPTACachedAnswerLacks(t *testing.T) {
	// The answer comes back from cache stripped of its OPT, but the query asked
	// for keepalive, so the reply is allowed to carry one — and has to, or the
	// option has nowhere to go.
	req := queryAsking(true)
	resp := new(dns.Msg)
	resp.SetReply(req)

	attachTCPKeepalive(resp, req, "DoT")

	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT record was added, so the keepalive was silently dropped")
	}
	if !opt.Do() {
		t.Error("DO bit not carried over from the query; a validating client would stop asking this resolver for DNSSEC records")
	}
	if units, present := keepaliveIn(t, resp); !present || units != keepaliveUnits(dotIdleTimeout) {
		t.Errorf("keepalive = %d units (present=%v), want %d", units, present, keepaliveUnits(dotIdleTimeout))
	}
}

func TestKeepaliveReplacesAValueAlreadyInTheReply(t *testing.T) {
	// An upstream's own keepalive advice must not survive into our reply: it
	// describes how long *that* server holds a connection, not how long this one
	// does, and appending ours next to it leaves the client two answers.
	req := queryAsking(false)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.SetEdns0(dns.DefaultMsgSize, false)
	opt := resp.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: 12},
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "6162"},
	)

	attachTCPKeepalive(resp, req, "TCP")

	units, present := keepaliveIn(t, resp)
	if !present {
		t.Fatal("keepalive option disappeared")
	}
	if units != keepaliveUnits(tcpIdleTimeout) {
		t.Errorf("advertised %d units, want %d — the upstream's value was passed through", units, keepaliveUnits(tcpIdleTimeout))
	}
	if len(opt.Option) != 2 {
		t.Errorf("OPT carries %d options, want 2 — the unrelated NSID option must survive", len(opt.Option))
	}
}

func TestKeepaliveUnitsAreHundredsOfMilliseconds(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want uint16
	}{
		{30 * time.Second, 300},
		{60 * time.Second, 600},
		{100 * time.Millisecond, 1},
		// Zero from a server means "close the connection now", the opposite of
		// what this option is being sent to say, so it is never emitted.
		{0, 1},
		{-5 * time.Second, 1},
		{50 * time.Millisecond, 1},
		// The field is a uint16 of 100ms units, so anything past 6553.5s saturates
		// rather than wrapping to a tiny timeout.
		{2 * time.Hour, 65535},
	}
	for _, tc := range cases {
		if got := keepaliveUnits(tc.in); got != tc.want {
			t.Errorf("keepaliveUnits(%s) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestKeepaliveHandlesNilMessages(t *testing.T) {
	// serve() only calls this with a non-nil pair, but a panic in the response
	// path takes down the connection, so the guard is cheap insurance.
	attachTCPKeepalive(nil, queryAsking(false), "TCP")
	attachTCPKeepalive(new(dns.Msg), nil, "TCP")
}
