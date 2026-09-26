package upstream

// The pool decides which resolver's answer a client actually receives. On a
// filtered network the fastest upstream is usually the ISP's, and the ISP's reply
// for the domains this project exists to reach is REFUSED or SERVFAIL — so
// "fastest wins" and "correct wins" are not the same rule, and the difference is
// whether a game launcher works.
//
// These tests run against real DNS servers on loopback (UDP and TCP on a shared
// port) rather than a mocked client, because the truncation retry, the context
// cancellation of losing upstreams, and the ECS attachment all live at the socket
// boundary.
//
// On the race detector: it is unavailable in this environment (no C compiler), so
// TestConcurrentExchangeDuringReload is a stress substitute. It can surface a
// panic or a torn read; it cannot certify the pool race-free.

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// probeName is the name the tests query. It is deliberately not cloudflare.com.,
// the name BenchmarkAll asks for: keeping them distinct means a reply function
// that stalls the test's query cannot also stall an explicit BenchmarkAll call.
const probeName = "probe.hyperdns.test."

// answer describes how a test resolver replies to one query.
type answer struct {
	rcode     int
	ip        string        // non-empty appends an A record
	truncated bool          // set TC=1 on the reply
	delay     time.Duration // stall before replying
	silent    bool          // stall, then send nothing at all

	// spoofName replaces the question's name in the reply while the answer section
	// still carries a record for the name that was asked — an upstream answering
	// something other than what it was asked, which is the shape both a confused
	// resolver and an off-path spoofer produce.
	spoofName string
	// spoofType replaces the question's type the same way.
	spoofType uint16
}

// always answers every name the same way.
func always(a answer) func(string) answer { return func(string) answer { return a } }

// forName answers qname with a and everything else (the constructor's own
// cloudflare.com. probe included) with an immediate NOERROR.
func forName(qname string, a answer) func(string) answer {
	return func(q string) answer {
		if q == qname {
			return a
		}
		return answer{rcode: dns.RcodeSuccess, ip: "127.0.0.1"}
	}
}

// testResolver is a DNS server on loopback answering on both UDP and TCP.
type testResolver struct {
	addr    string
	udpHits atomic.Int64
	tcpHits atomic.Int64
	udp     func(qname string) answer
	tcp     func(qname string) answer

	// lastID is the transaction ID of the most recent request the resolver saw.
	// The pool must query upstream under a fresh ID, never the client's, so a
	// test can assert this is not the ID the caller chose.
	lastID atomic.Uint32

	mu         sync.Mutex
	lastSubnet *dns.EDNS0_SUBNET
	sawEDNS    bool
}

// newTestResolver starts a resolver on a port shared by UDP and TCP. tcpReply may
// be nil, in which case TCP answers like UDP.
func newTestResolver(t *testing.T, udpReply, tcpReply func(string) answer) *testResolver {
	t.Helper()
	if udpReply == nil {
		udpReply = always(answer{rcode: dns.RcodeSuccess, ip: "127.0.0.1"})
	}
	if tcpReply == nil {
		tcpReply = udpReply
	}
	r := &testResolver{udp: udpReply, tcp: tcpReply}

	var (
		pc  net.PacketConn
		ln  net.Listener
		err error
	)
	// The two protocols must share a port number. Bind UDP first: the kernel's
	// ephemeral assignment respects UDP's own exclusions, so the starting port
	// is never inside a UDP-excluded block (on Windows, Hyper-V/WSL reserve
	// per-protocol chunks of the ephemeral range, and TCP's exclusion list is a
	// different one). Each miss closes the UDP socket and retries — on a box
	// with several excluded blocks, 64 attempts make the pair overwhelming.
	for range 64 {
		pc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			r.addr = ln.Addr().String()
			break
		}
		_ = pc.Close()
	}
	if r.addr == "" {
		t.Fatalf("could not bind a shared udp/tcp port: %v", err)
	}

	udpSrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(r.serveUDP)}
	tcpSrv := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(r.serveTCP)}
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
	})
	return r
}

func (r *testResolver) serveUDP(w dns.ResponseWriter, req *dns.Msg) {
	r.udpHits.Add(1)
	r.reply(w, req, r.udp)
}

func (r *testResolver) serveTCP(w dns.ResponseWriter, req *dns.Msg) {
	r.tcpHits.Add(1)
	r.reply(w, req, r.tcp)
}

func (r *testResolver) reply(w dns.ResponseWriter, req *dns.Msg, pick func(string) answer) {
	if len(req.Question) == 0 {
		return
	}
	r.lastID.Store(uint32(req.Id))
	qname := req.Question[0].Name

	if opt := req.IsEdns0(); opt != nil {
		r.mu.Lock()
		r.sawEDNS = true
		for _, o := range opt.Option {
			if sn, ok := o.(*dns.EDNS0_SUBNET); ok {
				r.lastSubnet = sn
			}
		}
		r.mu.Unlock()
	}

	a := pick(qname)
	if a.delay > 0 {
		time.Sleep(a.delay)
	}
	if a.silent {
		return
	}

	m := new(dns.Msg)
	m.SetRcode(req, a.rcode)
	m.Truncated = a.truncated
	if a.ip != "" {
		if rr, err := dns.NewRR(qname + " 30 IN A " + a.ip); err == nil {
			m.Answer = append(m.Answer, rr)
		}
	}
	// Rewritten after the answer is built, so the reply carries the right
	// transaction ID and a record for the asked name under a question that belongs
	// to something else. SetRcode copies the question into a fresh slice, so this
	// cannot reach back into the server's own request.
	if len(m.Question) == 1 {
		if a.spoofName != "" {
			m.Question[0].Name = a.spoofName
		}
		if a.spoofType != 0 {
			m.Question[0].Qtype = a.spoofType
		}
	}
	_ = w.WriteMsg(m)
}

func (r *testResolver) subnet() *dns.EDNS0_SUBNET {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastSubnet
}

// newTestPool builds a pool through the real constructor. It used to sleep 40ms
// here to outwait a probe NewUpstreamPool fired from a bare goroutine; the
// constructor no longer does network I/O, so there is nothing to wait for and a
// test that reads these stats is no longer racing anything.
func newTestPool(t *testing.T, addrs []string, timeout time.Duration, racing bool, ecsIP string) *UpstreamPool {
	t.Helper()
	return NewUpstreamPool(addrs, timeout, racing, ecsIP)
}

func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

// firstA returns the first A record's address, or "" when the reply carries none.
func firstA(resp *dns.Msg) string {
	if resp == nil {
		return ""
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func statFor(t *testing.T, p *UpstreamPool, addr string) UpstreamStat {
	t.Helper()
	for _, s := range p.GetUpstreamStats() {
		if s.Address == addr {
			return s
		}
	}
	t.Fatalf("no stats for upstream %s", addr)
	return UpstreamStat{}
}

func TestNormalizeUpstreams(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"bare ipv4 gains the default port", []string{"1.1.1.1"}, []string{"1.1.1.1:53"}},
		{"explicit port kept", []string{"9.9.9.9:5353"}, []string{"9.9.9.9:5353"}},
		{"hostname accepted", []string{"dns.google"}, []string{"dns.google:53"}},
		{"bare ipv6 is bracketed", []string{"2606:4700:4700::1111"}, []string{"[2606:4700:4700::1111]:53"}},
		{"bracketed ipv6 with port kept", []string{"[::1]:5300"}, []string{"[::1]:5300"}},
		{"whitespace trimmed", []string{"  8.8.8.8  "}, []string{"8.8.8.8:53"}},
		{"blank entries dropped", []string{"", "   ", "1.1.1.1"}, []string{"1.1.1.1:53"}},
		{
			// A bare IP and the same IP with :53 are the same resolver; keeping
			// both made the racer query it twice on every lookup.
			"bare and explicit forms deduplicate",
			[]string{"1.1.1.1", "1.1.1.1:53", "1.1.1.1"},
			[]string{"1.1.1.1:53"},
		},
		{"order preserved", []string{"1.1.1.1", "8.8.8.8"}, []string{"1.1.1.1:53", "8.8.8.8:53"}},
		{"port zero dropped", []string{"1.1.1.1:0"}, []string{}},
		{"port out of range dropped", []string{"1.1.1.1:70000"}, []string{}},
		{"non-numeric port dropped", []string{"1.1.1.1:domain"}, []string{}},
		{"missing host dropped", []string{":53"}, []string{}},
		{"missing port dropped", []string{"1.1.1.1:"}, []string{}},
		// These are the shapes a hand-edited config produces. Each one used to
		// survive normalization as a bracketed pseudo-host that then failed every
		// exchange, which reads on the dashboard as a dead resolver rather than a
		// bad config line.
		{"doubled port dropped", []string{"8.8.8.8:53:53"}, []string{}},
		{"space-separated pair dropped", []string{"1.1.1.1 8.8.8.8"}, []string{}},
		{"comma-separated pair dropped", []string{"1.1.1.1,8.8.8.8"}, []string{}},
		{"url form dropped", []string{"https://dns.google/dns-query"}, []string{}},
		{"underscore host kept", []string{"my_resolver.lan:53"}, []string{"my_resolver.lan:53"}},
		{"leading-dash label dropped", []string{"-bad.example:53"}, []string{}},
		{"empty label dropped", []string{"bad..example:53"}, []string{}},
		{"nil input", nil, []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeUpstreams(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeUpstreams(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizeUpstreams(%q) = %q, want %q", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestNewUpstreamPoolNormalizesAndSeeds(t *testing.T) {
	p := newTestPool(t, []string{" 1.1.1.1 ", "1.1.1.1:53", "garbage host", "8.8.8.8:53"}, 0, true, "")

	got := p.GetUpstreams()
	want := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("GetUpstreams() = %q, want %q", got, want)
	}

	// A zero or negative timeout must not become "no deadline at all", which would
	// hang a client until the socket gave up.
	if p.timeout != 2500*time.Millisecond {
		t.Fatalf("timeout = %v, want the 2500ms default for a non-positive input", p.timeout)
	}

	// Every upstream starts with a seeded estimate so the dashboard has something
	// to show before the first real query lands.
	for _, s := range p.GetUpstreamStats() {
		if s.LatencyNs <= 0 {
			t.Fatalf("upstream %s seeded with latency %d, want a positive estimate", s.Address, s.LatencyNs)
		}
	}

	// The returned slice is a copy: a caller sorting or truncating it must not
	// reach into the live pool.
	got[0] = "mutated"
	if again := p.GetUpstreams(); again[0] != "1.1.1.1:53" {
		t.Fatalf("GetUpstreams() returned the live slice; mutation leaked as %q", again[0])
	}
}

func TestExchangeRejectsUnusableInput(t *testing.T) {
	// Every entry is unusable, so normalization empties the list. The pool must
	// say so rather than block or panic.
	empty := newTestPool(t, []string{"", "   ", ":53", "1.1.1.1:0"}, time.Second, true, "")
	if _, _, _, err := empty.Exchange(query(probeName)); err == nil {
		t.Fatal("Exchange with no usable upstream returned no error")
	} else if !strings.Contains(err.Error(), "no upstream") {
		t.Fatalf("Exchange error = %q, want it to name the missing upstreams", err)
	}

	// A nil message reaches the pool if any caller ever forgets a guard; a
	// resolver that panics on one is a denial of service.
	res := newTestResolver(t, nil, nil)
	p := newTestPool(t, []string{res.addr}, time.Second, true, "")
	if _, _, _, err := p.Exchange(nil); err == nil {
		t.Fatal("Exchange(nil) returned no error")
	}
}

// TestRacingPrefersUsableAnswerOverFastRefusal is the case this pool exists for.
// The ISP resolver is the closest one and answers in microseconds — with REFUSED,
// because the name is filtered. The public resolver is 60ms away and answers
// properly. "First reply wins" hands the client the refusal and the game launcher
// fails; the pool must wait for the answer that is actually an answer.
func TestRacingPrefersUsableAnswerOverFastRefusal(t *testing.T) {
	fastRefuser := newTestResolver(t, always(answer{rcode: dns.RcodeRefused}), nil)
	slowAnswerer := newTestResolver(t, forName(probeName, answer{
		rcode: dns.RcodeSuccess,
		ip:    "203.0.113.7",
		delay: 60 * time.Millisecond,
	}), nil)

	p := newTestPool(t, []string{fastRefuser.addr, slowAnswerer.addr}, 2*time.Second, true, "")

	resp, _, addr, err := p.Exchange(query(probeName))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR — the fast REFUSED won the race", dns.RcodeToString[resp.Rcode])
	}
	if got := firstA(resp); got != "203.0.113.7" {
		t.Fatalf("answer = %q, want 203.0.113.7", got)
	}
	if addr != slowAnswerer.addr {
		t.Fatalf("winning upstream = %s, want the resolver that answered (%s)", addr, slowAnswerer.addr)
	}
}

// TestRacingReturnsUpstreamVerdictWhenAllRefuse — when nobody can answer, the
// client should get the upstreams' own verdict rather than a SERVFAIL the pool
// invented. A REFUSED that every resolver agrees on is information.
func TestRacingReturnsUpstreamVerdictWhenAllRefuse(t *testing.T) {
	a := newTestResolver(t, always(answer{rcode: dns.RcodeRefused}), nil)
	b := newTestResolver(t, always(answer{rcode: dns.RcodeServerFailure}), nil)

	p := newTestPool(t, []string{a.addr, b.addr}, time.Second, true, "")

	resp, _, _, err := p.Exchange(query(probeName))
	if err != nil {
		t.Fatalf("Exchange returned an error instead of the upstream's reply: %v", err)
	}
	if resp == nil {
		t.Fatal("Exchange returned no response and no error")
	}
	if resp.Rcode == dns.RcodeSuccess {
		t.Fatalf("rcode = NOERROR, want the upstreams' refusal to be passed through")
	}
}

// TestRacingAcceptsNXDOMAINImmediately — NXDOMAIN is an answer, not a failure.
// Retrying it elsewhere would double the cost of every typo and every game client
// probing names that do not exist.
func TestRacingAcceptsNXDOMAINImmediately(t *testing.T) {
	nx := newTestResolver(t, always(answer{rcode: dns.RcodeNameError}), nil)
	other := newTestResolver(t, forName(probeName, answer{
		rcode: dns.RcodeSuccess,
		ip:    "198.51.100.9",
		delay: 150 * time.Millisecond,
	}), nil)

	p := newTestPool(t, []string{nx.addr, other.addr}, 2*time.Second, true, "")

	start := time.Now()
	resp, _, addr, err := p.Exchange(query(probeName))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if addr != nx.addr {
		t.Fatalf("winning upstream = %s, want the NXDOMAIN resolver %s", addr, nx.addr)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("took %v — an NXDOMAIN was held back waiting for a slower upstream", elapsed)
	}
}

// TestSequentialSkipsRefusingUpstream — with racing off, a filtered resolver at
// the head of the list used to end the walk, so the working resolvers behind it
// were never tried at all.
func TestSequentialSkipsRefusingUpstream(t *testing.T) {
	refuser := newTestResolver(t, always(answer{rcode: dns.RcodeRefused}), nil)
	answerer := newTestResolver(t, forName(probeName, answer{rcode: dns.RcodeSuccess, ip: "203.0.113.8"}), nil)

	p := newTestPool(t, []string{refuser.addr, answerer.addr}, 2*time.Second, false, "")
	before := refuser.udpHits.Load()

	resp, _, addr, err := p.Exchange(query(probeName))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := firstA(resp); got != "203.0.113.8" {
		t.Fatalf("answer = %q, want 203.0.113.8 from the second upstream", got)
	}
	if addr != answerer.addr {
		t.Fatalf("answering upstream = %s, want %s", addr, answerer.addr)
	}
	// The first upstream is still tried first — the fix is that its refusal does
	// not end the walk, not that it is skipped.
	if delta := refuser.udpHits.Load() - before; delta != 1 {
		t.Fatalf("first upstream received %d queries, want exactly 1", delta)
	}
}

// TestSequentialStopsAtFirstUsableAnswer — the walk must not keep going once it
// has a real answer, or a two-upstream config would double every query.
func TestSequentialStopsAtFirstUsableAnswer(t *testing.T) {
	first := newTestResolver(t, forName(probeName, answer{rcode: dns.RcodeSuccess, ip: "192.0.2.10"}), nil)
	second := newTestResolver(t, nil, nil)

	p := newTestPool(t, []string{first.addr, second.addr}, 2*time.Second, false, "")
	before := second.udpHits.Load()

	if _, _, addr, err := p.Exchange(query(probeName)); err != nil || addr != first.addr {
		t.Fatalf("Exchange = (%s, %v), want the first upstream and no error", addr, err)
	}
	if delta := second.udpHits.Load() - before; delta != 0 {
		t.Fatalf("second upstream received %d queries after the first answered", delta)
	}
}

// TestTruncatedAnswerRetriesOverTCP — a clipped UDP reply must be re-asked over
// TCP. Without this a name with many A records (the CDN endpoints game launchers
// use) resolves to a partial set, and the client keeps retrying the few addresses
// it was given.
func TestTruncatedAnswerRetriesOverTCP(t *testing.T) {
	res := newTestResolver(t,
		always(answer{rcode: dns.RcodeSuccess, truncated: true}),
		always(answer{rcode: dns.RcodeSuccess, ip: "192.0.2.55"}),
	)

	p := newTestPool(t, []string{res.addr}, 2*time.Second, false, "")
	beforeTCP := res.tcpHits.Load()

	resp, _, _, err := p.Exchange(query(probeName))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := firstA(resp); got != "192.0.2.55" {
		t.Fatalf("answer = %q, want the full TCP answer 192.0.2.55", got)
	}
	if resp.Truncated {
		t.Fatal("returned reply is still flagged truncated")
	}
	if delta := res.tcpHits.Load() - beforeTCP; delta != 1 {
		t.Fatalf("TCP retries = %d, want exactly 1", delta)
	}
}

// TestLosingUpstreamIsNotChargedAnError — the winner cancels the others, and a
// cancelled query used to be recorded as that upstream's failure. With racing on
// and three resolvers, two errors were booked per lookup, so the dashboard's error
// column measured how often a resolver lost the race and the healthiest upstream
// looked the most broken.
func TestLosingUpstreamIsNotChargedAnError(t *testing.T) {
	fast := newTestResolver(t, forName(probeName, answer{rcode: dns.RcodeSuccess, ip: "192.0.2.1"}), nil)
	slow := newTestResolver(t, forName(probeName, answer{
		rcode: dns.RcodeSuccess,
		ip:    "192.0.2.2",
		delay: 400 * time.Millisecond,
	}), nil)

	p := newTestPool(t, []string{fast.addr, slow.addr}, 3*time.Second, true, "")
	baseline := statFor(t, p, slow.addr).Errors

	for range 5 {
		if _, _, addr, err := p.Exchange(query(probeName)); err != nil || addr != fast.addr {
			t.Fatalf("Exchange = (%s, %v), want the fast upstream and no error", addr, err)
		}
	}
	// Let the abandoned goroutines finish unwinding before reading the counters.
	time.Sleep(100 * time.Millisecond)

	if got := statFor(t, p, slow.addr).Errors; got != baseline {
		t.Fatalf("losing upstream errors = %d, want the pre-race %d — losing a race is not a failure", got, baseline)
	}
	if got := statFor(t, p, fast.addr).Hits; got == 0 {
		t.Fatal("winning upstream recorded no hits")
	}
}

// TestRefusalIsChargedAsAnError — a resolver that answers instantly with REFUSED
// is useless for that name, and the health column should say so. Latency alone
// would rank it first.
func TestRefusalIsChargedAsAnError(t *testing.T) {
	refuser := newTestResolver(t, always(answer{rcode: dns.RcodeRefused}), nil)

	p := newTestPool(t, []string{refuser.addr}, time.Second, false, "")
	baseline := statFor(t, p, refuser.addr).Errors

	if _, _, _, err := p.Exchange(query(probeName)); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := statFor(t, p, refuser.addr).Errors; got <= baseline {
		t.Fatalf("errors = %d, want more than the pre-query %d", got, baseline)
	}
}

func TestAttachECSMasksTheClientAddress(t *testing.T) {
	p := &UpstreamPool{}

	msg := query(probeName)
	p.attachECS(msg, net.ParseIP("203.0.113.45"))

	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("attachECS left the message without an OPT record")
	}
	var subnets []*dns.EDNS0_SUBNET
	for _, o := range opt.Option {
		if sn, ok := o.(*dns.EDNS0_SUBNET); ok {
			subnets = append(subnets, sn)
		}
	}
	if len(subnets) != 1 {
		t.Fatalf("found %d subnet options, want exactly 1", len(subnets))
	}
	sn := subnets[0]
	// The host octet must be gone. Sending 203.0.113.45 with a /24 source netmask
	// tells every upstream the exact machine that asked.
	if got := sn.Address.String(); got != "203.0.113.0" {
		t.Fatalf("ECS address = %s, want the masked 203.0.113.0", got)
	}
	if sn.SourceNetmask != 24 || sn.Family != 1 || sn.SourceScope != 0 {
		t.Fatalf("ECS = family %d /%d scope %d, want family 1 /24 scope 0", sn.Family, sn.SourceNetmask, sn.SourceScope)
	}

	// A second call replaces rather than appends: two subnet options in one query
	// is malformed and some resolvers drop the whole message.
	p.attachECS(msg, net.ParseIP("198.51.100.200"))
	count := 0
	for _, o := range msg.IsEdns0().Option {
		if sn, ok := o.(*dns.EDNS0_SUBNET); ok {
			count++
			if got := sn.Address.String(); got != "198.51.100.0" {
				t.Fatalf("ECS address = %s, want the replacement 198.51.100.0", got)
			}
		}
	}
	if count != 1 {
		t.Fatalf("after a second attach there are %d subnet options, want 1", count)
	}

	// IPv6 is masked to /56, which keeps the site prefix and drops the interface.
	v6 := query(probeName)
	p.attachECS(v6, net.ParseIP("2001:db8:abcd:ef01:2345:6789:abcd:ef01"))
	for _, o := range v6.IsEdns0().Option {
		if sn, ok := o.(*dns.EDNS0_SUBNET); ok {
			if sn.Family != 2 || sn.SourceNetmask != 56 {
				t.Fatalf("IPv6 ECS = family %d /%d, want family 2 /56", sn.Family, sn.SourceNetmask)
			}
			if got := sn.Address.String(); got != "2001:db8:abcd:ef00::" {
				t.Fatalf("IPv6 ECS address = %s, want 2001:db8:abcd:ef00::", got)
			}
		}
	}
}

// TestExchangeSendsECSWithoutMutatingTheCallersMessage — the handler reuses the
// request it passed in to build its reply and its cache key. Attaching the subnet
// option to that message instead of to a copy would leak an OPT record the client
// never sent into the answer it receives.
func TestExchangeSendsECSWithoutMutatingTheCallersMessage(t *testing.T) {
	res := newTestResolver(t, forName(probeName, answer{rcode: dns.RcodeSuccess, ip: "192.0.2.77"}), nil)
	p := newTestPool(t, []string{res.addr}, 2*time.Second, false, "")
	p.ecsClientIP = net.ParseIP("203.0.113.45")

	req := query(probeName)
	if _, _, _, err := p.Exchange(req); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if req.IsEdns0() != nil {
		t.Fatal("Exchange added an OPT record to the caller's message")
	}
	sn := res.subnet()
	if sn == nil {
		t.Fatal("upstream saw no ECS option")
	}
	if got := sn.Address.String(); got != "203.0.113.0" {
		t.Fatalf("upstream saw ECS %s, want the masked 203.0.113.0", got)
	}
}

// TestParseECSClientIPRejectsWhatNoUpstreamCanUse — the configured subnet is one
// value for the whole resolver, so a bad one is wrong for every query and, before
// this, wrong silently. An unparseable string used to disable the feature without a
// word, and a private address was forwarded to public resolvers that cannot
// possibly geolocate it. Both must come back nil, and the caller keeps resolving
// without ECS rather than failing.
func TestParseECSClientIPRejectsWhatNoUpstreamCanUse(t *testing.T) {
	usable := []string{"203.0.113.45", "2001:db8::1", "  198.51.100.7  "}
	for _, raw := range usable {
		if got := parseECSClientIP(raw); got == nil {
			t.Errorf("parseECSClientIP(%q) = nil, want the address kept", raw)
		}
	}

	unusable := []string{
		// Not configured, and three ways operators mistype the field: a name, an
		// upstream pasted in, and the CIDR the field looks like it wants.
		"", "not-an-ip", "203.0.113.45:53", "203.0.113.0/24",
		// Addresses no public resolver can locate. 192.168.1.10 is the likeliest
		// mistake — the operator's own LAN address, which reads like a client.
		"127.0.0.1", "10.0.0.1", "192.168.1.10", "172.16.4.4", "169.254.10.10",
		"0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fd00::1",
	}
	for _, raw := range unusable {
		if got := parseECSClientIP(raw); got != nil {
			t.Errorf("parseECSClientIP(%q) = %s, want nil — ECS must be disabled, not sent", raw, got)
		}
	}
}

// TestSetUpstreamsReplacesListAndPrunesStats — live reload from the dashboard.
// Stats for a removed resolver must go with it, or the upstream table keeps
// showing rows the pool no longer queries.
func TestSetUpstreamsReplacesListAndPrunesStats(t *testing.T) {
	a := newTestResolver(t, nil, nil)
	b := newTestResolver(t, nil, nil)

	p := newTestPool(t, []string{a.addr}, time.Second, false, "")
	if _, _, _, err := p.Exchange(query(probeName)); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	hitsBefore := statFor(t, p, a.addr).Hits
	if hitsBefore == 0 {
		t.Fatal("no hits recorded for the only upstream")
	}

	// Keep a, add b, and hand in a duplicate and a blank to be normalized away.
	p.SetUpstreams([]string{a.addr, b.addr, b.addr, "  "})
	if got := p.GetUpstreams(); len(got) != 2 {
		t.Fatalf("GetUpstreams() = %q, want 2 entries", got)
	}
	// A surviving upstream keeps its history — it is the same resolver.
	if got := statFor(t, p, a.addr).Hits; got != hitsBefore {
		t.Fatalf("hits for the retained upstream = %d, want the earlier %d", got, hitsBefore)
	}

	p.SetUpstreams([]string{b.addr})
	stats := p.GetUpstreamStats()
	if len(stats) != 1 || stats[0].Address != b.addr {
		t.Fatalf("GetUpstreamStats() = %+v, want only %s", stats, b.addr)
	}
	if _, ok := p.stats[a.addr]; ok {
		t.Fatal("stats for the removed upstream were kept")
	}
}

// TestUpstreamStatsOrderIsStable — right after a restart every upstream carries
// the same seeded estimate, and an unstable sort made the dashboard's resolver
// list reshuffle on every poll.
func TestUpstreamStatsOrderIsStable(t *testing.T) {
	p := newTestPool(t, []string{"9.9.9.9:53", "1.1.1.1:53", "8.8.8.8:53"}, time.Second, false, "")

	first := p.GetUpstreamStats()
	for range 5 {
		next := p.GetUpstreamStats()
		if len(next) != len(first) {
			t.Fatalf("stat count changed between calls: %d then %d", len(first), len(next))
		}
		for i := range next {
			if next[i].Address != first[i].Address {
				t.Fatalf("order changed at %d: %s then %s", i, first[i].Address, next[i].Address)
			}
		}
	}
	// Equal latencies fall back to the address, so the order is defined rather
	// than merely repeatable within one process.
	for i := 1; i < len(first); i++ {
		if first[i-1].LatencyNs == first[i].LatencyNs && first[i-1].Address > first[i].Address {
			t.Fatalf("equal latencies not ordered by address: %s before %s", first[i-1].Address, first[i].Address)
		}
	}
	// The exported latency is reported twice, in nanoseconds and milliseconds; the
	// dashboard reads one and the TUI the other.
	for _, s := range first {
		if want := float64(s.LatencyNs) / 1e6; s.LatencyMs != want {
			t.Fatalf("%s: LatencyMs = %v, want %v", s.Address, s.LatencyMs, want)
		}
	}
}

// TestExchangeTimesOutWithinBudget — a silent upstream must not hold a client past
// the configured deadline, and the whole sequential walk shares that one budget.
func TestExchangeTimesOutWithinBudget(t *testing.T) {
	blackhole := newTestResolver(t, forName(probeName, answer{silent: true, delay: time.Second}), nil)
	other := newTestResolver(t, forName(probeName, answer{silent: true, delay: time.Second}), nil)

	const budget = 200 * time.Millisecond
	p := newTestPool(t, []string{blackhole.addr, other.addr}, budget, false, "")

	start := time.Now()
	_, _, _, err := p.Exchange(query(probeName))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Exchange against two silent upstreams returned no error")
	}
	// Two upstreams, one shared deadline: the walk must not cost 2 × budget.
	if elapsed > 2*budget {
		t.Fatalf("took %v with a %v budget — the deadline is not shared across the walk", elapsed, budget)
	}
}

// TestConcurrentExchangeDuringReload is the stress substitute for the race
// detector, which cannot run in this environment (no C compiler). Queries, stat
// reads and a live upstream swap all run at once: a torn read or a lock-order
// mistake shows up as a panic or a hang, but a clean run does NOT certify the pool
// race-free.
func TestConcurrentExchangeDuringReload(t *testing.T) {
	a := newTestResolver(t, nil, nil)
	b := newTestResolver(t, nil, nil)

	p := newTestPool(t, []string{a.addr, b.addr}, time.Second, true, "")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _, _, _ = p.Exchange(query(probeName))
				_ = p.GetUpstreamStats()
				_ = p.GetUpstreams()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		lists := [][]string{{a.addr}, {a.addr, b.addr}, {b.addr}}
		for i := range 300 {
			p.SetUpstreams(lists[i%len(lists)])
		}
	}()

	// The writer finishes on its own; the readers run until told to stop.
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// A reply is correlated to a query by transaction ID alone — that is all
// miekg/dns checks, and all an off-path attacker has to guess alongside the source
// port. usableRcode then looks only at the rcode. So the question section is the
// last thing standing between "an upstream sent us something" and "this is the
// answer to what we asked", and the handler puts whatever comes back into the
// cache under the *client's* question, where every later client is served it too.
// These tests pin that a reply which answers something else is treated as an
// upstream failure: not returned, not cached, and not counted as that resolver
// working.

// TestUpstreamGetsFreshTransactionID locks in the RFC 5452 defense: the pool
// must query upstream under a fresh transaction ID rather than forwarding the
// client's chosen one (which would let a client, or an off-path spoofer who
// learned it, predict the ID and blind-spray a forged reply to poison the shared
// cache). The client's ID must still come back on the reply, and the caller's
// message must not be mutated.
func TestUpstreamGetsFreshTransactionID(t *testing.T) {
	r := newTestResolver(t, always(answer{rcode: dns.RcodeSuccess, ip: "127.0.0.1"}), nil)
	p := newTestPool(t, []string{r.addr}, time.Second, false, "")

	const clientID = 0x1234
	seen := map[uint16]struct{}{}
	for range 16 {
		m := new(dns.Msg)
		m.SetQuestion(probeName, dns.TypeA)
		m.Id = clientID

		resp, _, _, err := p.Exchange(m)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if resp == nil || resp.Id != clientID {
			t.Fatalf("the reply handed back to the client must carry its own ID 0x%04x", clientID)
		}
		if m.Id != clientID {
			t.Fatalf("Exchange mutated the caller's message ID to 0x%04x; it must copy, not mutate", m.Id)
		}
		seen[uint16(r.lastID.Load())] = struct{}{}
	}
	// Forwarding the client ID verbatim would make every upstream query carry
	// 0x1234, so the set of observed IDs would be exactly {0x1234}. A fresh
	// per-exchange ID yields many distinct values.
	if len(seen) <= 1 {
		t.Fatalf("upstream saw a single transaction ID across 16 exchanges (%v); the ID must be regenerated per exchange", seen)
	}
}

func TestUpstreamReplyForAnotherQuestionIsNeverReturned(t *testing.T) {
	// The reply carries an A record for the name that was asked, under a question
	// that belongs to a different name. Believing it caches the attacker's address
	// for auth.riotgames.com.
	spoofer := newTestResolver(t, forName(probeName, answer{
		rcode:     dns.RcodeSuccess,
		ip:        "198.51.100.66",
		spoofName: "attacker.example.",
	}), nil)

	p := newTestPool(t, []string{spoofer.addr}, time.Second, false, "")

	resp, _, _, err := p.Exchange(query(probeName))
	if err == nil {
		t.Fatalf("the mismatched reply was accepted: %v", resp)
	}
	if !errors.Is(err, ErrQuestionMismatch) {
		t.Errorf("error = %v, want ErrQuestionMismatch", err)
	}
	if resp != nil {
		t.Errorf("a message was returned alongside the error: %v", resp)
	}
	// The operator has to be able to see which resolver did this, and both names
	// have to be in the line to tell a spoof from a plain mix-up.
	for _, want := range []string{spoofer.addr, probeName, "attacker.example."} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestRacingIgnoresTheMismatchedReplyAndTakesTheRealAnswer is the poisoning race
// as it actually plays out: whoever answers first wins, so the forged reply is
// built to arrive first. The real resolver is 60ms behind it and its answer is the
// one the client must get.
func TestRacingIgnoresTheMismatchedReplyAndTakesTheRealAnswer(t *testing.T) {
	spoofer := newTestResolver(t, forName(probeName, answer{
		rcode:     dns.RcodeSuccess,
		ip:        "198.51.100.66",
		spoofName: "attacker.example.",
	}), nil)
	honest := newTestResolver(t, forName(probeName, answer{
		rcode: dns.RcodeSuccess,
		ip:    "203.0.113.7",
		delay: 60 * time.Millisecond,
	}), nil)

	p := newTestPool(t, []string{spoofer.addr, honest.addr}, 2*time.Second, true, "")

	resp, _, addr, err := p.Exchange(query(probeName))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := firstA(resp); got != "203.0.113.7" {
		t.Fatalf("answer = %q, want 203.0.113.7 — the forged reply won the race", got)
	}
	if addr != honest.addr {
		t.Errorf("winning upstream = %s, want the honest resolver %s", addr, honest.addr)
	}
	// A mismatched reply must not be held as the fallback either: falling back to it
	// when no upstream does better would cache it anyway, just more slowly.
	if len(resp.Question) != 1 || !strings.EqualFold(resp.Question[0].Name, probeName) {
		t.Errorf("returned question = %v, want %s", resp.Question, probeName)
	}
}

// TestSequentialMovesOnFromAWrongAnswerAndCountsItAgainstTheUpstream — with racing
// off the walk has to continue past the bad reply, and the resolver that sent it
// has to look broken on the dashboard rather than fast.
func TestSequentialMovesOnFromAWrongAnswerAndCountsItAgainstTheUpstream(t *testing.T) {
	spoofer := newTestResolver(t, forName(probeName, answer{
		rcode:     dns.RcodeSuccess,
		ip:        "198.51.100.66",
		spoofType: dns.TypeTXT,
	}), nil)
	honest := newTestResolver(t, forName(probeName, answer{rcode: dns.RcodeSuccess, ip: "203.0.113.8"}), nil)

	p := newTestPool(t, []string{spoofer.addr, honest.addr}, 2*time.Second, false, "")
	baseline := statFor(t, p, spoofer.addr).Errors

	resp, _, addr, err := p.Exchange(query(probeName))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := firstA(resp); got != "203.0.113.8" {
		t.Fatalf("answer = %q, want 203.0.113.8 from the second upstream", got)
	}
	if addr != honest.addr {
		t.Errorf("answering upstream = %s, want %s", addr, honest.addr)
	}
	// An A query answered with a TXT question is the same failure as the wrong name:
	// the type is part of what was asked.
	if got := statFor(t, p, spoofer.addr).Errors; got <= baseline {
		t.Errorf("errors for the misanswering upstream = %d, want more than %d", got, baseline)
	}
}

// TestTruncatedRetryMustAlsoAnswerTheQuestion — the TCP retry used to return
// straight to the caller, so a check placed only on the UDP reply would leave the
// larger, more interesting message unvalidated. A resolver that answers TC=1 over
// UDP and then something else over TCP fails the upstream outright: the truncated
// reply is nearly useless to a client, and one that misanswers on TCP has not
// earned the benefit of the doubt.
func TestTruncatedRetryMustAlsoAnswerTheQuestion(t *testing.T) {
	res := newTestResolver(t,
		forName(probeName, answer{rcode: dns.RcodeSuccess, truncated: true}),
		forName(probeName, answer{rcode: dns.RcodeSuccess, ip: "198.51.100.66", spoofName: "attacker.example."}),
	)

	p := newTestPool(t, []string{res.addr}, 2*time.Second, false, "")

	resp, _, _, err := p.Exchange(query(probeName))
	if !errors.Is(err, ErrQuestionMismatch) {
		t.Fatalf("error = %v, want ErrQuestionMismatch; reply: %v", err, resp)
	}
	if res.tcpHits.Load() == 0 {
		t.Error("the TCP retry never happened, so this test proved nothing")
	}
}

// question builds a message carrying exactly the questions given, without the
// helpers that would normalise them.
func question(qs ...dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.Question = qs
	return m
}

func TestAnswersTheQuestion(t *testing.T) {
	asked := dns.Question{Name: "auth.riotgames.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	req := question(asked)

	echoed := func(mutate func(*dns.Question)) *dns.Msg {
		q := asked
		mutate(&q)
		return question(q)
	}

	cases := map[string]struct {
		req  *dns.Msg
		resp *dns.Msg
		want bool
	}{
		"the question echoed back": {req, question(asked), true},

		// RFC 4343: names compare case-insensitively. A byte comparison would break an
		// upstream that echoes the name in another case, and would defeat 0x20-encoding
		// — the anti-spoofing trick of randomising that case deliberately.
		"the same name in another case": {
			req,
			echoed(func(q *dns.Question) { q.Name = "AuTh.RiotGames.CoM." }),
			true,
		},

		"a different name":  {req, echoed(func(q *dns.Question) { q.Name = "attacker.example." }), false},
		"a different type":  {req, echoed(func(q *dns.Question) { q.Qtype = dns.TypeTXT }), false},
		"a different class": {req, echoed(func(q *dns.Question) { q.Qclass = dns.ClassCHAOS }), false},

		// A reply with no question cannot be correlated at all, and one with two
		// questions is a message this resolver never sent: it forwards a single
		// question, having already refused anything else at the front door.
		"no question at all": {req, question(), false},
		"a second question":  {req, question(asked, asked), false},
		"no reply":           {req, nil, false},

		// Defensive. Every caller passes a single-question request, and these stay
		// false so that a future one which does not cannot get a reply waved through.
		"no request at all":     {nil, question(asked), false},
		"nothing was asked":     {question(), question(asked), false},
		"two things were asked": {question(asked, asked), question(asked), false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := answersTheQuestion(tc.req, tc.resp); got != tc.want {
				t.Errorf("answersTheQuestion = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQuestionSummaryNamesWhatThereIsToName(t *testing.T) {
	// This string is what the operator reads in the log when an upstream is dropped,
	// so the two empty shapes have to say something rather than render as blank.
	cases := map[string]struct {
		msg  *dns.Msg
		want string
	}{
		"a reply with a question": {
			question(dns.Question{Name: "auth.riotgames.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}),
			"auth.riotgames.com. A",
		},
		"a reply with none": {question(), "no question"},
		"no reply at all":   {nil, "no reply"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := questionSummary(tc.msg); got != tc.want {
				t.Errorf("questionSummary = %q, want %q", got, tc.want)
			}
		})
	}
}
