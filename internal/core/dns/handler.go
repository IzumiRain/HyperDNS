package dns

import (
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/database"
)

type AccessProvider interface {
	IsIPAllowed(ip string) (*database.Client, bool)
	IsAllowAll() bool
}

type TelemetrySink interface {
	PushQueryLog(item database.QueryLogItem)
	RecordQuery()
}

// QuotaEnforcer reports whether a client has spent its traffic allowance. It is
// optional: the access provider is asked for it by type assertion, so a test
// double that only knows about IP checks keeps working and simply never has a
// quota applied.
type QuotaEnforcer interface {
	QuotaExceeded(c *database.Client) bool
}

type Handler struct {
	access       AccessProvider
	cache        *cache.Cache
	matcher      *matcher.Matcher
	upstreams    *upstream.UpstreamPool
	telemetry    TelemetrySink
	publicIP     string
	publicIPv6   string
	totalQueries atomic.Uint64

	quota QuotaEnforcer

	// limiter is replaced only during startup, before any listener is accepting,
	// so the query path reads it without synchronisation.
	limiter *rateLimiter
	limited atomic.Uint64
}

func NewHandler(
	access AccessProvider,
	c *cache.Cache,
	m *matcher.Matcher,
	u *upstream.UpstreamPool,
	t TelemetrySink,
	publicIP string,
) *Handler {
	h := &Handler{
		access:    access,
		cache:     c,
		matcher:   m,
		upstreams: u,
		telemetry: t,
		publicIP:  publicIP,
		limiter:   newRateLimiter(defaultRateLimitQPS),
	}
	if q, ok := access.(QuotaEnforcer); ok {
		h.quota = q
	}
	// Let the cache renew its own entries through the pool. A name anyone is
	// actually using is then refreshed in the background before it expires,
	// instead of costing whoever asks next a full upstream round trip.
	if c != nil && u != nil {
		c.SetRefresher(h.refreshUpstream)
	}
	return h
}

// refreshUpstream re-resolves one question for the cache's background refresh.
//
// It builds a fresh query rather than replaying a client's: the stored question is
// all the cache knows, and a refresh must not carry some earlier client's
// transaction ID or EDNS0 options into the pool. The pool attaches its own ECS
// option from the configured public address, so a refresh is scoped exactly as a
// client-driven query is.
func (h *Handler) refreshUpstream(q dns.Question) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.Question[0].Qclass = q.Qclass
	m.RecursionDesired = true

	resp, _, _, err := h.upstreams.Exchange(m)
	return resp, err
}

// SetRateLimit replaces the per-source query limit. A value of zero or less turns
// limiting off entirely. Call it during startup only.
func (h *Handler) SetRateLimit(qps int) {
	h.limiter = newRateLimiter(qps)
}

// RateLimited is the number of queries dropped or refused for exceeding a
// source's query rate since start.
func (h *Handler) RateLimited() uint64 {
	return h.limited.Load()
}

// RateLimitQPS is the per-source limit in effect, or 0 when limiting is off.
// The dropped count alone is not interpretable — "1,204 dropped" reads as an
// attack to an operator who set the limit to 20 by hand and as a
// misconfiguration to one who left it at the default — so the dashboard is given
// both numbers.
func (h *Handler) RateLimitQPS() int {
	if h.limiter == nil {
		return 0
	}
	return int(h.limiter.qps)
}

// SetPublicIP installs the address proxied A answers point at. Only a usable
// IPv4 is accepted (v2.1.0 B-13 remediation): an IPv6 literal or a typo made
// dns.NewRR fail per query, and the discarded error turned every proxied A
// answer into an empty NOERROR logged as a successful "PROXY" — clients failed
// silently and the log said everything was fine. The daemon cannot run without
// an operator fixing the value, but it can refuse to pretend.
func (h *Handler) SetPublicIP(ip string) {
	if ip != "" {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed == nil || parsed.To4() == nil {
			log.Printf("[DNS] Warning: public IP %q is not a usable IPv4 address; proxied A records will answer SERVFAIL until it is fixed in Settings or -public-ip", ip)
			h.publicIP = ""
			return
		}
	}
	h.publicIP = strings.TrimSpace(ip)
}

// SetPublicIPv6 installs the address proxied AAAA answers point at (v2.5). Only
// a usable IPv6 literal is accepted; anything else clears it, and with it clear
// the resolver keeps the older behaviour of sinking AAAA on proxied names so an
// IPv4 client is forced onto the A record. Set it only when the server actually
// has a reachable IPv6 on which the SNI proxy listens, or IPv6 clients would be
// handed an address that answers nothing.
func (h *Handler) SetPublicIPv6(ip string) {
	ip = strings.TrimSpace(ip)
	if ip != "" {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() != nil {
			log.Printf("[DNS] Warning: public IPv6 %q is not a usable IPv6 address; proxied AAAA stays sunk (IPv4 forced)", ip)
			h.publicIPv6 = ""
			return
		}
	}
	h.publicIPv6 = ip
}

// TotalQueries is the number of questions this handler has processed since start,
// across every transport (UDP, TCP, DoT, DoH).
func (h *Handler) TotalQueries() uint64 {
	return h.totalQueries.Load()
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	h.serve(w, r, "")
}

// ServeWithProto returns a handler that tags every query with an explicit
// protocol label. The DoT listener runs over plain TCP as far as the
// ResponseWriter is concerned, so without this its traffic is indistinguishable
// from port-53 TCP in the query log.
func (h *Handler) ServeWithProto(proto string) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		h.serve(w, r, proto)
	})
}

func (h *Handler) serve(w dns.ResponseWriter, r *dns.Msg, proto string) {
	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	if clientIP == "" {
		clientIP = w.RemoteAddr().String()
	}
	if proto == "" {
		proto = w.RemoteAddr().Network()
	}
	proto = normalizeProto(proto)

	resp := h.ProcessQuery(r, clientIP, proto, w.RemoteAddr().String())
	if resp == nil {
		return
	}
	attachTCPKeepalive(resp, r, proto)
	// Datagram replies must fit what the client said it can receive, otherwise
	// the write fails outright or the answer is fragmented and dropped.
	if proto == "UDP" {
		resp.Truncate(udpSize(r))
	}
	_ = w.WriteMsg(resp)
}

// attachTCPKeepalive answers RFC 7828's edns-tcp-keepalive option, which is how a
// server tells a connection-oriented client how long it may keep the connection
// idle. Without the option the client can only guess, and guessing badly is
// expensive in both directions: guess too long and it writes a query into a socket
// the server has already closed, then waits out a timeout before retrying; guess
// too short and it throws away a connection — and for DoT a whole TLS handshake —
// that would have been reused.
//
// Sent only when the query asked for it, and never over UDP: RFC 7828 §3.3
// forbids it there, where there is no connection to hold open and the option would
// be extra bytes in a reply that can be aimed at a spoofed source.
func attachTCPKeepalive(resp, req *dns.Msg, proto string) {
	if resp == nil || req == nil {
		return
	}
	var timeout time.Duration
	switch proto {
	case "TCP":
		timeout = tcpIdleTimeout
	case "DoT":
		timeout = dotIdleTimeout
	default:
		return
	}

	reqOpt := req.IsEdns0()
	if reqOpt == nil || findOption(reqOpt, dns.EDNS0TCPKEEPALIVE) == nil {
		return
	}

	opt := resp.IsEdns0()
	if opt == nil {
		// A reply may only carry an OPT record when the query did (RFC 6891 §6.1.1),
		// and this one did — that is where the option came from. An answer served
		// from cache can still arrive without one.
		resp.SetEdns0(dns.DefaultMsgSize, reqOpt.Do())
		if opt = resp.IsEdns0(); opt == nil {
			return
		}
	}

	ka := &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: keepaliveUnits(timeout)}
	for i, o := range opt.Option {
		if o.Option() == dns.EDNS0TCPKEEPALIVE {
			opt.Option[i] = ka
			return
		}
	}
	opt.Option = append(opt.Option, ka)
}

// attachProhibitedEDE adds the RFC 8914 "Prohibited" Extended DNS Error to an
// access-refusal reply, but only when the query itself carried an OPT record —
// RFC 6891 §6.1.1 forbids a reply from introducing OPT the client never offered,
// and a plain client sees nothing but the REFUSED it always saw. The option
// merge mirrors attachTCPKeepalive: a reply that already carries OPT (the
// keepalive path above may have run first on connection transports) gets the
// option merged in rather than a second OPT appended.
func attachProhibitedEDE(resp, req *dns.Msg) {
	if resp == nil || req == nil {
		return
	}
	reqOpt := req.IsEdns0()
	if reqOpt == nil {
		return
	}
	opt := resp.IsEdns0()
	if opt == nil {
		resp.SetEdns0(dns.DefaultMsgSize, reqOpt.Do())
		if opt = resp.IsEdns0(); opt == nil {
			return
		}
	}
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0EDE {
			return // one EDE per reply; the first cause stands
		}
	}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeProhibited,
		ExtraText: "This address is not registered with this HyperDNS server.",
	})
}

func findOption(opt *dns.OPT, code uint16) dns.EDNS0 {
	for _, o := range opt.Option {
		if o.Option() == code {
			return o
		}
	}
	return nil
}

// keepaliveUnits converts an idle timeout to the unit RFC 7828 carries it in,
// hundreds of milliseconds. Never zero: a server sending zero is telling the
// client to close the connection at once, which is the opposite of the message.
func keepaliveUnits(d time.Duration) uint16 {
	units := d / (100 * time.Millisecond)
	if units < 1 {
		return 1
	}
	return uint16(min(units, math.MaxUint16))
}

// udpSize is the largest UDP payload this client will accept: its EDNS0
// advertised buffer, or the RFC 1035 512-byte floor when the query carries no
// OPT record. Clamped to 4096 so an absurd advertisement cannot be used to
// generate fragmented traffic.
func udpSize(r *dns.Msg) int {
	size := dns.MinMsgSize
	if opt := r.IsEdns0(); opt != nil {
		if adv := int(opt.UDPSize()); adv > size {
			size = adv
		}
	}
	return min(size, 4096)
}

// questionName is the queried name for logging, without its trailing dot. A
// message with no question at all still has to be loggable: the rate limiter runs
// before the shape of the query is validated.
func questionName(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
}

func normalizeProto(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "udp", "udp4", "udp6":
		return "UDP"
	case "tcp", "tcp4", "tcp6":
		return "TCP"
	case "dot", "tcp-tls":
		return "DoT"
	case "doh", "https":
		return "DoH"
	}
	return p
}

func (h *Handler) ProcessQuery(r *dns.Msg, clientIP string, protocol ...string) *dns.Msg {
	start := time.Now()
	h.totalQueries.Add(1)
	if h.telemetry != nil {
		h.telemetry.RecordQuery()
	}

	proto := "UDP"
	if len(protocol) > 0 && protocol[0] != "" {
		proto = normalizeProto(protocol[0])
	}

	// peerIP is the immediate transport peer, NOT the header-resolved client
	// address. The rate limiter's loopback exemption keys on it (v2.1.0 fix for
	// the finding that a spoofable clientIP could claim the exemption), while
	// the bucket itself still keys on the effective client address.
	peerIP := clientIP
	if len(protocol) > 1 && protocol[1] != "" {
		peerIP = protocol[1]
	}

	// Rate limit before any parsing or lookup, so a flood costs one hash and one
	// mutex. A UDP query over the limit is dropped without a reply: the source
	// address of a flood is typically forged, and a "you are being limited"
	// answer is still a packet aimed at whoever the flood names. Connection-
	// oriented transports have a peer that completed a handshake, and the DoH
	// bridge turns a nil response into HTTP 500, so those are refused explicitly.
	if !h.limiter.allow(clientIP, peerIP) {
		n := h.limited.Add(1)
		// One log line per drop would give a flood a query-log write and a
		// fan-out to every SSE dashboard subscriber for each packet it sends —
		// the amplification this check exists to remove. Sampling keeps the
		// offending source visible at bounded cost.
		if n%rateLimitLogSample == 1 {
			h.logQuery(start, clientIP, "Public", proto, questionName(r), "Rate limit", "RATELIMIT", false)
		}
		if proto == "UDP" {
			return nil
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		return m
	}

	// Exactly one question is the only shape ever deployed; anything else is
	// malformed and is a favourite probe for amplification reflectors.
	if len(r.Question) != 1 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		return m
	}
	if r.Opcode != dns.OpcodeQuery {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNotImplemented)
		return m
	}

	// 1. Validate Access Control
	var accountName = "Public"
	var activeClient *database.Client
	if h.access != nil {
		client, allowed := h.access.IsIPAllowed(clientIP)
		if allowed && client != nil {
			activeClient = client
			accountName = client.Name
		} else if !h.access.IsAllowAll() {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			// RFC 8914 Extended DNS Error, so a client that sent OPT learns WHY the
			// answer is REFUSED instead of retrying or blaming its resolver: the
			// address is not registered with this server. Sent only to queries that
			// carried an OPT record (a reply may never introduce one the query did
			// not), and only here — every other REFUSED below has a different cause
			// a "Prohibited" label would misstate.
			attachProhibitedEDE(m, r)
			return m
		}
	}

	// An account that has spent its traffic allowance is refused, not disabled:
	// disabling would need an operator to re-enable it by hand after a top-up,
	// while a refusal clears itself the moment the limit is raised or the counter
	// is reset. An unidentified "Public" source has no allowance to exceed, so
	// this only ever applies to a client the access provider recognised.
	if activeClient != nil && h.quota != nil && h.quota.QuotaExceeded(activeClient) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		h.logQuery(start, clientIP, accountName, proto, questionName(r), "Traffic quota exceeded", "QUOTA", false)
		return m
	}

	q := r.Question[0]
	qName := strings.ToLower(q.Name)
	domain := strings.TrimSuffix(qName, ".")

	// 2. RFC 8482: never serve ANY. Dumping every RRset for a name is the
	// classic DNS amplification primitive, so refuse before any lookup.
	if q.Qtype == dns.TypeANY {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		h.logQuery(start, clientIP, accountName, proto, domain, "ANY refused", "BLOCK", false)
		return m
	}

	// 3. Custom record overrides outrank every preset rule. Both address
	// families are answered here — previously only A was intercepted, so a
	// client could reach the real host by asking for AAAA instead.
	if customIP, ok := h.matcher.GetCustomRecord(domain); ok && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) {
		if ip := net.ParseIP(strings.TrimSpace(customIP)); ip != nil {
			m := new(dns.Msg)
			m.SetReply(r)
			isV4 := ip.To4() != nil
			if isV4 && q.Qtype == dns.TypeA {
				if rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, ip.String())); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else if !isV4 && q.Qtype == dns.TypeAAAA {
				if rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA %s", q.Name, ip.String())); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			// The other family deliberately gets an empty NOERROR.
			h.logQuery(start, clientIP, accountName, proto, domain, "Custom Record", "CUSTOM", false)
			return m
		}
	}

	// 4. Rule matcher (honoring per-client policy exceptions if configured)
	var action matcher.Action
	var ruleName string
	if activeClient != nil && len(activeClient.CustomPolicies) > 0 {
		action, ruleName = h.matcher.MatchForClient(domain, activeClient.CustomPolicies)
	} else {
		action, ruleName = h.matcher.Match(domain)
	}

	switch action {
	case matcher.ActionBlock:
		m := new(dns.Msg)
		m.SetReply(r)
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 0.0.0.0", q.Name))
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		h.logQuery(start, clientIP, accountName, proto, domain, ruleName, "BLOCK", false)
		return m

	case matcher.ActionProxy:
		if q.Qtype == dns.TypeA && h.publicIP != "" {
			m := new(dns.Msg)
			m.SetReply(r)
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, h.publicIP))
			if err != nil {
				// Unreachable while SetPublicIP validates, but a distinct action
				// here means a future regression can never masquerade as a
				// successful proxy answer again (v2.1.0 B-13 remediation).
				log.Printf("[DNS] Could not build proxied A record for %s from public IP %q: %v", q.Name, h.publicIP, err)
				h.logQuery(start, clientIP, accountName, proto, domain, ruleName, "PROXY_FAILED", false)
				m.SetRcode(r, dns.RcodeServerFailure)
				return m
			}
			m.Answer = append(m.Answer, rr)
			h.logQuery(start, clientIP, accountName, proto, domain, ruleName, "PROXY", false)
			return m
		}
		if q.Qtype == dns.TypeAAAA {
			// A proxied name's AAAA: if the operator has published a reachable
			// server IPv6 (v2.5), answer it so an IPv6 client reaches the SNI
			// proxy over v6 (which binds dual-stack). Otherwise keep the leak
			// guard — an empty NOERROR — so an IPv4 client is forced onto the
			// proxied A record instead of escaping to the real host over v6.
			m := new(dns.Msg)
			m.SetReply(r)
			if h.publicIPv6 != "" {
				if rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA %s", q.Name, h.publicIPv6)); err == nil {
					m.Answer = append(m.Answer, rr)
					h.logQuery(start, clientIP, accountName, proto, domain, ruleName, "PROXY", false)
					return m
				}
			}
			h.logQuery(start, clientIP, accountName, proto, domain, ruleName, "PROXY_IPV6_SINK", false)
			return m
		}
	}

	// 5. Cache, consulted only on the DIRECT path. When the lookup ran before
	// the matcher, a client whose policy resolved to DIRECT populated an entry
	// that was then served to clients whose policy said PROXY or BLOCK,
	// silently bypassing their rules.
	//
	// Lookup, not Get: an entry that has just expired is still served, with a short
	// TTL, while it is refreshed behind the scenes, and an entry approaching expiry
	// is refreshed early. Either way nobody waits on an upstream for a name the
	// resolver already knows.
	if h.cache != nil {
		if cachedResp, stale := h.cache.Lookup(q); cachedResp != nil {
			cachedResp.Id = r.Id
			cachedResp.Question = r.Question
			cachedResp.RecursionDesired = r.RecursionDesired
			rule, act := "Cached", "CACHED"
			if stale {
				// Logged apart from a live hit: the client's experience is
				// identical, but an operator seeing a lot of these is looking at an
				// upstream that has stopped answering, not at a healthy cache.
				rule, act = "Cached (stale, refreshing)", "STALE"
			}
			h.logQuery(start, clientIP, accountName, proto, domain, rule, act, true)
			return cachedResp
		}
	}

	// 6. Query Upstream Resolver Pool (Fastest Racing)
	resp, _, _, err := h.upstreams.Exchange(r)
	if err != nil {
		log.Printf("[DNS] Upstream query error for %s: %v", domain, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		return m
	}

	// Cache successful and authoritative-negative answers. NXDOMAIN was
	// excluded here, so every miss for a non-existent name re-queried upstream.
	// TC=1 messages are never cached (v2.1.0 B-01 remediation): a truncated
	// reply is an instruction to retry over TCP, not an answer — caching it
	// served the same partial to every client for a full TTL, and a TC=1 over
	// a connection transport is a protocol violation. The racer now refuses to
	// hand one back as a winner; this gate is the second fence.
	if h.cache != nil && resp != nil && !resp.Truncated && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
		h.cache.Put(q, resp)
		// The cached copy is clamped to the configured TTL window; clamp the
		// answer this client gets too, so the first requester is not the one
		// client told to hold the record for longer than the cache will.
		h.cache.ClampTTLs(resp)
	}

	// A stream client (TCP/DoT/DoH) must never receive TC=1 (RFC 7766 §4.2.2):
	// the whole point of a connection transport is that the answer fits. If a
	// truncated answer somehow survived the racer, answer SERVFAIL instead of
	// sending clients into a retry loop over a connection that cannot carry
	// the "please retry" flag usefully.
	if proto != "UDP" && resp != nil && resp.Truncated {
		log.Printf("[DNS] upstream returned TC=1 on %s for %s; answering SERVFAIL", proto, domain)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		return m
	}

	h.logQuery(start, clientIP, accountName, proto, domain, ruleName, action.String(), false)
	return resp
}

func (h *Handler) logQuery(start time.Time, ip, account, proto, domain, rule, action string, cached bool) {
	if h.telemetry == nil {
		return
	}
	h.telemetry.PushQueryLog(database.QueryLogItem{
		Timestamp:   start,
		ClientIP:    ip,
		AccountName: account,
		Protocol:    proto,
		Domain:      domain,
		RuleMatched: rule,
		Action:      action,
		LatencyMs:   float64(time.Since(start).Microseconds()) / 1000.0,
		Cached:      cached,
	})
}
