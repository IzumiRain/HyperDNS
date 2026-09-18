package dns

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/config"
	"hyperdns/internal/rules"
)

type QueryLogItem struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ClientIP  string    `json:"client_ip"`
	Protocol  string    `json:"protocol"` // UDP, TCP, DoH, DoT
	Domain    string    `json:"domain"`
	QType     string    `json:"qtype"`
	Action    string    `json:"action"` // PROXY, DIRECT, BLOCK, CUSTOM
	Answer    string    `json:"answer"`
	LatencyMs float64   `json:"latency_ms"`
	Cached    bool      `json:"cached"`
	RuleName  string    `json:"rule_name"`
}

type Handler struct {
	cfg        *config.Config
	cache      *Cache
	matcher    *rules.Matcher
	upstreams  *UpstreamPool
	logChan    chan QueryLogItem
	totalQPS   uint64
	totalHits  uint64
	totalCache uint64
}

func NewHandler(cfg *config.Config, cache *Cache, matcher *rules.Matcher, upstreams *UpstreamPool) *Handler {
	return &Handler{
		cfg:       cfg,
		cache:     cache,
		matcher:   matcher,
		upstreams: upstreams,
		logChan:   make(chan QueryLogItem, 2048),
	}
}

func (h *Handler) GetLogChannel() <-chan QueryLogItem {
	return h.logChan
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	clientIP := ""
	protocol := "UDP"
	if w != nil && w.RemoteAddr() != nil {
		host, _, err := net.SplitHostPort(w.RemoteAddr().String())
		if err == nil {
			clientIP = host
		} else {
			clientIP = w.RemoteAddr().String()
		}
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			protocol = "TCP"
		}
	}

	resp := h.ProcessQuery(r, clientIP, protocol)
	if w != nil && resp != nil {
		_ = w.WriteMsg(resp)
	}
}

func (h *Handler) ProcessQuery(r *dns.Msg, clientIP, protocol string) *dns.Msg {
	start := time.Now()
	atomic.AddUint64(&h.totalQPS, 1)
	atomic.AddUint64(&h.totalHits, 1)

	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		return m
	}

	q := r.Question[0]
	rawDomain := q.Name
	cleanDomain := strings.ToLower(strings.TrimSuffix(rawDomain, "."))

	// 1. Special Domain: example.com Connectivity & Registration Diagnostic
	if cleanDomain == "example.com" || cleanDomain == "www.example.com" {
		if _, ok := h.cfg.GetValidClientByIP(clientIP); ok {
			// Registered and valid accounting date -> Return DNS Server Public IP
			publicIP := h.cfg.Server.PublicIP
			if publicIP == "" {
				publicIP = "127.0.0.1"
			}
			resp := h.handleProxySpoof(r, q, publicIP)
			lat := time.Since(start)
			h.pushLog(clientIP, protocol, cleanDomain, dns.TypeToString[q.Qtype], "PROXY", fmt.Sprintf("%s (HyperDNS Connected - Client Active)", publicIP), lat, false, "Connectivity Test")
			h.cfg.IncrementClientQuery(clientIP)
			return resp
		}
		// Unregistered, disabled, or expired client -> Resolve to REAL IP from upstream (Cloudflare)
		resp := h.resolveDirect(r, q)
		lat := time.Since(start)
		h.pushLog(clientIP, protocol, cleanDomain, dns.TypeToString[q.Qtype], "DIRECT", fmt.Sprintf("%s (Real Upstream IP - Client Inactive/Unregistered)", extractAnswers(resp)), lat, false, "Connectivity Test")
		return resp
	}

	// 2. Access Control Check (Whitelisting / Blacklisting)
	if !h.cfg.IsIPAllowed(clientIP) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		h.pushLog(clientIP, protocol, cleanDomain, dns.TypeToString[q.Qtype], "REFUSED", "Access Denied (Not Whitelisted)", time.Since(start), false, "Client Whitelist")
		return m
	}
	h.cfg.IncrementClientQuery(clientIP)

	// 3. Evaluate Smart Routing Rules
	ruleResult := h.matcher.Match(cleanDomain)

	var resp *dns.Msg
	var answerSummary string
	var cached bool

	switch ruleResult.Action {
	case rules.ActionBlock:
		resp = h.handleBlock(r, q)
		answerSummary = "0.0.0.0 (Sinkhole)"

	case rules.ActionCustom:
		resp = h.handleCustom(r, q, ruleResult.CustomIP)
		answerSummary = ruleResult.CustomIP

	case rules.ActionProxy:
		// Spoof to Server's Public IP for SNI Proxying
		publicIP := h.cfg.Server.PublicIP
		if publicIP == "" {
			publicIP = "127.0.0.1"
		}
		resp = h.handleProxySpoof(r, q, publicIP)
		answerSummary = fmt.Sprintf("%s (SNI Proxy)", publicIP)

	case rules.ActionDirect:
		// Check Cache or Query Upstream Resolvers
		resp = h.resolveDirect(r, q)
		answerSummary = extractAnswers(resp)
	}

	lat := time.Since(start)
	h.pushLog(clientIP, protocol, cleanDomain, dns.TypeToString[q.Qtype], ruleResult.Action.String(), answerSummary, lat, cached, ruleResult.MatchedBy)

	return resp
}

func (h *Handler) resolveDirect(r *dns.Msg, q dns.Question) *dns.Msg {
	if cachedMsg := h.cache.Get(q); cachedMsg != nil {
		cachedMsg.Id = r.Id
		atomic.AddUint64(&h.totalCache, 1)
		return cachedMsg
	}
	upResp, _, _, err := h.upstreams.Exchange(r)
	if err != nil || upResp == nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		return m
	}
	upResp.Id = r.Id
	h.cache.Put(q, upResp)
	return upResp
}

func (h *Handler) handleBlock(r *dns.Msg, q dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if q.Qtype == dns.TypeA {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 0.0.0.0", q.Name))
		m.Answer = append(m.Answer, rr)
	} else if q.Qtype == dns.TypeAAAA {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA ::", q.Name))
		m.Answer = append(m.Answer, rr)
	} else {
		m.SetRcode(r, dns.RcodeNameError)
	}
	return m
}

func (h *Handler) handleCustom(r *dns.Msg, q dns.Question, customIP string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	ip := net.ParseIP(customIP)
	if ip == nil {
		// Treat as CNAME if not IP
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN CNAME %s.", q.Name, strings.TrimSuffix(customIP, ".")))
		m.Answer = append(m.Answer, rr)
		return m
	}

	if ip.To4() != nil && q.Qtype == dns.TypeA {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, customIP))
		m.Answer = append(m.Answer, rr)
	} else if ip.To4() == nil && q.Qtype == dns.TypeAAAA {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA %s", q.Name, customIP))
		m.Answer = append(m.Answer, rr)
	}
	return m
}

func (h *Handler) handleProxySpoof(r *dns.Msg, q dns.Question, publicIP string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	ip := net.ParseIP(publicIP)
	if ip != nil {
		if ip.To4() != nil && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN A %s", q.Name, ip.String()))
			m.Answer = append(m.Answer, rr)
		} else if ip.To4() == nil && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN AAAA %s", q.Name, ip.String()))
			m.Answer = append(m.Answer, rr)
		}
	} else {
		// Default fallback
		rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN A 127.0.0.1", q.Name))
		m.Answer = append(m.Answer, rr)
	}
	return m
}

func (h *Handler) isIPAllowed(clientIP string) bool {
	if clientIP == "" || clientIP == "127.0.0.1" || clientIP == "::1" {
		return true
	}

	access := &h.cfg.Access
	if len(access.BlockedIPs) > 0 {
		for _, b := range access.BlockedIPs {
			if strings.TrimSpace(b) == clientIP {
				return false
			}
		}
	}

	if access.AllowAll {
		return true
	}

	if len(access.AllowedIPs) == 0 {
		return true
	}

	for _, a := range access.AllowedIPs {
		if strings.TrimSpace(a) == clientIP {
			return true
		}
	}
	return false
}

func extractAnswers(msg *dns.Msg) string {
	if msg == nil || len(msg.Answer) == 0 {
		return "NODATA"
	}
	var answers []string
	for _, a := range msg.Answer {
		switch rr := a.(type) {
		case *dns.A:
			answers = append(answers, rr.A.String())
		case *dns.AAAA:
			answers = append(answers, rr.AAAA.String())
		case *dns.CNAME:
			answers = append(answers, rr.Target)
		}
	}
	if len(answers) == 0 {
		return dns.RcodeToString[msg.Rcode]
	}
	return strings.Join(answers, ", ")
}

func (h *Handler) pushLog(clientIP, proto, domain, qtype, action, answer string, dur time.Duration, cached bool, rule string) {
	item := QueryLogItem{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		ClientIP:  clientIP,
		Protocol:  proto,
		Domain:    domain,
		QType:     qtype,
		Action:    action,
		Answer:    answer,
		LatencyMs: float64(dur.Microseconds()) / 1000.0,
		Cached:    cached,
		RuleName:  rule,
	}

	select {
	case h.logChan <- item:
	default:
		// Drop oldest if full
		select {
		case <-h.logChan:
		default:
		}
		h.logChan <- item
	}
}

func (h *Handler) GetCounters() (uint64, uint64, uint64) {
	return atomic.LoadUint64(&h.totalQPS), atomic.LoadUint64(&h.totalHits), atomic.LoadUint64(&h.totalCache)
}
