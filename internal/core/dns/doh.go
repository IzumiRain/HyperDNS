package dns

import (
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"

	"github.com/miekg/dns"
	"hyperdns/internal/netutil"
)

type DoHHandler struct {
	dnsHandler *Handler
	// tokens, when non-empty, are the only values a DoH client may present as
	// ?token= to be served. Comparison is constant-time per entry. An empty
	// list means the endpoint is open to whoever the access layer allows.
	tokens []string
}

func NewDoHHandler(h *Handler) *DoHHandler {
	return &DoHHandler{dnsHandler: h}
}

// SetDoHTokens installs the operator's DoH bearer tokens. An empty list
// disables token checking. Wired from the "access" record (dashboard card and
// config.json doh_tokens) — previously the card wrote the list and nothing
// ever read it (v2.1.0 B-07 remediation).
func (h *DoHHandler) SetDoHTokens(tokens []string) {
	h.tokens = tokens
}

// tokenOK reports whether the request's ?token= is accepted. Constant-time
// per entry so a wrong guess reveals nothing about which prefix matched.
func (h *DoHHandler) tokenOK(r *http.Request) bool {
	if len(h.tokens) == 0 {
		return true
	}
	given := r.URL.Query().Get("token")
	if given == "" {
		return false
	}
	ok := false
	for _, t := range h.tokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(given)) == 1 {
			ok = true
		}
	}
	return ok
}

func (h *DoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// No CORS headers (v2.1.0 A-05 remediation): RFC 8484 clients — browsers via
	// the standard API, stub resolvers — issue no preflighted cross-origin reads
	// that need them, and an open wildcard let any third-party website use this
	// resolver through its visitors' browsers. The endpoint is a service for
	// this server's subscribers, not a public cross-origin resource.
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientIP := netutil.ClientIP(r)

	if !h.tokenOK(r) {
		http.Error(w, "Missing or invalid DoH token", http.StatusUnauthorized)
		return
	}

	var reqMsg *dns.Msg
	switch r.Method {
	case http.MethodGet:
		dnsQueryParam := r.URL.Query().Get("dns")
		if dnsQueryParam == "" {
			http.Error(w, "Missing 'dns' query parameter", http.StatusBadRequest)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(dnsQueryParam)
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(dnsQueryParam)
			if err != nil {
				http.Error(w, "Invalid base64 payload", http.StatusBadRequest)
				return
			}
		}
		reqMsg = new(dns.Msg)
		if err := reqMsg.Unpack(raw); err != nil {
			http.Error(w, "Invalid DNS wire format", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		reqMsg = new(dns.Msg)
		if err := reqMsg.Unpack(body); err != nil {
			http.Error(w, "Invalid DNS wire format", http.StatusBadRequest)
			return
		}

	default:
		// RFC 8484 defines exactly these two methods for DoH, and RFC 9110 §15.5.6 asks a 405
		// to say so: a resolver client that guessed wrong is told which verb to retry with
		// instead of being left to conclude the endpoint is not DoH at all.
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// peerIP is the immediate TCP peer: the rate limiter's loopback exemption
	// keys on it, so a forwarded header can never claim the exemption.
	peerIP := netutil.PeerIP(r)
	resp := h.dnsHandler.ProcessQuery(reqMsg, clientIP, "DoH", peerIP)
	if resp == nil {
		http.Error(w, "DNS processing failure", http.StatusInternalServerError)
		return
	}

	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	// RFC 8484 §5.1: the HTTP freshness lifetime must not outlive the DNS TTL,
	// otherwise intermediary caches keep serving answers the resolver retired.
	if ttl := minAnswerTTL(resp); ttl > 0 {
		w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(ttl), 10))
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packed)
}

// minAnswerTTL is the smallest TTL across all non-OPT records, i.e. how long
// the whole message stays valid.
func minAnswerTTL(msg *dns.Msg) uint32 {
	var ttl uint32
	first := true
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if first || h.Ttl < ttl {
				ttl, first = h.Ttl, false
			}
		}
	}
	return ttl
}
