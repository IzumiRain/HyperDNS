package dns

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/database"
	"hyperdns/internal/netutil"
)

// The DoH endpoint, which is the one transport where the client's address arrives in
// a header rather than from the socket. netutil's own tests already pin when a
// forwarding header may be believed; what these tests pin is that this endpoint's
// access decision is made from that verdict, and that the RFC 8484 envelope around
// it — the two defined methods, both base64url spellings, the bounded body, and a
// Cache-Control that cannot outlive the DNS TTL — behaves as a resolver client
// expects.

// oneSubscriberAccess allows exactly one address, the way a server with allow_all
// switched off and a single paid subscriber does.
type oneSubscriberAccess struct{ allowed string }

func (o *oneSubscriberAccess) IsIPAllowed(ip string) (*database.Client, bool) {
	if ip != o.allowed {
		return nil, false
	}
	return &database.Client{Name: "Paid Subscriber"}, true
}

func (o *oneSubscriberAccess) IsAllowAll() bool { return false }

// newDoHHandler wires a DoH front-end onto a resolver that can answer one name from
// a custom record, so a served query needs no upstream. The pool address is a
// documentation range: reaching it means a test took a path it was not meant to.
func newDoHHandler(t *testing.T, access AccessProvider) *DoHHandler {
	t.Helper()
	c := cache.NewCache(1000, 60, 3600)
	t.Cleanup(c.Close)
	m := matcher.NewMatcher()
	m.SetCustomRules(nil, nil, nil, map[string]string{"pin.internal.test": "203.0.113.77"})
	u := upstream.NewUpstreamPool([]string{"192.0.2.1:53"}, 200*time.Millisecond, true, "")
	return NewDoHHandler(NewHandler(access, c, m, u, nil, "198.51.100.1"))
}

// dohQuery is one A query packed the way RFC 8484 sends it.
func dohQuery(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.RecursionDesired = true
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return raw
}

// dohReply unpacks a DoH response body, failing the test unless the endpoint
// answered with a DNS message at all.
func dohReply(t *testing.T, rec *httptest.ResponseRecorder) *dns.Msg {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("Content-Type = %q, want application/dns-message", ct)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatalf("reply is not a DNS message: %v", err)
	}
	return msg
}

func TestDoHIgnoresForwardedForFromAnUntrustedPeer(t *testing.T) {
	const subscriber = "203.0.113.50"
	h := newDoHHandler(t, &oneSubscriberAccess{allowed: subscriber})

	// A stranger on the public listener claims to be the paying subscriber. Believing
	// the header here would hand a subscription to anyone who can read one address off
	// a support ticket, and the DoH endpoint is the only place that header is read.
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(dohQuery(t, "pin.internal.test.")))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("X-Forwarded-For", subscriber)
	req.Header.Set("X-Real-IP", subscriber)
	req.RemoteAddr = "198.51.100.66:51000"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	// RFC 8484 §4.2.1: a refusal is a successful HTTP transaction carrying a DNS
	// message, so the check reads the rcode rather than the status code.
	reply := dohReply(t, rec)
	if reply.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[reply.Rcode])
	}
	if got := answerIPs(reply); len(got) != 0 {
		t.Errorf("refusal carried %v", got)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store for a reply with no records", cc)
	}
}

func TestDoHHonoursForwardedForFromATrustedHop(t *testing.T) {
	const subscriber = "203.0.113.50"
	h := newDoHHandler(t, &oneSubscriberAccess{allowed: subscriber})
	// The proxy must be declared: header trust without an operator allowlist is
	// exactly the leftmost-XFF spoof the A-01 remediation removed.
	netutil.SetTrustedProxies([]string{"127.0.0.1"})
	t.Cleanup(func() { netutil.SetTrustedProxies(nil) })

	// The same header, now from the reverse proxy this daemon is designed to sit
	// behind. The proxy's own address is all ProcessQuery would otherwise see, so
	// refusing here breaks every install that terminates TLS in nginx or Caddy.
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(dohQuery(t, "pin.internal.test.")))
	req.Header.Set("X-Forwarded-For", subscriber)
	req.RemoteAddr = "127.0.0.1:51001"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	reply := dohReply(t, rec)
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[reply.Rcode])
	}
	if got := answerIPs(reply); len(got) != 1 || got[0] != "203.0.113.77" {
		t.Errorf("answers = %v, want [203.0.113.77]", got)
	}
	// RFC 8484 §5.1: an intermediary must not keep serving this answer after the
	// record it carries has expired, so the freshness lifetime is the record's TTL.
	if cc := rec.Header().Get("Cache-Control"); cc != "max-age=60" {
		t.Errorf("Cache-Control = %q, want max-age=60 from the record's own TTL", cc)
	}
}

func TestDoHAcceptsBothBase64URLSpellings(t *testing.T) {
	h := newDoHHandler(t, &dummyAccess{})
	raw := dohQuery(t, "pin.internal.test.")

	padded := base64.URLEncoding.EncodeToString(raw)
	if !strings.HasSuffix(padded, "=") {
		t.Fatalf("fixture stopped exercising the padded spelling: %q needs no padding", padded)
	}

	// RFC 8484 §6 specifies the unpadded spelling, but padded values are what several
	// client libraries actually emit, and rejecting them looks to the user like the
	// endpoint is not DoH at all.
	for name, enc := range map[string]string{
		"unpadded, as the RFC specifies": base64.RawURLEncoding.EncodeToString(raw),
		"padded, as some clients send":   padded,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+enc, nil)
			req.RemoteAddr = "127.0.0.1:51002"
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			reply := dohReply(t, rec)
			if got := answerIPs(reply); len(got) != 1 || got[0] != "203.0.113.77" {
				t.Errorf("answers = %v, want [203.0.113.77]", got)
			}
			if len(reply.Question) != 1 || reply.Question[0].Name != "pin.internal.test." {
				t.Errorf("reply question = %v, want the query echoed back", reply.Question)
			}
		})
	}
}

func TestDoHRejectsUnusablePayloadsWithoutAnswering(t *testing.T) {
	h := newDoHHandler(t, &dummyAccess{})

	cases := []struct {
		name string
		req  func() *http.Request
	}{
		{"no dns parameter", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/dns-query", nil)
		}},
		{"an empty dns parameter", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/dns-query?dns=", nil)
		}},
		{"a dns parameter that is not base64", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/dns-query?dns=@@not-base64@@", nil)
		}},
		{"base64 that is not a DNS message", func() *http.Request {
			enc := base64.RawURLEncoding.EncodeToString([]byte("this is not a dns message"))
			return httptest.NewRequest(http.MethodGet, "/dns-query?dns="+enc, nil)
		}},
		{"a POST body that is not a DNS message", func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader("nonsense"))
		}},
		{"an empty POST body", func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader(""))
		}},
		// The body reader is capped at 4 KB. A message that genuinely needs more than
		// that is cut mid-record and fails to unpack, which is the behaviour that stops
		// this endpoint from being a way to make the daemon allocate megabytes per
		// request. Trailing junk after a complete message is not a useful test here:
		// miekg/dns ignores bytes past the last record by design.
		{"a message larger than the body cap", func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(oversizedWireQuery(t, 8<<10)))
		}},
		// GET must enforce the same 4 KB ceiling the POST branch does: a well-formed
		// but oversized message decoded from ?dns= is rejected rather than processed,
		// so the GET path is not an uncapped decode+unpack (v2.5 GET/POST parity fix).
		{"a GET dns= larger than the body cap", func() *http.Request {
			enc := base64.RawURLEncoding.EncodeToString(oversizedWireQuery(t, 8<<10))
			return httptest.NewRequest(http.MethodGet, "/dns-query?dns="+enc, nil)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req()
			req.RemoteAddr = "127.0.0.1:51003"
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// oversizedWireQuery is a well-formed query carrying an EDNS0 padding option of the given
// size, i.e. a message whose own records run past the endpoint's body cap. It returns wire
// bytes rather than a *dns.Msg because the DoH endpoint is fed an HTTP body, and it is a
// different helper from amplification_test.go's paddedQuery for that reason.
func oversizedWireQuery(t *testing.T, padding int) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("pin.internal.test.", dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(4096)
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, padding)})
	m.Extra = append(m.Extra, opt)

	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if len(raw) <= 4096 {
		t.Fatalf("fixture is %d bytes, which no longer exceeds the 4 KB body cap", len(raw))
	}
	return raw
}

func TestDoHRejectsMethodsRFC8484DoesNotDefine(t *testing.T) {
	h := newDoHHandler(t, &dummyAccess{})

	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead} {
		req := httptest.NewRequest(method, "/dns-query", nil)
		req.RemoteAddr = "127.0.0.1:51004"
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, rec.Code)
		}
		// RFC 9110 §15.5.6: without Allow, a client that guessed the verb wrong is left
		// to conclude the endpoint is not DoH instead of retrying correctly.
		if allow := rec.Header().Get("Allow"); allow != "GET, POST" {
			t.Errorf("%s: Allow = %q, want %q", method, allow, "GET, POST")
		}
	}
}

func TestDoHAnswersThePreflightWithoutConsultingTheResolver(t *testing.T) {
	h := newDoHHandler(t, &oneSubscriberAccess{allowed: "203.0.113.50"})

	// A browser sends this before any cross-origin DoH request, and it carries no
	// query. It has to be answered even for a source the resolver would refuse,
	// otherwise the refusal reaches the page as a CORS failure rather than as a
	// DNS rcode the client can act on.
	req := httptest.NewRequest(http.MethodOptions, "/dns-query", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.RemoteAddr = "198.51.100.66:51005"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	// CORS support was removed with the A-05 remediation: the endpoint is a
	// service for this server's subscribers, not a public cross-origin resource,
	// so a preflight is answered as the unknown-method case RFC 9110 asks for.
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, POST" {
		t.Errorf("Allow = %q, want GET, POST", got)
	}
	for header := range map[string]bool{
		"Access-Control-Allow-Origin":  true,
		"Access-Control-Allow-Methods": true,
		"Access-Control-Allow-Headers": true,
	} {
		if got := rec.Header().Get(header); got != "" {
			t.Errorf("%s = %q, want no CORS header at all", header, got)
		}
	}
}

// mustRR parses one record from presentation form.
func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func TestMinAnswerTTLIsTheShortestRecordAcrossEverySection(t *testing.T) {
	cases := []struct {
		name string
		msg  func(*testing.T) *dns.Msg
		want uint32
	}{
		{"no records at all", func(*testing.T) *dns.Msg { return new(dns.Msg) }, 0},

		{"the shortest of several answers", func(t *testing.T) *dns.Msg {
			m := new(dns.Msg)
			m.Answer = append(m.Answer,
				mustRR(t, "a.example.com. 300 IN A 198.51.100.1"),
				mustRR(t, "a.example.com. 30 IN A 198.51.100.2"),
				mustRR(t, "a.example.com. 120 IN A 198.51.100.3"))
			return m
		}, 30},

		{"an authority record shorter than the answer", func(t *testing.T) *dns.Msg {
			m := new(dns.Msg)
			m.Answer = append(m.Answer, mustRR(t, "a.example.com. 300 IN A 198.51.100.1"))
			m.Ns = append(m.Ns, mustRR(t, "example.com. 15 IN NS ns1.example.com."))
			return m
		}, 15},

		// A zero TTL is an answer that must not be reused, which is exactly the case the
		// caller turns into no-store.
		{"a zero TTL", func(t *testing.T) *dns.Msg {
			m := new(dns.Msg)
			m.Answer = append(m.Answer, mustRR(t, "a.example.com. 0 IN A 198.51.100.1"))
			return m
		}, 0},

		// The OPT pseudo-record's TTL field carries flags, not a lifetime. Counting it
		// would read as zero and make every EDNS0-bearing answer uncacheable by any
		// intermediary — a silent latency cost on the majority of real replies.
		{"the OPT pseudo-record is skipped", func(t *testing.T) *dns.Msg {
			m := new(dns.Msg)
			m.Answer = append(m.Answer, mustRR(t, "a.example.com. 120 IN A 198.51.100.1"))
			m.SetEdns0(4096, false)
			return m
		}, 120},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := minAnswerTTL(tc.msg(t)); got != tc.want {
				t.Errorf("minAnswerTTL = %d, want %d", got, tc.want)
			}
		})
	}
}
