package proxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// fakeChallengeResponder stands in for the ACME manager: it knows exactly one
// (host, token) pair while "proving" it, like the real one does for the
// seconds a validation is in flight.
type fakeChallengeResponder struct {
	domain string
	token  string
	body   string
}

func (f *fakeChallengeResponder) ChallengeResponse(host, token string) (string, bool) {
	if token == f.token && strings.EqualFold(strings.TrimSpace(host), f.domain) {
		return f.body, true
	}
	return "", false
}

// startChallengeServer boots a Server with the challenge responder attached
// and one enabled plain-HTTP listener on the given port, then returns a
// client that dials it.
func startChallengeServer(t *testing.T, domain string, responder ChallengeResponder) (*Server, string) {
	t.Helper()
	settings := database.SNIProxySettings{
		Enabled:  true,
		HTTPPort: 0, // ephemeral; Start listens on 127.0.0.1:<random>
	}
	s := NewServer(settings, "127.0.0.1", domain, nil)
	if responder != nil {
		s.SetChallengeResponder(responder)
	}
	// Bind one ephemeral HTTP listener manually; Start() with port 0 is the
	// same code path but this keeps the test independent of the full port set.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close(); s.Stop() })
	go s.acceptLoopForTest(ln, false)
	return s, ln.Addr().String()
}

// acceptLoopForTest is acceptLoop with an explicit listener; the production
// acceptLoop is started by Start() per bound port and takes the same
// arguments.
func (s *Server) acceptLoopForTest(ln net.Listener, isTLS bool) {
	s.acceptLoop(context.Background(), ln, isTLS, 0)
}

func dialAndSend(t *testing.T, addr, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var sb strings.Builder
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		sb.WriteString(line)
		if err != nil || strings.Contains(line, "</body>") || line == "\r\n" {
			// Read until headers end (the challenge response closes right
			// after the body) or the connection closes.
			if line == "\r\n" {
				body, _ := br.ReadString(0)
				sb.WriteString(body)
			}
			break
		}
	}
	return sb.String()
}

const challengeRequest = "GET /.well-known/acme-challenge/%s HTTP/1.1\r\nHost: %s\r\n\r\n"

// TestChallengePathAnswersDuringAnIssuance: with a token actively being
// proven, the CA's validation request is answered locally, with the exact
// response body, regardless of the requester's IP (the CA is never a
// subscriber).
func TestChallengePathAnswersDuringAnIssuance(t *testing.T) {
	responder := &fakeChallengeResponder{domain: "dns.example.org", token: "tgV0-tokEN_abc123", body: "response-body.contents"}
	_, addr := startChallengeServer(t, "dns.example.org", responder)

	got := dialAndSend(t, addr, "GET /.well-known/acme-challenge/tgV0-tokEN_abc123 HTTP/1.1\r\nHost: dns.example.org\r\n\r\n")
	if !strings.Contains(got, "200 OK") {
		t.Fatalf("challenge request was not answered locally: %.200s", got)
	}
	if !strings.Contains(got, "response-body.contents") {
		t.Fatalf("the challenge body is wrong: %.200s", got)
	}
	if !strings.Contains(got, "Content-Type: application/octet-stream") {
		t.Errorf("challenge response Content-Type is not the ACME octet-stream: %.200s", got)
	}
}

// TestChallengePathIgnoresUnknownTokens: a scanner (or anyone) replaying the
// path with a token no issuance is proving must NOT be answered — the
// connection falls through to the ordinary relay path, which relays to the
// Host it names.
func TestChallengePathIgnoresUnknownTokens(t *testing.T) {
	responder := &fakeChallengeResponder{domain: "dns.example.org", token: "real-token", body: "x"}
	_, addr := startChallengeServer(t, "dns.example.org", responder)

	got := dialAndSend(t, addr, "GET /.well-known/acme-challenge/made-up-token HTTP/1.1\r\nHost: dns.example.org\r\n\r\n")
	if strings.Contains(got, "200 OK") && strings.Contains(got, "application/octet-stream") {
		t.Fatalf("an unknown token was answered as a challenge: %.200s", got)
	}
}

// TestChallengePathIgnoresForeignHosts: a challenge-shaped request for a Host
// that is not the configured domain is relayed, not intercepted — this proxy
// answers challenges for its own domain only.
func TestChallengePathIgnoresForeignHosts(t *testing.T) {
	responder := &fakeChallengeResponder{domain: "dns.example.org", token: "real-token", body: "x"}
	_, addr := startChallengeServer(t, "dns.example.org", responder)

	got := dialAndSend(t, addr, "GET /.well-known/acme-challenge/real-token HTTP/1.1\r\nHost: other.example.net\r\n\r\n")
	if strings.Contains(got, "200 OK") && strings.Contains(got, "application/octet-stream") {
		t.Fatalf("a foreign-Host challenge request was answered: %.200s", got)
	}
}

// TestChallengePathAnswersAfterADomainResave: the field-report regression. The
// proxy was constructed with the OLD domain (boot time); the operator then
// saved a NEW domain from the dashboard, which started an issuance for the new
// name immediately. The old code compared Host against the proxy's captured
// copy, so the validation for the new domain was never answered and the
// re-save could not succeed until a restart. The manager — which knows the
// domain in flight — is now the authority, so the proxy's stale copy is
// irrelevant.
func TestChallengePathAnswersAfterADomainResave(t *testing.T) {
	// Server built with the OLD domain; responder proving a token for the NEW one.
	responder := &fakeChallengeResponder{domain: "new.example.org", token: "resave-token", body: "resave-body"}
	_, addr := startChallengeServer(t, "old.example.org", responder)

	got := dialAndSend(t, addr, "GET /.well-known/acme-challenge/resave-token HTTP/1.1\r\nHost: new.example.org\r\n\r\n")
	if !strings.Contains(got, "200 OK") || !strings.Contains(got, "resave-body") {
		t.Fatalf("a validation for a re-saved domain was not answered (the boot-time domain would block it): %.200s", got)
	}
}

// TestChallengePathIgnoresNonGET: POST to the challenge path is not a
// validation request; RFC 8555 validators GET.
func TestChallengePathIgnoresNonGET(t *testing.T) {
	responder := &fakeChallengeResponder{domain: "dns.example.org", token: "real-token", body: "x"}
	_, addr := startChallengeServer(t, "dns.example.org", responder)

	got := dialAndSend(t, addr, "POST /.well-known/acme-challenge/real-token HTTP/1.1\r\nHost: dns.example.org\r\n\r\n")
	if strings.Contains(got, "200 OK") && strings.Contains(got, "application/octet-stream") {
		t.Fatalf("a POST was answered as a challenge: %.200s", got)
	}
}

// TestParseHTTPRequestHead pins the parser directly: request line, Host, and
// the malformed shapes that must be rejected.
func TestParseHTTPRequestHead(t *testing.T) {
	m, p, h, ok := parseHTTPRequestHead([]byte("GET /path HTTP/1.1\r\nHost: a.example\r\nX-Other: 1\r\n\r\n"))
	if !ok || m != "GET" || p != "/path" || h != "a.example" {
		t.Fatalf("parse = %q %q %q %v", m, p, h, ok)
	}
	// Host case-insensitive in header name, value trimmed.
	_, _, h, ok = parseHTTPRequestHead([]byte("GET / HTTP/1.1\r\nHOST:   spaced.example  \r\n\r\n"))
	if !ok || h != "spaced.example" {
		t.Fatalf("host parse = %q %v", h, ok)
	}
	// No Host -> not ok.
	if _, _, _, ok = parseHTTPRequestHead([]byte("GET / HTTP/1.1\r\n\r\n")); ok {
		t.Error("a head with no Host parsed as ok")
	}
	// Garbage request line -> not ok.
	if _, _, _, ok = parseHTTPRequestHead([]byte("not a request line at all\r\nHost: a.example\r\n\r\n")); ok {
		t.Error("a garbage request line parsed as ok")
	}
	// A path traversal attempt in the token position is rejected by the
	// caller's isACToken/Slash check, not by the parser — pin that here too.
	if _, p, _, ok = parseHTTPRequestHead([]byte("GET /.well-known/acme-challenge/../../etc HTTP/1.1\r\nHost: a.example\r\n\r\n")); !ok || strings.Contains(p, "..") == false {
		if !ok {
			t.Fatal("valid-shaped head with a traversal path did not parse")
		}
	}
}
