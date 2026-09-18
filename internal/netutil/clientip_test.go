package netutil

import (
	"net/http"
	"testing"
)

// req builds a request with the given peer address and headers. The headers are
// passed as name/value pairs so a case reads as one line.
func req(remoteAddr string, hdr ...string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = remoteAddr
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	return r
}

func TestPeerIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:54321":    "203.0.113.7",
		"127.0.0.1:8080":       "127.0.0.1",
		"[2606:4700::1]:443":   "2606:4700::1",
		"[::1]:443":            "::1",
		"203.0.113.7":          "203.0.113.7", // no port at all
		" 203.0.113.7 ":        "203.0.113.7", // padded, as a unix socket peer can be
		"":                     "",
		"203.0.113.7:notaport": "203.0.113.7",
	}
	for in, want := range cases {
		if got := PeerIP(req(in)); got != want {
			t.Errorf("PeerIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsTrustedHop(t *testing.T) {
	trusted := []string{
		"127.0.0.1", "127.0.0.53", "::1",
		"10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1",
		"fd00::1", "fc00::1", // IPv6 unique-local counts as private
		"169.254.1.1", "fe80::1", // link-local
		"0.0.0.0", "::", // unspecified
		" 10.0.0.1 ", // padding must not change the verdict
	}
	for _, ip := range trusted {
		if !IsTrustedHop(ip) {
			t.Errorf("IsTrustedHop(%q) = false, want true", ip)
		}
	}

	// A public peer is never trusted: on a public listener anyone could otherwise
	// set X-Forwarded-For to an authorized subscriber's address and inherit that
	// subscriber's access rights.
	untrusted := []string{
		"", "localhost", "not-an-ip", "203.0.113.7:443",
		"1.1.1.1", "8.8.8.8", "203.0.113.7", "198.51.100.9",
		"172.15.255.255", "172.32.0.1", // just outside RFC 1918
		"100.64.0.1",             // CGNAT is not a reverse-proxy hop
		"2606:4700:4700::11",     // public IPv6
		"127.0.0.1, 203.0.113.9", // a raw header value, not an address
	}
	for _, ip := range untrusted {
		if IsTrustedHop(ip) {
			t.Errorf("IsTrustedHop(%q) = true, want false", ip)
		}
	}
}

func TestClientIPIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	// This is the whole point of the helper: a direct caller on a public listener
	// claims to be someone else and must be given its own address regardless.
	spoofs := [][]string{
		{"X-Forwarded-For", "10.0.0.5"},
		{"X-Forwarded-For", "192.168.1.50"},
		{"X-Real-IP", "10.0.0.5"},
		{"X-Forwarded-For", "127.0.0.1", "X-Real-IP", "127.0.0.1"},
	}
	for _, hdr := range spoofs {
		r := req("203.0.113.7:44444", hdr...)
		if got := ClientIP(r); got != "203.0.113.7" {
			t.Errorf("ClientIP with %v from a public peer = %q, want the peer 203.0.113.7", hdr, got)
		}
	}
}

// TestClientIPIgnoresHeadersWithoutADeclaredProxy pins the A-01 remediation's
// core property: a loopback or private PEER alone no longer earns header trust.
// Containers, Kubernetes pods and home LANs are all "private"; a compromised
// private hop must not gain the right to rewrite the address the lockout, rate
// limiter, DoH access and portal binding key on. Header trust requires the
// operator to declare the proxy.
func TestClientIPIgnoresHeadersWithoutADeclaredProxy(t *testing.T) {
	spoofs := [][]string{
		{"X-Forwarded-For", "203.0.113.9"},
		{"X-Real-IP", "203.0.113.9"},
	}
	for _, hdr := range spoofs {
		for _, peer := range []string{"127.0.0.1:8080", "10.0.0.2:8080", "[::1]:8080"} {
			r := req(peer, hdr...)
			if got := ClientIP(r); got != PeerIP(r) {
				t.Errorf("ClientIP with %v from undeclared peer %s = %q, want the peer", hdr, peer, got)
			}
		}
	}
}

func TestClientIPHonoursHeadersFromDeclaredProxy(t *testing.T) {
	SetTrustedProxies([]string{"127.0.0.1", "::1/128", "10.0.0.0/8"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	cases := []struct {
		peer string
		hdr  []string
		want string
		why  string
	}{
		{"127.0.0.1:8080", []string{"X-Forwarded-For", "203.0.113.9"}, "203.0.113.9",
			"a single-entry chain from a declared loopback proxy"},
		{"10.0.0.2:8080", []string{"X-Forwarded-For", "203.0.113.9"}, "203.0.113.9",
			"a declared private-network proxy"},
		{"[::1]:8080", []string{"X-Forwarded-For", "2606:4700::1"}, "2606:4700::1",
			"an IPv6 loopback proxy forwarding an IPv6 client"},
		// The heart of the A-01 fix: with nginx's header-APPENDING default, the
		// client's forgery sits at index 0 and the proxy-added hop at the end.
		// The rightmost non-proxy entry is the only value a conforming chain
		// puts beyond the client's reach.
		{"127.0.0.1:8080", []string{"X-Forwarded-For", "6.6.6.6, 203.0.113.9"}, "203.0.113.9",
			"the client's forged head of the chain loses to the proxy-appended tail"},
		{"127.0.0.1:8080", []string{"X-Forwarded-For", "6.6.6.6, 203.0.113.9, 10.9.9.9"}, "203.0.113.9",
			"an inner proxy hop inside the declared CIDR is skipped, not trusted"},
		{"127.0.0.1:8080", []string{"X-Real-IP", "203.0.113.9"}, "203.0.113.9",
			"X-Real-IP when there is no X-Forwarded-For"},
		{"127.0.0.1:8080", []string{"X-Forwarded-For", "203.0.113.9", "X-Real-IP", "198.51.100.1"},
			"203.0.113.9", "X-Forwarded-For taking precedence"},
	}
	for _, tc := range cases {
		if got := ClientIP(req(tc.peer, tc.hdr...)); got != tc.want {
			t.Errorf("ClientIP(peer=%s, %v) = %q, want %q (%s)", tc.peer, tc.hdr, got, tc.want, tc.why)
		}
	}
}

// TestClientIPTrustFollowsTheAllowlistLive proves the allowlist is read per
// request: declaring a proxy changes the verdict on the very next call, and
// clearing it revokes the trust — the wiring the settings handler relies on.
func TestClientIPTrustFollowsTheAllowlistLive(t *testing.T) {
	r := req("10.0.0.2:8080", "X-Forwarded-For", "203.0.113.9")

	SetTrustedProxies(nil)
	if got := ClientIP(r); got != "10.0.0.2" {
		t.Errorf("with no allowlist, ClientIP = %q, want the peer", got)
	}
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	if got := ClientIP(r); got != "203.0.113.9" {
		t.Errorf("after declaring 10.0.0.0/8, ClientIP = %q, want the forwarded value", got)
	}
}

func TestClientIPFallsBackOnUnusableHeader(t *testing.T) {
	SetTrustedProxies([]string{"127.0.0.1"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	// A trusted hop sending nonsense must not turn the header into an identity.
	// Falling back to the peer keeps the value something the callers — the login
	// lockout key, the DoH access check — can compare against a real address.
	bad := [][]string{
		{"X-Forwarded-For", ""},
		{"X-Forwarded-For", "not-an-ip"},
		{"X-Forwarded-For", ","},
		{"X-Forwarded-For", "example.com"},
		{"X-Forwarded-For", "203.0.113.9:443"}, // an address:port is not an address
		{"X-Real-IP", "not-an-ip"},
		{"X-Forwarded-For", "not-an-ip", "X-Real-IP", "also-bad"},
	}
	for _, hdr := range bad {
		if got := ClientIP(req("127.0.0.1:8080", hdr...)); got != "127.0.0.1" {
			t.Errorf("ClientIP with %v from a trusted hop = %q, want the peer 127.0.0.1", hdr, got)
		}
	}

	// An unparseable X-Forwarded-For must not shadow a usable X-Real-IP.
	r := req("127.0.0.1:8080", "X-Forwarded-For", "not-an-ip", "X-Real-IP", "203.0.113.9")
	if got := ClientIP(r); got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want the X-Real-IP fallback 203.0.113.9", got)
	}
}
