// Package netutil holds the small networking helpers shared by the DNS, DoH and
// web front-ends — chiefly the single definition of which client address may be
// trusted, so that policy cannot drift between transports.
package netutil

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// PeerIP is the address of the immediate TCP peer, without its port.
func PeerIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || peer == "" {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return peer
}

// trustedProxyAllowlist is the operator-declared set of addresses a forwarding
// header is believed from. It is filled once at startup from configuration
// (SetTrustedProxies) and read on every request; the copy-on-write swap keeps
// the hot path lock-free.
//
// The security property this enforces is the one CWE-290/348 attacks exploit
// when it is missing: an X-Forwarded-For value is accepted only when the
// IMMEDIATE peer is an operator-declared proxy, and the value taken is the
// RIGHTMOST entry not appended by one of our own proxies. The leftmost entry
// is whatever the CLIENT sent; with a header-appending proxy (nginx
// `proxy_add_x_forwarded_for`) it stays at index 0, so trusting it lets any
// client behind the proxy forge the address the login lockout, the DNS rate
// limiter, the DoH access check and the portal's IP binding all key on.
var trustedProxyAllowlist struct {
	mu  sync.RWMutex
	ips map[string]bool
	set bool
}

// SetTrustedProxies replaces the allowlist of proxy addresses forwarding
// headers may be believed from. An empty list DISABLES header trust entirely:
// every client is its immediate peer, which is the correct posture for a
// deployment with no reverse proxy and the fail-closed answer when the
// operator has not configured one.
func SetTrustedProxies(cidrs []string) {
	set := make(map[string]bool, len(cidrs))
	for _, entry := range cidrs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil {
				if ip.To4() != nil {
					entry += "/32"
				} else {
					entry += "/128"
				}
			}
		}
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			set[ipnet.String()] = true
		}
	}
	trustedProxyAllowlist.mu.Lock()
	trustedProxyAllowlist.ips = set
	trustedProxyAllowlist.set = len(set) > 0
	trustedProxyAllowlist.mu.Unlock()
}

// isDeclaredProxy reports whether addr falls inside the operator-declared
// trusted-proxy list. Loopback/private ranges alone are deliberately NOT
// enough: containers, Kubernetes pods and home LANs are all "private", and a
// compromised or misbehaving private peer must not gain the right to rewrite
// the address the security decisions key on.
func isDeclaredProxy(addr string) bool {
	trustedProxyAllowlist.mu.RLock()
	defer trustedProxyAllowlist.mu.RUnlock()
	if !trustedProxyAllowlist.set {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	for cidr := range trustedProxyAllowlist.ips {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP resolves the effective client address.
//
// Header trust requires BOTH conditions, per the finding that leftmost-trust
// behind a merely-private hop is attacker-controlled:
//
//  1. the immediate peer must be an operator-declared trusted proxy
//     (SetTrustedProxies), not merely loopback/private; and
//  2. the value taken is the RIGHTMOST X-Forwarded-For entry not appended by
//     one of our own proxies — the hop a conforming proxy chain adds last —
//     with X-Real-IP from the declared proxy as the fallback.
//
// With no allowlist configured every caller is its own peer. That is the
// documented default: an operator who fronts the daemon with nginx declares
// the proxy once and the semantics are right from then on.
func ClientIP(r *http.Request) string {
	peer := PeerIP(r)
	if !isDeclaredProxy(peer) {
		return peer
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Walk right to left; the first entry not belonging to our own proxy
		// list is the client as the nearest declared proxy saw it. A client
		// may prepend anything it likes — every entry left of the proxy-added
		// tail is attacker text.
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			cand := strings.TrimSpace(parts[i])
			ip := net.ParseIP(cand)
			if ip == nil {
				continue
			}
			if isDeclaredProxy(cand) {
				continue // our own proxy hop; keep walking left
			}
			return cand
		}
	}
	if rip := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(rip) != nil && !isDeclaredProxy(rip) {
		return rip
	}
	return peer
}

// IsTrustedHop is retained for compatibility with existing call sites; the
// security decision moved to isDeclaredProxy. It reports whether addr belongs
// to this machine or a private network — a weak property that must not be
// confused with "allowed to forward identity headers".
func IsTrustedHop(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}
