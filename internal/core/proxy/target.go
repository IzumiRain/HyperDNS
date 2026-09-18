package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Reasons a relay target is refused. They are distinct errors so a caller can
// log why a connection was dropped without re-deriving the reason.
var (
	ErrTargetMalformed = errors.New("proxy: target hostname is malformed")
	ErrTargetBlocked   = errors.New("proxy: target resolves to a non-routable or local address")
	ErrTargetSelf      = errors.New("proxy: target resolves to this host")
)

// maxHostnameLen is the DNS limit on a presentation-format name.
const maxHostnameLen = 253

// blockedPrefixes are the ranges a relay must never reach: loopback and
// link-local (this daemon's own services, and 169.254.169.254 cloud metadata),
// RFC 1918 and CGNAT (the operator's LAN), plus the reserved and benchmark
// ranges that have no business being proxied. Reaching any of them turns the SNI
// relay into an SSRF pivot into the network hosting the daemon.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local + cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC 1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC 1918
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved + 255.255.255.255
	netip.MustParsePrefix("::/128"),          // unspecified
	netip.MustParsePrefix("::1/128"),         // loopback
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("fc00::/7"),        // unique-local
	netip.MustParsePrefix("fe80::/10"),       // link-local
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
	netip.MustParsePrefix("ff00::/8"),        // multicast
}

// embeddedV4Prefixes wrap an IPv4 address inside an IPv6 one, so the inner
// address has to be unwrapped and checked as well: 2002:7f00:1:: is the 6to4
// form of 127.0.0.1 and 64:ff9b::7f00:1 is its NAT64 form, neither of which any
// IPv6 prefix above describes.
var embeddedV4Prefixes = []struct {
	prefix netip.Prefix
	offset int // byte offset of the embedded IPv4 address within the 16-byte form
}{
	{netip.MustParsePrefix("2002::/16"), 2},     // RFC 3056 6to4
	{netip.MustParsePrefix("64:ff9b::/96"), 12}, // RFC 6052 well-known NAT64
}

// embeddedV4 extracts the IPv4 address tunnelled inside an IPv6 address, if any.
func embeddedV4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() || addr.Is4In6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	for _, e := range embeddedV4Prefixes {
		if e.prefix.Contains(addr) {
			return netip.AddrFrom4([4]byte{b[e.offset], b[e.offset+1], b[e.offset+2], b[e.offset+3]}), true
		}
	}
	return netip.Addr{}, false
}

// IsBlockedAddr reports whether addr is in a range the relay refuses to dial.
func IsBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	// A zone identifier only ever scopes an address to a local interface.
	if addr.Zone() != "" {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	// One level of recursion only: embeddedV4 never matches an IPv4 address.
	if inner, ok := embeddedV4(addr); ok && IsBlockedAddr(inner) {
		return true
	}
	return false
}

// NormalizeHostname canonicalises a hostname taken from a ClientHello or a Host
// header and rejects anything the OS resolver might read differently from this
// code. "127.0.0.1." and "[::1]" are the same targets as their bare forms, and a
// bare "2130706433" is not a DNS name at all yet getaddrinfo turns it into
// 127.0.0.1 — so every accepted value is either a well-formed IP literal or a
// legal DNS name, and nothing in between.
func NormalizeHostname(host string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	// A Host header may carry the authority in bracketed IPv6 form.
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	// A trailing dot is a legal fully-qualified name that a string comparison
	// against "localhost" would miss.
	h = strings.TrimRight(h, ".")

	switch {
	case h == "":
		return "", fmt.Errorf("%w: empty", ErrTargetMalformed)
	case len(h) > maxHostnameLen:
		return "", fmt.Errorf("%w: %d bytes exceeds the %d-byte DNS limit",
			ErrTargetMalformed, len(h), maxHostnameLen)
	}

	// An IP literal needs no name validation; IsBlockedAddr vets it instead.
	if _, err := netip.ParseAddr(h); err == nil {
		return h, nil
	}
	if err := validateDNSName(h); err != nil {
		return "", err
	}
	if suffix, ok := blockedSuffix(h); ok {
		return "", fmt.Errorf("%w: %q is in the non-public %q namespace",
			ErrTargetBlocked, h, suffix)
	}
	return h, nil
}

// blockedNamespaces are name suffixes that only ever denote something local: the
// loopback interface, an mDNS neighbour, or an internal corporate zone. They are
// refused on the name so that a hostile or misconfigured resolver answering
// "localhost" with a routable address still cannot get a relay.
var blockedNamespaces = []string{
	"localhost", "local", "internal", "intranet", "private",
	"corp", "lan", "home.arpa", "onion",
}

func blockedSuffix(h string) (string, bool) {
	for _, ns := range blockedNamespaces {
		if h == ns || strings.HasSuffix(h, "."+ns) {
			return ns, true
		}
	}
	return "", false
}

func validateDNSName(h string) error {
	allNumeric := true
	for _, label := range strings.Split(h, ".") {
		switch {
		case label == "":
			return fmt.Errorf("%w: %q contains an empty label", ErrTargetMalformed, h)
		case len(label) > 63:
			return fmt.Errorf("%w: label %q exceeds 63 bytes", ErrTargetMalformed, label)
		case label[0] == '-' || label[len(label)-1] == '-':
			return fmt.Errorf("%w: label %q starts or ends with a hyphen", ErrTargetMalformed, label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c == '-', c == '_':
				allNumeric = false
			case c >= '0' && c <= '9':
			default:
				return fmt.Errorf("%w: %q contains a byte that is not valid in a DNS name",
					ErrTargetMalformed, h)
			}
		}
	}
	// "2130706433" and "0177.0.0.1" parse as no IP at all, yet resolve to
	// 127.0.0.1 through getaddrinfo. No real DNS name is made of digits and dots
	// alone, so refusing that shape closes the whole family of alternate integer
	// encodings in one check.
	if allNumeric {
		return fmt.Errorf("%w: %q is an alternate numeric address encoding, not a hostname",
			ErrTargetMalformed, h)
	}
	return nil
}

// selfAddrTTL bounds how long the set of local addresses is trusted. Interfaces
// come and go and DHCP leases change, so the set is refreshed rather than being
// captured once at start-up.
const selfAddrTTL = 30 * time.Second

// targetGuard vets relay destinations. lookupIP and localAddrs are fields rather
// than direct calls so the vetting rules can be tested without a live resolver
// or a particular host configuration.
type targetGuard struct {
	mu        sync.Mutex
	selfAddrs map[netip.Addr]struct{}
	refreshed time.Time

	lookupIP   func(ctx context.Context, host string) ([]netip.Addr, error)
	localAddrs func() map[netip.Addr]struct{}
	now        func() time.Time
}

func newTargetGuard() *targetGuard {
	return &targetGuard{
		lookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		localAddrs: localAddrSet,
		now:        time.Now,
	}
}

// isSelf reports whether addr belongs to this machine. Relaying there makes the
// daemon connect to itself: at best a loop burning two relay slots per request,
// at worst a route to a service bound to the machine's public address, which no
// block list of reserved ranges can describe.
func (g *targetGuard) isSelf(addr netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.selfAddrs == nil || g.now().Sub(g.refreshed) > selfAddrTTL {
		g.selfAddrs = g.localAddrs()
		g.refreshed = g.now()
	}
	_, ok := g.selfAddrs[addr]
	return ok
}

// localAddrSet collects every address configured on this machine's interfaces.
func localAddrSet() map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{}, 8)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return set
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			set[addr.Unmap()] = struct{}{}
		}
	}
	return set
}

// resolve canonicalises host, resolves it and returns the addresses that are
// safe to dial. Vetting happens on the resolved addresses, not on the hostname
// alone: "rebind.example.com" is an ordinary name that can answer with
// 127.0.0.1, so a string check leaves the relay wide open. The caller dials one
// of the returned addresses directly, so the name cannot resolve to something
// else between this check and the connection.
func (g *targetGuard) resolve(ctx context.Context, host string) (string, []netip.Addr, error) {
	name, err := NormalizeHostname(host)
	if err != nil {
		return "", nil, err
	}

	if literal, perr := netip.ParseAddr(name); perr == nil {
		addr := literal.Unmap()
		if err := g.vet(name, addr); err != nil {
			return "", nil, err
		}
		return name, []netip.Addr{addr}, nil
	}

	resolved, err := g.lookupIP(ctx, name)
	if err != nil {
		return "", nil, fmt.Errorf("proxy: resolving %s: %w", name, err)
	}

	allowed := make([]netip.Addr, 0, len(resolved))
	for _, addr := range resolved {
		// A single poisoned answer condemns the whole name: a rebinding attacker
		// returns one public and one private address and relies on the proxy
		// happening to pick the private one.
		if err := g.vet(name, addr.Unmap()); err != nil {
			return "", nil, err
		}
		allowed = append(allowed, addr.Unmap())
	}
	if len(allowed) == 0 {
		return "", nil, fmt.Errorf("%w: %s has no usable addresses", ErrTargetBlocked, name)
	}
	return name, allowed, nil
}

// vet applies the block list and the self-address check to one address.
func (g *targetGuard) vet(name string, addr netip.Addr) error {
	if IsBlockedAddr(addr) {
		return fmt.Errorf("%w: %s -> %s", ErrTargetBlocked, name, addr)
	}
	if g.isSelf(addr) {
		return fmt.Errorf("%w: %s -> %s", ErrTargetSelf, name, addr)
	}
	return nil
}
