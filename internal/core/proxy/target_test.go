package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestIsBlockedAddr(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "0.0.0.0", "0.1.2.3",
		"10.0.0.1", "172.16.5.5", "172.31.255.254", "192.168.1.1",
		"100.64.0.1", "100.127.255.254", // CGNAT
		"169.254.169.254",                      // cloud metadata
		"192.0.0.1", "192.0.2.7", "198.18.0.1", // reserved / benchmark
		"198.51.100.9", "203.0.113.9", // TEST-NET
		"224.0.0.1", "239.1.1.1", "255.255.255.255", "240.0.0.1",
		"::", "::1", "fe80::1", "fd00::1", "fc00::1", "ff02::1",
		"fec0::1", "2001:db8::1", "100::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // v4-mapped
		"2002:7f00:0001::", // 6to4 wrapping 127.0.0.1
		"2002:0a00:0001::", // 6to4 wrapping 10.0.0.1
		"64:ff9b::7f00:1",  // NAT64 wrapping 127.0.0.1
	}
	for _, s := range blocked {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test fixture %q is not an address: %v", s, err)
		}
		if !IsBlockedAddr(addr) {
			t.Errorf("IsBlockedAddr(%s) = false, want true", s)
		}
	}

	allowed := []string{
		"1.1.1.1", "8.8.8.8", "93.184.216.34", "99.99.99.99",
		"100.63.255.255", "100.128.0.1", // just outside CGNAT
		"172.15.255.255", "172.32.0.1", // just outside RFC 1918
		"2606:4700:4700::1111", "2001:4860:4860::8888",
		"2002:0808:0808::", // 6to4 wrapping 8.8.8.8 is routable
	}
	for _, s := range allowed {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test fixture %q is not an address: %v", s, err)
		}
		if IsBlockedAddr(addr) {
			t.Errorf("IsBlockedAddr(%s) = true, want false", s)
		}
	}

	if !IsBlockedAddr(netip.Addr{}) {
		t.Error("the zero Addr must be treated as blocked")
	}
	if zoned := netip.MustParseAddr("fe80::1").WithZone("eth0"); !IsBlockedAddr(zoned) {
		t.Error("a zoned address is interface-scoped and must be blocked")
	}
}

func TestNormalizeHostname(t *testing.T) {
	ok := map[string]string{
		"example.com":        "example.com",
		"EXAMPLE.COM":        "example.com",
		"  example.com  ":    "example.com",
		"example.com.":       "example.com",
		"example.com...":     "example.com",
		"a-b.c_d.example":    "a-b.c_d.example",
		"1.1.1.1":            "1.1.1.1",
		"127.0.0.1.":         "127.0.0.1",
		"[2606:4700::1111]":  "2606:4700::1111",
		"[::1]":              "::1",
		"xn--80ak6aa92e.com": "xn--80ak6aa92e.com",
	}
	for in, want := range ok {
		got, err := NormalizeHostname(in)
		if err != nil {
			t.Errorf("NormalizeHostname(%q) returned %v, want %q", in, err, want)
			continue
		}
		if got != want {
			t.Errorf("NormalizeHostname(%q) = %q, want %q", in, got, want)
		}
	}

	// Every one of these reaches 127.0.0.1 through getaddrinfo but is not a
	// hostname, so the guard must refuse it before the resolver ever sees it.
	malformed := []string{
		"", "   ", ".", "..",
		"2130706433",      // decimal 127.0.0.1
		"0177.0.0.1",      // octal
		"127.1",           // short form
		"1.2.3.4.5.6",     // numeric, not a name
		"exa mple.com",    // space
		"exam\x00ple.com", // NUL injection
		"host\r\nX: y",    // header injection through a Host value
		"-leading.com",
		"trailing-.com",
		"a..b.com",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 130) + "com",
	}
	for _, in := range malformed {
		if got, err := NormalizeHostname(in); !errors.Is(err, ErrTargetMalformed) {
			t.Errorf("NormalizeHostname(%q) = (%q, %v), want ErrTargetMalformed", in, got, err)
		}
	}
}

// testGuard builds a guard whose resolver and local-address set are fixed, so
// the vetting rules are exercised without touching DNS or the host's interfaces.
func testGuard(answers map[string][]string, self []string) *targetGuard {
	selfSet := make(map[netip.Addr]struct{}, len(self))
	for _, s := range self {
		selfSet[netip.MustParseAddr(s)] = struct{}{}
	}
	return &targetGuard{
		lookupIP: func(_ context.Context, host string) ([]netip.Addr, error) {
			ips, ok := answers[host]
			if !ok {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			out := make([]netip.Addr, 0, len(ips))
			for _, ip := range ips {
				out = append(out, netip.MustParseAddr(ip))
			}
			return out, nil
		},
		localAddrs: func() map[netip.Addr]struct{} { return selfSet },
		now:        time.Now,
	}
}

func TestTargetGuardResolve(t *testing.T) {
	g := testGuard(map[string][]string{
		"good.example":     {"93.184.216.34"},
		"rebind.example":   {"127.0.0.1"},
		"mixed.example":    {"93.184.216.34", "10.0.0.5"},
		"self.example":     {"45.33.32.156"},
		"metadata.example": {"169.254.169.254"},
		"v6.example":       {"2606:4700:4700::1111"},
		"mapped.example":   {"::ffff:127.0.0.1"},
	}, []string{"45.33.32.156"})

	name, addrs, err := g.resolve(context.Background(), "GOOD.example.")
	if err != nil {
		t.Fatalf("resolve(good.example) returned %v", err)
	}
	if name != "good.example" {
		t.Errorf("resolved name = %q, want %q", name, "good.example")
	}
	if len(addrs) != 1 || addrs[0].String() != "93.184.216.34" {
		t.Errorf("resolved addrs = %v, want [93.184.216.34]", addrs)
	}

	blocked := []struct {
		host string
		want error
		why  string
	}{
		{"rebind.example", ErrTargetBlocked, "a public name answering with a loopback address"},
		{"mixed.example", ErrTargetBlocked, "one private address in the answer set condemns the name"},
		{"metadata.example", ErrTargetBlocked, "the cloud metadata endpoint"},
		{"mapped.example", ErrTargetBlocked, "an IPv4-mapped loopback address"},
		{"self.example", ErrTargetSelf, "an address configured on this host"},
		{"45.33.32.156", ErrTargetSelf, "this host by literal address"},
		{"127.0.0.1", ErrTargetBlocked, "a loopback literal"},
		{"[::1]", ErrTargetBlocked, "a bracketed loopback literal"},
		{"192.168.1.1.", ErrTargetBlocked, "a private literal with a trailing dot"},
		{"2130706433", ErrTargetMalformed, "the decimal encoding of 127.0.0.1"},
		{"localhost", ErrTargetBlocked, "the loopback namespace"},
		{"db.internal", ErrTargetBlocked, "an internal corporate namespace"},
		{"printer.local", ErrTargetBlocked, "an mDNS namespace"},
	}
	for _, tc := range blocked {
		_, _, err := g.resolve(context.Background(), tc.host)
		if err == nil {
			t.Errorf("resolve(%q) succeeded; %s must be refused", tc.host, tc.why)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("resolve(%q) = %v, want %v (%s)", tc.host, err, tc.want, tc.why)
		}
	}

	if _, _, err := g.resolve(context.Background(), "v6.example"); err != nil {
		t.Errorf("resolve(v6.example) returned %v, want a routable IPv6 answer to pass", err)
	}
	if _, _, err := g.resolve(context.Background(), "nxdomain.example"); err == nil {
		t.Error("resolve on a name with no answer must fail")
	}
}
