package dns

import (
	"testing"

	"github.com/miekg/dns"
)

// answerA returns the first A address in a reply, or "".
func answerA(resp *dns.Msg) string {
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

// A subscriber whose source IP changed falls off the whitelist and is REFUSED
// for everything — including the very portal link they need to re-register from.
// v2.6 answers the server's OWN service names (panel / portal / DoH-DoT host)
// with its public address ahead of the access gate, so that one door stays open.
func TestSelfServiceNamesResolveDespiteWhitelist(t *testing.T) {
	h := strictHandler(t) // allow_all off, every source unknown, publicIP 198.51.100.1
	h.SetSelfDomains([]string{"panel.example.com", "portal.example.com", "dot.example.com"})

	ask := func(name string, qtype uint16) *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
		return h.ProcessQuery(req, "203.0.113.99", "UDP") // an unregistered source
	}

	// A self name is answered with the public IP for an unregistered source.
	resp := ask("panel.example.com.", dns.TypeA)
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("self name A: want NOERROR, got %v", resp)
	}
	if got := answerA(resp); got != "198.51.100.1" {
		t.Fatalf("self name A: want 198.51.100.1, got %q", got)
	}

	// Matching is case- and trailing-dot-insensitive.
	if got := answerA(ask("PORTAL.Example.com.", dns.TypeA)); got != "198.51.100.1" {
		t.Fatalf("self name match must be case-insensitive, got %q", got)
	}

	// A non-self name from the same unregistered source is still REFUSED: the
	// self-service door does not turn the resolver into an open one.
	if resp := ask("notours.example.net.", dns.TypeA); resp == nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("a non-self name must stay refused for an unregistered source, got %v", resp)
	}

	// AAAA with no server IPv6 configured is a deliberate empty NOERROR.
	resp = ask("panel.example.com.", dns.TypeAAAA)
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("self name AAAA with no IPv6: want empty NOERROR, got %v", resp)
	}

	// With an IPv6 published, AAAA is answered too.
	h.SetPublicIPv6("2001:db8::1")
	if resp := ask("panel.example.com.", dns.TypeAAAA); resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("self name AAAA with IPv6 set: want an AAAA answer, got %v", resp)
	}
}

// TestSelfServiceUnsetResolvesNothingSpecial: with no self domains configured
// (the IP-only deployment), the access gate is unchanged and an unregistered
// source is refused as before.
func TestSelfServiceUnsetLeavesGateUnchanged(t *testing.T) {
	h := strictHandler(t)

	req := new(dns.Msg)
	req.SetQuestion("panel.example.com.", dns.TypeA)
	if resp := h.ProcessQuery(req, "203.0.113.99", "UDP"); resp == nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("with no self domains set, an unregistered source must be refused, got %v", resp)
	}
}
