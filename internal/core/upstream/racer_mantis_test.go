package upstream

import (
	"testing"

	"github.com/miekg/dns"
)

// B-01: a TC=1 reply must never win a race nor be cached.
func TestUsableRcodeRejectsTruncated(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("x.example.test.", dns.TypeA)
	m.Rcode = dns.RcodeSuccess
	m.Truncated = true
	if usableRcode(m) {
		t.Error("a truncated SUCCESS was accepted as usable — it would beat a complete answer and poison the cache")
	}
	m.Truncated = false
	if !usableRcode(m) {
		t.Error("the same answer without TC should be usable")
	}
}
