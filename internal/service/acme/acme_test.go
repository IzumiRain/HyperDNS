package acme

// Unit tests for the HTTP-01 challenge answer's Host handling (Mantis v2.2.0
// A-8) and the account-key accessor (A-6).

import "testing"

func TestChallengeResponseAcceptsHostWithDefaultPort(t *testing.T) {
	m := NewManager("", "", t.TempDir(), nil)
	m.mu.Lock()
	m.pendingToken["token-1"] = "token-1.thumbprint"
	m.pendingDomains["dns.example.com"] = true
	m.mu.Unlock()

	cases := []struct {
		host string
		ok   bool
	}{
		{"dns.example.com", true},
		{"DNS.Example.com", true},
		{"dns.example.com:80", true}, // legal authority-form; some non-Go clients send it
		{"dns.example.com:8080", true},
		{"other.example.com", false},
		{"dns.example.com.evil.test", false},
	}
	for _, c := range cases {
		if _, ok := m.ChallengeResponse(c.host, "token-1"); ok != c.ok {
			t.Errorf("ChallengeResponse(%q) ok = %v, want %v", c.host, ok, c.ok)
		}
	}
	// The token is consumed only by the caller's lifecycle, not by reads here;
	// a refused host must not have burned it.
	if _, ok := m.ChallengeResponse("dns.example.com", "token-1"); !ok {
		t.Error("a refused-host attempt must not consume the pending token")
	}
}

func TestStripHostPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"dns.example.com", "dns.example.com"},
		{"dns.example.com:80", "dns.example.com"},
		{"[2001:db8::1]:80", "[2001:db8::1]"},
		{"::1", "::1"}, // a bare IPv6 literal is left alone; it never matches anyway
		{"host:", "host:"},
	}
	for _, c := range cases {
		if got := stripHostPort(c.in); got != c.want {
			t.Errorf("stripHostPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAccountKeyCopiesUnderLock(t *testing.T) {
	m := NewManager("", "", t.TempDir(), []byte("pem-bytes"))
	got := m.AccountKey()
	if string(got) != "pem-bytes" {
		t.Fatalf("AccountKey() = %q, want %q", got, "pem-bytes")
	}
	// A copy, not the backing array: the caller persisting it must not alias
	// state the manager can replace mid-issuance.
	got[0] = 'X'
	if string(m.AccountKey()) != "pem-bytes" {
		t.Error("AccountKey() must return a copy of the PEM")
	}
	if empty := (&Manager{}).AccountKey(); empty != nil {
		t.Errorf("AccountKey() on an empty manager = %v, want nil", empty)
	}
}
