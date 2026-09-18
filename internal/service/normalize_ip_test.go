package service

import (
	"errors"
	"testing"
)

// normalizeAllowedIP is the single choke point between what an operator types and
// what the resolver can match, and the match is a map lookup on an exact string —
// not an address comparison. So every accepted-but-wrong form is a subscriber who
// cannot resolve while the dashboard insists their address is whitelisted, and the
// operator has no symptom to work from. These are the forms that reached the
// database before it existed.
func TestNormalizeAllowedIP(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// The canonical forms pass through untouched.
		{"plain v4", "203.0.113.9", "203.0.113.9"},
		{"plain v6", "2001:db8::1", "2001:db8::1"},

		// A pasted address brings its surroundings with it.
		{"leading and trailing space", "  203.0.113.9  ", "203.0.113.9"},
		{"tab padded", "\t203.0.113.9\n", "203.0.113.9"},
		{"v4 with port, as copied from a log line", "203.0.113.9:53", "203.0.113.9"},
		{"v6 with port and brackets", "[2001:db8::1]:853", "2001:db8::1"},
		{"bracketed v6 without a port", "[2001:db8::1]", "2001:db8::1"},

		// Canonicalisation: the stored form has to be the one the listener reports.
		{"v4-mapped v6 collapses to the dotted quad", "::ffff:203.0.113.9", "203.0.113.9"},
		{"upper-case v4-mapped v6 collapses too", "::FFFF:203.0.113.9", "203.0.113.9"},
		{"upper-case v6 is lower-cased", "2001:DB8::AB", "2001:db8::ab"},
		{"expanded v6 is compressed", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"v6 loopback", "::1", "::1"},

		// Empty means "no address on file", which both UpdateClient and SetClientIP
		// rely on to clear the list. It is not an error.
		{"empty", "", ""},
		{"only whitespace", "   ", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeAllowedIP(tc.in)
			if err != nil {
				t.Fatalf("normalizeAllowedIP(%q) returned an error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeAllowedIP(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeAllowedIPRejects covers the input that must not reach the database.
// Every one of these used to be stored and displayed as the client's allowed IP.
func TestNormalizeAllowedIPRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"octet out of range", "203.0.113.999"},
		{"three octets", "203.0.113"},
		{"five octets", "203.0.113.9.1"},
		{"a hostname is not an address", "dns.example.com"},
		{"a CIDR block is not an address", "203.0.113.0/24"},
		{"leading zeros are ambiguous between octal and decimal", "010.1.1.1"},
		{"negative octet", "203.0.113.-1"},
		{"letters in a v4", "203.0.113.9a"},
		{"a bare word", "localhost"},
		{"too many v6 groups", "2001:db8::1::2"},
		{"a stray quote from a copy-paste", `"203.0.113.9"`},
		{"a URL", "https://203.0.113.9"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeAllowedIP(tc.in)
			if err == nil {
				t.Fatalf("normalizeAllowedIP(%q) accepted it and returned %q", tc.in, got)
			}
			// The sentinel is what lets a handler answer 400 instead of 500. A
			// plain error here means the dashboard tells the operator the daemon
			// failed when the honest answer is "that is not an address".
			if !errors.Is(err, ErrInvalidIP) {
				t.Errorf("normalizeAllowedIP(%q) returned %v, which does not wrap ErrInvalidIP", tc.in, err)
			}
			if got != "" {
				t.Errorf("normalizeAllowedIP(%q) returned %q alongside its error", tc.in, got)
			}
		})
	}
}

// TestNormalizeAllowedIPIsIdempotent is the property the index actually depends on:
// a value read back out of the database and normalised again must not change, or the
// address stored yesterday stops matching the key built today.
func TestNormalizeAllowedIPIsIdempotent(t *testing.T) {
	inputs := []string{
		"203.0.113.9",
		"  203.0.113.9:53 ",
		"::FFFF:203.0.113.9",
		"[2001:DB8::1]:853",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"",
	}

	for _, in := range inputs {
		once, err := normalizeAllowedIP(in)
		if err != nil {
			t.Fatalf("normalizeAllowedIP(%q): %v", in, err)
		}
		twice, err := normalizeAllowedIP(once)
		if err != nil {
			t.Fatalf("normalizeAllowedIP(%q) (second pass over %q): %v", once, in, err)
		}
		if once != twice {
			t.Errorf("not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}
