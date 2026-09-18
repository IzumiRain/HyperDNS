package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
)

// clientHello captures the record crypto/tls actually emits for cfg, so the
// parser is exercised against a hello a current client really sends — real key
// shares, real extension order, real length — not a hand-built approximation.
func clientHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	go func() { _ = tls.Client(client, cfg).Handshake() }()

	buf := make([]byte, handshakeBufSize)
	n, err := readHandshake(server, buf, true)
	if err != nil {
		t.Fatalf("reading the ClientHello returned %v", err)
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}

func TestExtractSNI(t *testing.T) {
	for _, name := range []string{
		"example.com",
		strings.Repeat("a", 63) + ".example.com",
		"xn--80ak6aa92e.com",
	} {
		hello := clientHello(t, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
		got, err := ExtractSNI(hello)
		if err != nil {
			t.Errorf("ExtractSNI(hello for %q) returned %v", name, err)
			continue
		}
		if got != name {
			t.Errorf("ExtractSNI(hello for %q) = %q", name, got)
		}
	}

	// A hello with no server_name is well-formed; it just cannot be relayed.
	noSNI := clientHello(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if got, err := ExtractSNI(noSNI); !errors.Is(err, ErrNoSNI) {
		t.Errorf("ExtractSNI(hello without SNI) = (%q, %v), want ErrNoSNI", got, err)
	}
}

func TestExtractSNIMalformed(t *testing.T) {
	hello := clientHello(t, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12})

	malformed := []struct {
		in   []byte
		want error
		why  string
	}{
		{nil, ErrTruncated, "an empty buffer"},
		{[]byte{0x16}, ErrTruncated, "a record header cut after the type"},
		{[]byte{0x16, 0x03, 0x01, 0x00, 0x00}, ErrNotTLS, "a zero-length record"},
		{[]byte{0x16, 0x03, 0x01, 0xff, 0xff}, ErrNotTLS, "a record longer than TLS allows"},
		{[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), ErrNotTLS, "an HTTP request"},
		{append([]byte{0x15}, hello[1:]...), ErrNotTLS, "an alert record"},
		{append([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x02}, hello[6:]...), ErrNotTLS, "a ServerHello"},
	}
	for _, tc := range malformed {
		got, err := ExtractSNI(tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("ExtractSNI(%s) = (%q, %v), want %v", tc.why, got, err, tc.want)
		}
	}
}

// TestExtractSNIPrefixes feeds every prefix of a real ClientHello to the parser.
// The bytes arrive from an unauthenticated socket, so every length is reachable:
// each one must either fail or return the correct name, and none may panic.
func TestExtractSNIPrefixes(t *testing.T) {
	hello := clientHello(t, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12})
	for i := 0; i <= len(hello); i++ {
		got, err := ExtractSNI(hello[:i])
		if err == nil && got != "example.com" {
			t.Fatalf("ExtractSNI(hello[:%d]) = %q with no error, want the name or a failure", i, got)
		}
	}
}

// TestExtractSNIMutations corrupts one byte at a time. A length field forced to
// 0x00 or 0xff is the cheapest way to make a parser walk off its buffer, and
// every such byte is attacker-controlled here.
func TestExtractSNIMutations(t *testing.T) {
	hello := clientHello(t, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12})
	for i := range hello {
		for _, b := range []byte{0x00, 0x01, 0x7f, 0xff} {
			mutated := make([]byte, len(hello))
			copy(mutated, hello)
			mutated[i] = b
			// The result is not asserted: a mutated length can legitimately
			// yield a different name. Not panicking is the property under test.
			_, _ = ExtractSNI(mutated)
		}
	}
}

func TestExtractHTTPHost(t *testing.T) {
	ok := map[string]string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n":                      "example.com",
		"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n":                      "example.com",
		"GET / HTTP/1.1\r\nHOST:\texample.com  \r\n\r\n":                   "example.com",
		"GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n":                 "example.com",
		"GET / HTTP/1.1\r\nHost: [2606:4700::1111]:443\r\n\r\n":            "[2606:4700::1111]",
		"GET / HTTP/1.1\r\nHost: [2606:4700::1111]\r\n\r\n":                "[2606:4700::1111]",
		"GET / HTTP/1.1\r\nX-A: 1\r\nHost: example.com\r\nX-B: 2\r\n\r\n":  "example.com",
		"GET / HTTP/1.1\nHost: example.com\n\n":                            "example.com",
		"GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n": "example.com",
		// A body line that looks like a header is not one.
		"POST / HTTP/1.1\r\nHost: example.com\r\n\r\nHost: evil.example\r\n": "example.com",
	}
	for in, want := range ok {
		got, err := ExtractHTTPHost([]byte(in))
		if err != nil {
			t.Errorf("ExtractHTTPHost(%q) returned %v, want %q", in, err, want)
			continue
		}
		if got != want {
			t.Errorf("ExtractHTTPHost(%q) = %q, want %q", in, got, want)
		}
	}

	bad := []struct {
		in   string
		want error
		why  string
	}{
		{"", ErrNoHostHeader, "an empty request"},
		{"GET / HTTP/1.1\r\n\r\n", ErrNoHostHeader, "no Host header at all"},
		{"GET / HTTP/1.1\r\nHost:\r\n\r\n", ErrNoHostHeader, "an empty Host value"},
		{"GET / HTTP/1.1\r\nHost: example.com", ErrNoHostHeader, "headers that never end"},
		{"POST / HTTP/1.1\r\nA: 1\r\n\r\nHost: evil.example\r\n", ErrNoHostHeader,
			"a Host line that is only in the body"},
		{"GET / HTTP/1.1\r\nHost: example.com\r\nHost: evil.example\r\n\r\n", ErrHostAmbiguous,
			"two Host headers that disagree"},
		{"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n", ErrHostAmbiguous,
			"a header name padded before the colon"},
		{"GET / HTTP/1.1\r\nHost: example.com\r\n\tevil.example\r\n\r\n", ErrHostAmbiguous,
			"an obs-fold continuation line"},
	}
	for _, tc := range bad {
		got, err := ExtractHTTPHost([]byte(tc.in))
		if !errors.Is(err, tc.want) {
			t.Errorf("ExtractHTTPHost(%q) = (%q, %v), want %v (%s)", tc.in, got, err, tc.want, tc.why)
		}
	}
}

// FuzzExtractSNI runs its seed corpus on every `go test` and can be driven
// further with -fuzz. The parser reads bytes straight off an unauthenticated
// socket, so a panic in it is remotely reachable by anyone who can connect.
func FuzzExtractSNI(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add(clientHello(f, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12}))

	f.Fuzz(func(t *testing.T, data []byte) {
		name, err := ExtractSNI(data)
		if err == nil && name == "" {
			t.Fatal("ExtractSNI returned an empty name and no error")
		}
	})
}

// FuzzExtractHTTPHost additionally asserts the contract the relay depends on:
// whatever the parser returns is something the guard can classify, so no value
// can slip through to a dialer unexamined.
func FuzzExtractHTTPHost(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\nHost: [::1]:80\n\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		host, err := ExtractHTTPHost(data)
		if err != nil {
			return
		}
		if host == "" {
			t.Fatal("ExtractHTTPHost returned an empty host and no error")
		}
		if _, err := NormalizeHostname(host); err != nil &&
			!errors.Is(err, ErrTargetMalformed) && !errors.Is(err, ErrTargetBlocked) {
			t.Fatalf("NormalizeHostname(%q) returned an unclassified error: %v", host, err)
		}
	})
}
