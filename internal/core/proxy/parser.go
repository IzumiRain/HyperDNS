package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Parse failures are distinct errors so the relay can tell "this is not TLS at
// all" from "this is a ClientHello that carries no name to relay to".
var (
	ErrNotTLS        = errors.New("proxy: not a TLS ClientHello")
	ErrTruncated     = errors.New("proxy: handshake is truncated")
	ErrNoSNI         = errors.New("proxy: ClientHello carries no server_name extension")
	ErrNoHostHeader  = errors.New("proxy: request carries no usable Host header")
	ErrHostAmbiguous = errors.New("proxy: request carries conflicting Host headers")
)

const (
	tlsHandshakeRecord = 0x16
	tlsClientHello     = 0x01
	extServerName      = 0x0000
	sniHostName        = 0x00
	// maxTLSRecord is the largest fragment RFC 8446 allows, so a longer length
	// field describes a malformed record rather than a big ClientHello.
	maxTLSRecord = 1 << 14
)

// cursor walks a byte slice and refuses to read past its end. The parser it
// replaces advanced a bare index and checked the result afterwards, so every
// check that was missed became an out-of-range read on a crafted ClientHello.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) u8() (int, bool) {
	if c.pos+1 > len(c.b) {
		return 0, false
	}
	v := int(c.b[c.pos])
	c.pos++
	return v, true
}

func (c *cursor) u16() (int, bool) {
	if c.pos+2 > len(c.b) {
		return 0, false
	}
	v := int(c.b[c.pos])<<8 | int(c.b[c.pos+1])
	c.pos += 2
	return v, true
}

func (c *cursor) u24() (int, bool) {
	if c.pos+3 > len(c.b) {
		return 0, false
	}
	v := int(c.b[c.pos])<<16 | int(c.b[c.pos+1])<<8 | int(c.b[c.pos+2])
	c.pos += 3
	return v, true
}

// take returns the next n bytes, or false when fewer than n remain.
func (c *cursor) take(n int) ([]byte, bool) {
	if n < 0 || c.pos+n > len(c.b) {
		return nil, false
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v, true
}

// takeVec reads a vector whose length prefix is size bytes wide, returning only
// the body. Confining each nested structure to the length its parent declared is
// what stops a record that lies about its own sizes from steering the parser.
func (c *cursor) takeVec(size int) ([]byte, bool) {
	var (
		n  int
		ok bool
	)
	switch size {
	case 1:
		n, ok = c.u8()
	case 2:
		n, ok = c.u16()
	case 3:
		n, ok = c.u24()
	}
	if !ok {
		return nil, false
	}
	return c.take(n)
}

// rest returns everything not yet read.
func (c *cursor) rest() []byte { return c.b[c.pos:] }

// ExtractSNI returns the server_name carried by a TLS ClientHello. Every field
// is read through a bounds-checked cursor, and a truncated record yields an error
// rather than a partially parsed name.
func ExtractSNI(data []byte) (string, error) {
	rec := &cursor{b: data}
	typ, ok := rec.u8()
	if !ok {
		return "", ErrTruncated
	}
	if typ != tlsHandshakeRecord {
		return "", fmt.Errorf("%w: record type 0x%02x", ErrNotTLS, typ)
	}
	if _, ok := rec.take(2); !ok { // legacy_record_version
		return "", ErrTruncated
	}
	recordLen, ok := rec.u16()
	if !ok {
		return "", ErrTruncated
	}
	if recordLen == 0 || recordLen > maxTLSRecord {
		return "", fmt.Errorf("%w: record length %d", ErrNotTLS, recordLen)
	}

	// Confine the handshake to the record it claims to be in, while tolerating a
	// record that has not fully arrived: readHandshake stops early when the peer
	// closes, and a hello whose SNI is already present is still usable.
	hs := &cursor{b: rec.rest()}
	if len(hs.b) > recordLen {
		hs.b = hs.b[:recordLen]
	}

	hsType, ok := hs.u8()
	if !ok {
		return "", ErrTruncated
	}
	if hsType != tlsClientHello {
		return "", fmt.Errorf("%w: handshake type 0x%02x", ErrNotTLS, hsType)
	}
	hsLen, ok := hs.u24()
	if !ok {
		return "", ErrTruncated
	}
	hello := &cursor{b: hs.rest()}
	if len(hello.b) > hsLen {
		hello.b = hello.b[:hsLen]
	}
	return sniFromHello(hello)
}

// sniFromHello walks the fixed part of the ClientHello to reach the extensions.
func sniFromHello(c *cursor) (string, error) {
	if _, ok := c.take(2 + 32); !ok { // legacy_version + random
		return "", ErrTruncated
	}
	if _, ok := c.takeVec(1); !ok { // legacy_session_id
		return "", ErrTruncated
	}
	if _, ok := c.takeVec(2); !ok { // cipher_suites
		return "", ErrTruncated
	}
	if _, ok := c.takeVec(1); !ok { // legacy_compression_methods
		return "", ErrTruncated
	}
	exts, ok := c.takeVec(2)
	if !ok {
		// A TLS 1.2 ClientHello may end here with no extension block at all. It
		// simply cannot carry a name, which is not the same as a bad record.
		return "", ErrNoSNI
	}
	return sniFromExtensions(&cursor{b: exts})
}

func sniFromExtensions(c *cursor) (string, error) {
	for {
		extType, ok := c.u16()
		if !ok {
			return "", ErrNoSNI
		}
		body, ok := c.takeVec(2)
		if !ok {
			return "", ErrTruncated
		}
		if extType == extServerName {
			return serverNameFromExtension(&cursor{b: body})
		}
	}
}

// serverNameFromExtension reads the ServerNameList of RFC 6066. Only host_name
// entries exist in practice; anything else is skipped rather than ending the scan.
func serverNameFromExtension(c *cursor) (string, error) {
	list, ok := c.takeVec(2)
	if !ok {
		return "", ErrTruncated
	}
	l := &cursor{b: list}
	for {
		nameType, ok := l.u8()
		if !ok {
			return "", ErrNoSNI
		}
		name, ok := l.takeVec(2)
		if !ok {
			return "", ErrTruncated
		}
		if nameType == sniHostName && len(name) > 0 {
			return string(name), nil
		}
	}
}

// ExtractHTTPHost returns the Host header of a plaintext HTTP request. Three
// things the previous version did are unsafe for a relay that picks its target
// from this value: it scanned the whole buffer, so a "Host:" line inside a request
// body was read as a header; it took the first of several Host headers, which is
// exactly the disagreement request-smuggling payloads are built on; and it cut the
// value at the first colon, mangling "[::1]:443" into "[".
func ExtractHTTPHost(data []byte) (string, error) {
	var head []byte
	switch {
	case bytes.Contains(data, []byte("\r\n\r\n")):
		head, _, _ = bytes.Cut(data, []byte("\r\n\r\n"))
	case bytes.Contains(data, []byte("\n\n")):
		head, _, _ = bytes.Cut(data, []byte("\n\n"))
	default:
		// An unterminated header block may still have a second, different Host
		// header in flight, and picking a target from a partial block is the
		// same ambiguity as picking one of two conflicting headers. Every real
		// request terminates its headers, so refusing costs nothing legitimate.
		return "", fmt.Errorf("%w: the header block is incomplete", ErrNoHostHeader)
	}

	var host string
	found := false
	for i, raw := range bytes.Split(head, []byte("\n")) {
		if i == 0 {
			continue // the request line, not a header
		}
		line := bytes.TrimSuffix(raw, []byte("\r"))
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Obsolete line folding. No current client emits it and parsers
			// disagree on how to unfold it, so such a request has no single
			// agreed Host and must not be relayed anywhere.
			return "", fmt.Errorf("%w: a header uses obsolete line folding", ErrHostAmbiguous)
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !bytes.EqualFold(bytes.TrimSpace(name), []byte("host")) {
			continue
		}
		if !bytes.Equal(name, bytes.TrimSpace(name)) {
			return "", fmt.Errorf("%w: %q is padded with whitespace", ErrHostAmbiguous, name)
		}
		v := stripPort(string(bytes.TrimSpace(value)))
		if found && v != host {
			return "", fmt.Errorf("%w: %q and %q", ErrHostAmbiguous, host, v)
		}
		host, found = v, true
	}
	if !found || host == "" {
		return "", ErrNoHostHeader
	}
	return host, nil
}

// stripPort removes a trailing ":port" from an authority. A bracketed IPv6
// literal keeps its brackets, which NormalizeHostname strips, and a bare IPv6
// literal — several colons, no port — is left alone.
func stripPort(authority string) string {
	if strings.HasPrefix(authority, "[") {
		if i := strings.LastIndex(authority, "]"); i >= 0 {
			return authority[:i+1]
		}
		return authority
	}
	if strings.Count(authority, ":") == 1 {
		return authority[:strings.IndexByte(authority, ':')]
	}
	return authority
}
