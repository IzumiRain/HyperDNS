package proxy

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// maybeServeACMEChallenge inspects an already-read plain-HTTP request head and
// answers it locally when — and only when — it is a valid HTTP-01 validation
// request this daemon is currently proving. It returns true when the
// connection has been answered and must not be relayed.
//
// The checks, all of which must pass, are what keep the carve-out from being
// an "answer any local HTTP" hole:
//
//   - the request line is a GET for /.well-known/acme-challenge/<token>, with
//     a token made only of the characters ACME tokens contain;
//   - the ACME manager recognizes the (Host, token) pair — the mapping exists
//     only while an issuance this daemon started is waiting for exactly that
//     validation, and the manager checks the Host against the domain the
//     order is for (not against any boot-time copy this proxy could hold).
//     A scanner replaying the path gets no answer, because no issuance is
//     proving its made-up token; a challenge for some other vhost is relayed
//     like any other request.
func (s *Server) maybeServeACMEChallenge(clientConn net.Conn, head []byte) bool {
	method, path, host, ok := parseHTTPRequestHead(head)
	if !ok || method != "GET" {
		return false
	}
	if !strings.HasPrefix(path, acmeChallengePrefix) {
		return false
	}
	token := path[len(acmeChallengePrefix):]
	if token == "" || strings.Contains(token, "/") || !isACToken(token) {
		return false
	}
	body, known := s.acme.ChallengeResponse(host, token)
	if !known {
		return false
	}

	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n\r\n" + body
	_ = clientConn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	_, _ = clientConn.Write([]byte(resp))
	s.acmeAnswered.Add(1)
	return true
}

// isACToken accepts the base64url alphabet ACME tokens are drawn from. Anything
// else in the path means the request is not a validation and the relay path
// should treat it exactly as it did before this code existed.
func isACToken(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// parseHTTPRequestHead pulls the method, path and Host out of a request head
// that readHandshake has already established is header-complete. Deliberately
// minimal: no headers beyond Host, no multi-line folding — the relay only ever
// needed Host, and the challenge check needs the request line too. ok=false
// for anything malformed, which sends the connection down the ordinary relay
// path (where a malformed head already produced no destination and was
// dropped).
func parseHTTPRequestHead(head []byte) (method, path, host string, ok bool) {
	lineEnd := bytes.IndexByte(head, '\n')
	if lineEnd < 0 {
		return "", "", "", false
	}
	requestLine := strings.TrimSpace(string(head[:lineEnd]))
	parts := strings.Fields(requestLine)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return "", "", "", false
	}
	method, path = parts[0], parts[1]

	rest := head[lineEnd+1:]
	for {
		idx := bytes.IndexByte(rest, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimSpace(string(rest[:idx]))
		rest = rest[idx+1:]
		if i := strings.IndexByte(line, ':'); i > 0 {
			name := strings.ToLower(strings.TrimSpace(line[:i]))
			if name == "host" {
				host = strings.TrimSpace(line[i+1:])
				break
			}
		}
	}
	if host == "" {
		return "", "", "", false
	}
	return method, path, host, true
}
