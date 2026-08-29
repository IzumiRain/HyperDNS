package sniproxy

import (
	"bytes"
	"errors"
)

// ExtractSNI parses the TLS ClientHello handshake and returns the Server Name Indication hostname.
func ExtractSNI(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("data too short for TLS header")
	}

	// TLS Record Header: ContentType 0x16 (Handshake)
	if data[0] != 0x16 {
		return "", errors.New("not a TLS handshake record")
	}

	pos := 5
	// Handshake type (1 byte) = 0x01 (ClientHello)
	if pos >= len(data) || data[pos] != 0x01 {
		return "", errors.New("not a ClientHello handshake")
	}

	pos += 4 // Skip Handshake Type (1) + Length (3)
	pos += 2 // Skip Client Version (2)
	pos += 32 // Skip Random (32)

	if pos >= len(data) {
		return "", errors.New("truncated ClientHello at Random")
	}

	// Session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return "", errors.New("truncated ClientHello at SessionID")
	}

	// Cipher Suites
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return "", errors.New("truncated ClientHello at CipherSuites")
	}

	// Compression Methods
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen
	if pos+2 > len(data) {
		return "", errors.New("no TLS extensions present")
	}

	// Extensions
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	end := pos + extensionsLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > end {
			break
		}

		// Server Name Extension (Type = 0x0000)
		if extType == 0x0000 {
			if extLen < 5 {
				return "", errors.New("invalid SNI extension length")
			}
			// Server Name List Length (2) + Server Name Type (1) = 0 (host_name)
			nameType := data[pos+2]
			if nameType == 0 {
				nameLen := int(data[pos+3])<<8 | int(data[pos+4])
				nameStart := pos + 5
				if nameStart+nameLen <= pos+extLen {
					sni := string(data[nameStart : nameStart+nameLen])
					return sni, nil
				}
			}
		}
		pos += extLen
	}

	return "", errors.New("SNI extension not found")
}

// ExtractHTTPHost extracts the Host header from an unencrypted HTTP request
func ExtractHTTPHost(data []byte) (string, error) {
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				host := bytes.TrimSpace(parts[1])
				// remove port if present e.g. example.com:80
				if idx := bytes.IndexByte(host, ':'); idx != -1 {
					host = host[:idx]
				}
				return string(host), nil
			}
		}
	}
	return "", errors.New("HTTP host header not found")
}
