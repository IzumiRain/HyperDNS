package dns

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

type DoHHandler struct {
	dnsHandler *Handler
}

func NewDoHHandler(dnsHandler *Handler) *DoHHandler {
	return &DoHHandler{dnsHandler: dnsHandler}
}

func (h *DoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Check DoH Token if configured
	if !h.isTokenAuthorized(r) {
		http.Error(w, "Unauthorized DoH Token", http.StatusUnauthorized)
		return
	}

	clientIP := h.extractClientIP(r)

	// Accept RFC 8484 DNS queries
	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam != "" {
			// Base64URL decoded raw DNS message
			raw, err := base64.RawURLEncoding.DecodeString(dnsParam)
			if err != nil {
				// Retry with standard URL encoding
				raw, err = base64.URLEncoding.DecodeString(dnsParam)
			}
			if err != nil {
				http.Error(w, "Invalid Base64 DNS parameter", http.StatusBadRequest)
				return
			}
			h.handleRawDNS(w, raw, clientIP)
			return
		}

		// Handle simple JSON-like queries: ?name=example.com&type=A
		name := r.URL.Query().Get("name")
		if name != "" {
			qtypeStr := r.URL.Query().Get("type")
			qtype := dns.TypeA
			if qtypeStr != "" {
				if t, ok := dns.StringToType[strings.ToUpper(qtypeStr)]; ok {
					qtype = t
				}
			}

			req := new(dns.Msg)
			req.SetQuestion(dns.Fqdn(name), qtype)
			req.RecursionDesired = true

			resp := h.dnsHandler.ProcessQuery(req, clientIP, "DoH")
			raw, err := resp.Pack()
			if err != nil {
				http.Error(w, "Failed to pack response", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/dns-message")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
			return
		}

		http.Error(w, "Missing dns query parameter", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil || len(body) == 0 {
			http.Error(w, "Empty or invalid body", http.StatusBadRequest)
			return
		}
		h.handleRawDNS(w, body, clientIP)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (h *DoHHandler) handleRawDNS(w http.ResponseWriter, raw []byte, clientIP string) {
	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		http.Error(w, "Failed to unpack DNS message", http.StatusBadRequest)
		return
	}

	resp := h.dnsHandler.ProcessQuery(req, clientIP, "DoH")
	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packed)
}

func (h *DoHHandler) isTokenAuthorized(r *http.Request) bool {
	access := &h.dnsHandler.cfg.Access
	if len(access.DoHTokens) == 0 {
		return true
	}

	// 1. Check Query Parameter: ?token=XYZ or ?key=XYZ
	tok := r.URL.Query().Get("token")
	if tok == "" {
		tok = r.URL.Query().Get("key")
	}

	// 2. Check Authorization Header
	if tok == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			tok = strings.TrimPrefix(auth, "Bearer ")
		}
	}

	if tok == "" {
		return false
	}

	for _, valid := range access.DoHTokens {
		if strings.TrimSpace(valid) == tok {
			return true
		}
	}
	return false
}

func (h *DoHHandler) extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For or RemoteAddr
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
