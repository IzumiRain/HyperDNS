package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"hyperdns/internal/httpx"
)

// One-time SSE tickets (v2.1.0 A-06 remediation).
//
// EventSource cannot set headers, so the live-log stream used to accept the
// long-lived session token in the query string — a credential that leaks into
// access logs, browser history and Referer headers. The fix keeps the query
// string but never puts a long-lived credential in it: the dashboard exchanges
// its Bearer token once, via POST, for a ticket that is single-use and expires
// in 60 seconds. An intercepted URL therefore buys an attacker nothing after
// the first connection, and nothing at all if it is captured before use.

const (
	sseTicketTTL  = 60 * time.Second
	sseTicketSize = 16 // 128 bits of entropy
)

// sseTicketStore holds outstanding tickets. The mutex is fine at this scale:
// one ticket per operator tab connecting, not per query.
type sseTicketStore struct {
	mu      sync.Mutex
	tickets map[string]time.Time // value = expiry
}

func newSSETicketStore() *sseTicketStore {
	return &sseTicketStore{tickets: make(map[string]time.Time)}
}

// mint creates a fresh ticket bound to nothing but itself; the stream handler
// validates the caller's real credential separately after the redirect-free
// connect. Tickets are not tokens: they authorize exactly one /events/stream
// or /api/stream/queries handshake within the TTL and are consumed on use.
func (s *sseTicketStore) mint() string {
	b := make([]byte, sseTicketSize)
	_, _ = rand.Read(b)
	ticket := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Opportunistic sweep: the map holds at most a handful of entries, but a
	// swept map is a bounded map regardless of how many tabs were opened.
	now := time.Now()
	for k, exp := range s.tickets {
		if exp.Before(now) {
			delete(s.tickets, k)
		}
	}
	s.tickets[ticket] = now.Add(sseTicketTTL)
	return ticket
}

// consume validates and burns a ticket in one step.
func (s *sseTicketStore) consume(ticket string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.tickets[ticket]
	if !ok || exp.Before(time.Now()) {
		if ok {
			delete(s.tickets, ticket)
		}
		return false
	}
	delete(s.tickets, ticket)
	return true
}

// handleSSETicket exchanges a Bearer-authenticated request for a one-time
// ticket the EventSource can carry in its URL. POST only, auth required —
// the same gate as every other dashboard call, which is what makes the
// ticket's brevity safe.
func (ws *WebServer) handleSSETicket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	// The ticket is minted only for a caller already holding a valid session;
	// authGate with allowQueryToken=false keeps the query-string path out of
	// the exchange too.
	_ = r.Body.Close()
	ticket := ws.sseTickets.mint()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ticket":     ticket,
		"expires_in": int(sseTicketTTL.Seconds()),
	})
}

// sseTicketAuthorized reports whether the ?ticket= on the request is a live,
// unconsumed one-time ticket.
func (ws *WebServer) sseTicketAuthorized(r *http.Request) bool {
	t := r.URL.Query().Get("ticket")
	return t != "" && ws.sseTickets.consume(t)
}
