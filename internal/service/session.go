package service

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// SessionTokenPrefix is the marker every dashboard session token carries. It is
// exported so a caller that must distinguish a session from the master REST key —
// the logout route, which has a session to revoke only in the first case — reads
// the same constant the minting and validation paths use instead of re-spelling
// it.
const SessionTokenPrefix = "hdns_session_"

const sessionPrefix = SessionTokenPrefix

// sessionTokenBytes is the entropy behind a token. 32 bytes is far past the point
// where guessing is a threat; the cost of the extra bytes is a longer header.
const sessionTokenBytes = 32

// DefaultSessionIdleTimeout is how long a session may sit unused before it is
// revoked. The absolute lifetime alone is not enough: a dashboard left open on an
// unattended machine, or a token copied out of localStorage, stays usable for the
// whole window otherwise. Two hours is long enough that an operator working
// through a settings change is never logged out mid-task.
const DefaultSessionIdleTimeout = 2 * time.Hour

// sessionTouchInterval is how stale lastSeen may get before Validate writes it
// back. Without it every authenticated request would take the write lock; with
// it, a busy dashboard takes it at most once a minute per session. It is capped
// at a quarter of the idle window, so a short idle timeout still gets refreshed
// often enough to actually behave as an idle timeout rather than an absolute one.
const sessionTouchInterval = time.Minute

type session struct {
	// expires is the hard ceiling, set once at creation and never extended, so a
	// stolen token cannot be kept alive indefinitely by using it.
	expires time.Time
	// lastSeen slides forward as the session is used and drives the idle timeout.
	lastSeen time.Time
}

// SessionManager holds server-side dashboard login sessions.
// Session tokens are only valid while present in this in-memory store
// and are wiped on daemon restart, forcing re-authentication.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]session
	ttl      time.Duration
	idleTTL  time.Duration
	// touchAfter is the resolved lastSeen write-back interval, derived from idleTTL.
	touchAfter time.Duration
	stop       chan struct{}
	stopOnce   sync.Once
}

func NewSessionManager(ttl time.Duration) *SessionManager {
	return NewSessionManagerWithIdle(ttl, DefaultSessionIdleTimeout)
}

// NewSessionManagerWithIdle builds a manager with an explicit idle timeout. An
// idle timeout longer than the absolute lifetime is clamped, since it could never
// fire.
func NewSessionManagerWithIdle(ttl, idleTTL time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if idleTTL <= 0 {
		idleTTL = DefaultSessionIdleTimeout
	}
	if idleTTL > ttl {
		idleTTL = ttl
	}
	touchAfter := sessionTouchInterval
	if quarter := idleTTL / 4; quarter < touchAfter {
		touchAfter = quarter
	}
	if touchAfter <= 0 {
		touchAfter = time.Millisecond
	}
	s := &SessionManager{
		sessions:   make(map[string]session),
		ttl:        ttl,
		idleTTL:    idleTTL,
		touchAfter: touchAfter,
		stop:       make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Create mints a new random session token prefixed with hdns_session_.
//
// The read from crypto/rand is not error-checked because as of Go 1.24 it cannot
// fail: rand.Read always fills the buffer and panics if the operating system's
// entropy source is broken. A silent short read — a token an attacker could
// guess — is therefore not a state this function can reach.
func (s *SessionManager) Create() string {
	b := make([]byte, sessionTokenBytes)
	rand.Read(b) //nolint:errcheck // cannot fail; panics instead (Go >= 1.24)
	token := sessionPrefix + hex.EncodeToString(b)

	now := time.Now()
	s.mu.Lock()
	s.sessions[token] = session{expires: now.Add(s.ttl), lastSeen: now}
	s.mu.Unlock()
	return token
}

// Validate reports whether the token is a live session, and marks it as used.
// A token that is past its absolute lifetime or has been idle too long is revoked
// rather than merely rejected, so a replay cannot keep probing it.
func (s *SessionManager) Validate(token string) bool {
	if !strings.HasPrefix(token, sessionPrefix) {
		return false
	}
	s.mu.RLock()
	sess, ok := s.sessions[token]
	idleTTL := s.idleTTL
	touchAfter := s.touchAfter
	s.mu.RUnlock()
	if !ok {
		return false
	}

	now := time.Now()
	if now.After(sess.expires) || now.Sub(sess.lastSeen) > idleTTL {
		s.Delete(token)
		return false
	}

	if now.Sub(sess.lastSeen) >= touchAfter {
		s.mu.Lock()
		// Re-read: the session may have been revoked while the lock was released.
		if cur, still := s.sessions[token]; still {
			cur.lastSeen = now
			s.sessions[token] = cur
		}
		s.mu.Unlock()
	}
	return true
}

// DeleteAll revokes all active sessions (e.g. after admin password change).
func (s *SessionManager) DeleteAll() {
	s.mu.Lock()
	s.sessions = make(map[string]session)
	s.mu.Unlock()
}

// Delete revokes a single session token (logout / expiry).
func (s *SessionManager) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// Count returns the number of stored sessions, expired ones included until the
// next sweep. Used by diagnostics and tests.
func (s *SessionManager) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// SetIdleTimeout adjusts the idle window at runtime (Phase D): the dashboard's
// settings card can tighten or relax it without a restart. The floor of one
// minute keeps a zero/negative save from turning the panel into an immediate
// log-out loop; the ceiling stays clamped to the absolute lifetime as in the
// constructor. The touch interval rides along, so a shorter window still gets
// refreshed often enough to behave as an idle timeout.
func (s *SessionManager) SetIdleTimeout(idleTTL time.Duration) {
	if idleTTL < time.Minute {
		idleTTL = time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if idleTTL > s.ttl {
		idleTTL = s.ttl
	}
	s.idleTTL = idleTTL
	touchAfter := sessionTouchInterval
	if quarter := idleTTL / 4; quarter < touchAfter {
		touchAfter = quarter
	}
	if touchAfter <= 0 {
		touchAfter = time.Millisecond
	}
	s.touchAfter = touchAfter
}

// IdleTimeout reports the window in force, for the settings card to display.
func (s *SessionManager) IdleTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.idleTTL
}

// Close stops the background sweep. Safe to call more than once.
func (s *SessionManager) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for tok, sess := range s.sessions {
				if now.After(sess.expires) || now.Sub(sess.lastSeen) > s.idleTTL {
					delete(s.sessions, tok)
				}
			}
			s.mu.Unlock()
		}
	}
}
