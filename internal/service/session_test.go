package service

import (
	"strings"
	"testing"
	"time"
)

func TestSessionCreateAndValidate(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	defer sm.Close()

	tok := sm.Create()
	if !strings.HasPrefix(tok, sessionPrefix) {
		t.Fatalf("token %q lacks the %q prefix", tok, sessionPrefix)
	}
	// 32 random bytes as hex, plus the prefix.
	if want := len(sessionPrefix) + sessionTokenBytes*2; len(tok) != want {
		t.Fatalf("token length = %d, want %d", len(tok), want)
	}
	if !sm.Validate(tok) {
		t.Fatal("a freshly created session must validate")
	}
	if sm.Validate(tok + "0") {
		t.Fatal("a token with an extra character must not validate")
	}
	if sm.Validate("bearer-" + tok[len(sessionPrefix):]) {
		t.Fatal("a token without the prefix must not validate")
	}
	if sm.Validate("") {
		t.Fatal("an empty token must not validate")
	}
}

func TestSessionCreateIsUnique(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	defer sm.Close()

	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		tok := sm.Create()
		if _, dup := seen[tok]; dup {
			t.Fatalf("Create returned a duplicate token after %d calls", i)
		}
		seen[tok] = struct{}{}
	}
	if sm.Count() != 200 {
		t.Fatalf("Count = %d, want 200", sm.Count())
	}
}

func TestSessionAbsoluteExpiry(t *testing.T) {
	sm := NewSessionManagerWithIdle(40*time.Millisecond, 40*time.Millisecond)
	defer sm.Close()

	tok := sm.Create()
	time.Sleep(80 * time.Millisecond)
	if sm.Validate(tok) {
		t.Fatal("a session past its absolute lifetime must not validate")
	}
	// Rejection must also evict, so a replayed token cannot be probed forever.
	if sm.Count() != 0 {
		t.Fatalf("an expired session was rejected but left in the store (Count = %d)", sm.Count())
	}
}

// The absolute lifetime is a ceiling: using a session must not push it out.
func TestSessionAbsoluteExpiryIsNotExtendedByUse(t *testing.T) {
	sm := NewSessionManagerWithIdle(150*time.Millisecond, 150*time.Millisecond)
	defer sm.Close()

	tok := sm.Create()
	deadline := time.Now().Add(220 * time.Millisecond)
	for time.Now().Before(deadline) {
		sm.Validate(tok)
		time.Sleep(20 * time.Millisecond)
	}
	if sm.Validate(tok) {
		t.Fatal("continuous use extended the absolute lifetime")
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	// Long absolute lifetime, short idle window: only the idle rule can fire.
	sm := NewSessionManagerWithIdle(time.Hour, 60*time.Millisecond)
	defer sm.Close()

	tok := sm.Create()
	if !sm.Validate(tok) {
		t.Fatal("a fresh session must validate")
	}
	time.Sleep(120 * time.Millisecond)
	if sm.Validate(tok) {
		t.Fatal("a session idle beyond the idle timeout must not validate")
	}
}

// An idle timeout is only useful if activity actually resets it.
func TestSessionIdleTimeoutResetsOnUse(t *testing.T) {
	sm := NewSessionManagerWithIdle(time.Hour, 400*time.Millisecond)
	defer sm.Close()

	tok := sm.Create()
	// Keep it warm for longer than the idle window, in steps shorter than it.
	for i := 0; i < 6; i++ {
		time.Sleep(120 * time.Millisecond)
		if !sm.Validate(tok) {
			t.Fatalf("session went stale on step %d despite continuous use", i)
		}
	}
}

func TestSessionIdleClampedToAbsolute(t *testing.T) {
	// An idle window wider than the lifetime could never fire; it is clamped so
	// the two rules cannot contradict each other.
	sm := NewSessionManagerWithIdle(time.Minute, time.Hour)
	if sm.idleTTL != time.Minute {
		t.Fatalf("idleTTL = %v, want it clamped to the absolute ttl (%v)", sm.idleTTL, time.Minute)
	}
	sm.Close()

	// Zero and negative inputs fall back to defaults rather than expiring instantly.
	z := NewSessionManagerWithIdle(0, 0)
	if z.ttl != 24*time.Hour || z.idleTTL != DefaultSessionIdleTimeout {
		t.Fatalf("zero inputs gave ttl=%v idle=%v, want 24h / %v", z.ttl, z.idleTTL, DefaultSessionIdleTimeout)
	}
	z.Close()

	n := NewSessionManagerWithIdle(-time.Second, -time.Second)
	if n.ttl <= 0 || n.idleTTL <= 0 {
		t.Fatalf("negative inputs gave ttl=%v idle=%v, want positive fallbacks", n.ttl, n.idleTTL)
	}
	n.Close()
}

func TestSessionDeleteAndDeleteAll(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	defer sm.Close()

	a, b, c := sm.Create(), sm.Create(), sm.Create()
	sm.Delete(b)
	if sm.Validate(b) {
		t.Fatal("a deleted session must not validate")
	}
	if !sm.Validate(a) || !sm.Validate(c) {
		t.Fatal("Delete revoked more than the token it was given")
	}

	// This is what a password change relies on.
	sm.DeleteAll()
	if sm.Validate(a) || sm.Validate(c) {
		t.Fatal("DeleteAll left a session usable")
	}
	if sm.Count() != 0 {
		t.Fatalf("Count = %d after DeleteAll, want 0", sm.Count())
	}
}

func TestSessionConcurrentUse(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	defer sm.Close()

	const workers = 24
	tokens := make([]string, workers)
	for i := range tokens {
		tokens[i] = sm.Create()
	}

	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func(tok string) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				sm.Validate(tok)
				sm.Create()
				sm.Count()
			}
		}(tokens[i])
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	// The point is that the map survives; every original token is still live.
	for i, tok := range tokens {
		if !sm.Validate(tok) {
			t.Fatalf("token %d was lost under concurrent load", i)
		}
	}
}

func TestSessionCloseIsIdempotent(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	sm.Close()
	sm.Close() // must not panic on a closed channel
}
