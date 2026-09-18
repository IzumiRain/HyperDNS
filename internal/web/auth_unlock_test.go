package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdns/internal/service"
)

// Phase C: the unlock endpoint. The lockout lives in the daemon's memory, so
// this authenticated endpoint is the only way an operator (or the TUI, which
// calls it over loopback) can lift one without restarting the daemon — and it
// sits behind the session/API-key gate plus the second factor when 2FA is on,
// because an endpoint that undoes a security control must not be cheaper to
// reach than the control it undoes.

func TestAuthUnlockClearsALockout(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	// Lock the address out with three failures.
	for range service.DefaultMaxFailedAttempts {
		w := login(t, h, "admin", "wrong")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("setup failure: got %d", w.Code)
		}
	}
	if w := login(t, h, "admin", testAdminPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the address to be locked out, got %d", w.Code)
	}

	// Without a session: refused like any other admin call.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/unlock", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated unlock = %d, want 401", w.Code)
	}

	// With a session: every tracked address cleared.
	req = httptest.NewRequest(http.MethodPost, "/api/auth/unlock", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.RemoteAddr = "203.0.113.9:5555"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated unlock = %d — %s", w.Code, w.Body.String())
	}

	// And the operator can log in again from the locked address.
	if w := login(t, h, "admin", testAdminPassword); w.Code != http.StatusOK {
		t.Errorf("login after unlock = %d, want 200", w.Code)
	}
}

func TestAuthUnlockUsesDaemonSharedTracker(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	shared := service.NewLoginAttemptTracker()
	ws.SetControlState(service.NewBenchmarkRunner(func() {}), shared)

	for range service.DefaultMaxFailedAttempts {
		shared.RecordFailure("192.0.2.45")
	}
	if !shared.IsBlocked("192.0.2.45") {
		t.Fatal("setup did not block shared tracker address")
	}

	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/unlock", strings.NewReader(`{"ip":"192.0.2.45"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock = %d: %s", w.Code, w.Body.String())
	}
	if shared.IsBlocked("192.0.2.45") || shared.Count() != 0 {
		t.Fatal("web unlock did not clear daemon-shared tracker")
	}
}

func TestAuthUnlockRejectsWrongMethod(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/unlock", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET unlock = %d, want 405", w.Code)
	}
}
