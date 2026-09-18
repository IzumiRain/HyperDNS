package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Server-side logout. Until this existed, the dashboard's "Sign Out" button only
// removed the token from localStorage: the session stayed live on the daemon for
// the rest of its 24-hour lifetime, so anyone holding a copy of that token — a
// shared browser, a proxy log, a captured Authorization header — kept full
// dashboard access after the operator believed they had signed out.
// SessionManager.Delete existed and no route ever called it.

func TestLogoutRevokesOnlyThePresentedSession(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	sibling, ok := decodeBody(t, login(t, h, "admin", testAdminPassword))["token"].(string)
	if !ok {
		t.Fatal("could not obtain a second session token")
	}

	w := postJSON(t, h, "/api/auth/logout", `{}`, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200 — %s", w.Code, w.Body.String())
	}
	if ws.sessions.Validate(tok) {
		t.Error("the presented session survived logout")
	}
	if !ws.sessions.Validate(sibling) {
		t.Error("logout revoked a sibling session; only the presented one may be dropped")
	}

	// The revoked token must no longer open a dashboard route.
	if after := postJSON(t, h, "/api/config", ``, tok); after.Code != http.StatusUnauthorized {
		t.Errorf("a logged-out token still reached /api/config: %d", after.Code)
	}
}

// A second logout with the same token is not an error: the browser clears local
// state in a finally block, so a retry or a double-click must not surface a
// failure the operator cannot act on.
func TestLogoutIsIdempotent(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	if w := postJSON(t, h, "/api/auth/logout", `{}`, tok); w.Code != http.StatusOK {
		t.Fatalf("first logout = %d, want 200 — %s", w.Code, w.Body.String())
	}
	// The token is dead, so the gate answers 401 — that is the authentication
	// layer doing its job, not a logout failure. What must not happen is a 5xx.
	second := postJSON(t, h, "/api/auth/logout", `{}`, tok)
	if second.Code >= http.StatusInternalServerError {
		t.Fatalf("second logout = %d, want a client-level answer — %s", second.Code, second.Body.String())
	}
	if ws.sessions.Validate(tok) {
		t.Error("the token came back to life")
	}
}

// The master REST key is not a session, so it has nothing to revoke. Since
// v2.2.0 the dashboard gate refuses it outright (scoping: REST credentials
// no longer pass admin routes), so logout answers 401 at the gate — the
// caller is told the credential does not open this surface at all, which is
// the stronger and truer refusal than the old in-handler 400.
func TestLogoutRejectsTheMasterAPIKey(t *testing.T) {
	ws, h, _, cleanup := authedServer(t)
	defer cleanup()

	w := postJSON(t, h, "/api/auth/logout", `{}`, ws.settings.GetAPIKey())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("logout with the master key = %d, want 401 — %s", w.Code, w.Body.String())
	}
}

func TestLogoutRejectsNonPost(t *testing.T) {
	_, h, tok, cleanup := authedServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.RemoteAddr = "203.0.113.7:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/auth/logout = %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

func TestLogoutRequiresAuthentication(t *testing.T) {
	_, h, _, cleanup := authedServer(t)
	defer cleanup()

	if w := postJSON(t, h, "/api/auth/logout", `{}`, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated logout = %d, want 401", w.Code)
	}
}
