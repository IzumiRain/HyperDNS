package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.2.0 scoping: the master REST key must not authorize dashboard admin
// routes. A leaked REST key — the credential that lives in integrations, CI
// variables and support tickets — used to be a full panel takeover. It stays
// valid for the REST API (/api/v1|/api/v2) and for exactly one dashboard
// route: the lockout-recovery unlock the root-local TUI calls.

func TestMasterKeyIsRefusedOnAdminRoutes(t *testing.T) {
	ws, h, _, cleanup := authedServer(t)
	defer cleanup()
	key := ws.settings.GetAPIKey()

	// The credential-changing route — the worst thing the old behavior
	// allowed. Any admin route would prove the same; this one is the headline.
	for _, path := range []string{"/api/config", "/api/settings", "/api/config/server", "/api/auth/me"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		req.RemoteAddr = "203.0.113.9:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("master key reached %s: %d — %s", path, w.Code, w.Body.String())
		}
	}

	// A POST mutation is equally refused.
	req := httptest.NewRequest(http.MethodPost, "/api/config/server", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("master key mutated /api/config/server: %d — %s", w.Code, w.Body.String())
	}
}

// TestMasterKeyStillAuthorizesREST: the key is a REST credential and must
// keep working where it is supposed to — the versioned API under the admin
// namespace.
func TestMasterKeyStillAuthorizesREST(t *testing.T) {
	ws, h, _, cleanup := authedServer(t)
	defer cleanup()
	key := ws.settings.GetAPIKey()

	for _, path := range []string{"/api/v1/status", "/api/v2/status"} {
		// Loopback peer: the harness binds the REST API to 127.0.0.1, and the
		// bind gate (correctly) refuses anything else before auth is consulted.
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-API-Key", key)
		req.RemoteAddr = "127.0.0.1:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("master key refused on %s: %d — %s", path, w.Code, w.Body.String())
		}
	}
}

// TestUnlockKeepsTheMasterKeyPath: the recovery route is the one place the
// key is still accepted on the dashboard mux — the TUI calls it with the key
// because it has no session. Refusing it there would make a lockout
// permanent short of an SSH restart.
func TestUnlockKeepsTheMasterKeyPath(t *testing.T) {
	ws, h, _, cleanup := authedServer(t)
	defer cleanup()
	key := ws.settings.GetAPIKey()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/unlock", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock with the master key = %d — %s", w.Code, w.Body.String())
	}
}
