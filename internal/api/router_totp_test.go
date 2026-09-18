package api

// Regression test for Mantis v2.2.0 B-1: POST /api/v1/api-key rotates the
// master key — the same credential change the dashboard gates behind the
// second factor — and the route must consult the injected TOTP predicate
// instead of silently being the unguarded copy of that operation. GET only
// reveals the key and stays ungated.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyRotationConsultsTOTPGate(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	gateCalls := 0
	apiInst.SetTOTPGate(func(r *http.Request) bool {
		gateCalls++
		return r.URL.Query().Get("code") == "123456"
	})

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)
	call := func(method string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/api-key", nil)
		req.Header.Set("X-API-Key", "hdns_live_testkey123")
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	// GET is a read: the gate must not be consulted.
	if w := call(http.MethodGet); w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/api-key = %d, want 200", w.Code)
	}
	if gateCalls != 0 {
		t.Fatalf("GET consulted the TOTP gate %d time(s), want 0", gateCalls)
	}

	// POST without a valid code: 401, and the key must be unchanged.
	before := apiInst.settings.GetAPIKey()
	if w := call(http.MethodPost); w.Code != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/api-key without a code = %d, want 401", w.Code)
	}
	if after := apiInst.settings.GetAPIKey(); after != before {
		t.Fatal("a gated-out rotation must not change the key")
	}

	// POST with a valid code: through, and the key rotates.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-key?code=123456", nil)
	req.Header.Set("X-API-Key", "hdns_live_testkey123")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST with a valid code = %d, want 200", w.Code)
	}
	if after := apiInst.settings.GetAPIKey(); after == before {
		t.Fatal("an accepted rotation must change the key")
	}
}

func TestAPIKeyRotationUngatedWithoutPredicate(t *testing.T) {
	// Harnesses with no second factor wired keep working: nil predicate means
	// the gate reads as "TOTP not in force", the same contract the dashboard's
	// own gate has.
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-key", nil)
	req.Header.Set("X-API-Key", "hdns_live_testkey123")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST with no gate wired = %d, want 200", w.Code)
	}
}
