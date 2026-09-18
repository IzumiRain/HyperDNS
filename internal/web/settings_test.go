package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authedGet issues a GET with a bearer token.
func authedGet(t *testing.T, h http.Handler, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "203.0.113.9:5555"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// authedRequest issues an arbitrary method with a bearer token and no body.
func authedRequest(t *testing.T, h http.Handler, method, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "203.0.113.9:5555"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// hasKeyDeep reports whether any object anywhere in a decoded JSON document
// carries the given key. Matching on the exact key rather than a substring
// matters: admin_password_weak is a legitimate field the dashboard needs, and it
// contains "admin_password".
func hasKeyDeep(v any, key string) bool {
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			if k == key || hasKeyDeep(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range node {
			if hasKeyDeep(child, key) {
				return true
			}
		}
	}
	return false
}

// The whole point of hashing the admin password is that the verifier never leaves
// the process. Three responses used to serialise the ServerSettings struct
// wholesale, which put the PBKDF2 hash into browser memory, devtools and any
// cache that saw a dashboard response — where stored XSS could lift it and crack
// it offline. Assert on the key and on the stored value, so a rename of the JSON
// tag cannot quietly reopen the hole.
func TestSettingsResponsesDoNotLeakThePasswordVerifier(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	stored := ws.settings.AdminPassword
	if stored == "" {
		t.Fatal("the fixture has no stored password, so this test would pass vacuously")
	}

	responses := map[string]*httptest.ResponseRecorder{
		"GET /api/config":   authedGet(t, h, "/api/config", tok),
		"GET /api/settings": authedGet(t, h, "/api/settings", tok),
		"POST /api/settings": postJSON(t, h, "/api/settings",
			`{"public_ip":"198.51.100.10","api_bind":"127.0.0.1"}`, tok),
		"GET /api/auth/me": authedGet(t, h, "/api/auth/me", tok),
	}

	for name, w := range responses {
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 — %s", name, w.Code, w.Body.String())
		}
		body := w.Body.String()

		var doc any
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s is not JSON: %v", name, err)
		}
		if hasKeyDeep(doc, "admin_password") {
			t.Errorf("%s response carries an admin_password field: %s", name, body)
		}
		if strings.Contains(body, stored) {
			t.Errorf("%s response contains the stored password verifier", name)
		}
		if strings.Contains(body, testAdminPassword) {
			t.Errorf("%s response contains the plaintext password", name)
		}
	}

	// The fields the dashboard genuinely needs must still be there, otherwise the
	// sanitising could "pass" this test by returning nothing useful.
	var cfg map[string]any
	if err := json.Unmarshal(authedGet(t, h, "/api/config", tok).Body.Bytes(), &cfg); err != nil {
		t.Fatalf("/api/config is not JSON: %v", err)
	}
	server, ok := cfg["server"].(map[string]any)
	if !ok {
		t.Fatalf("/api/config has no server object: %v", cfg)
	}
	for _, key := range []string{"public_ip", "admin_username", "api_key", "api_bind", "web_port"} {
		if _, has := server[key]; !has {
			t.Errorf("/api/config server object is missing %q", key)
		}
	}
	// admin_password_weak drives the forced credential modal, so its absence would
	// silently disable the nag.
	if _, has := server["admin_password_weak"]; !has {
		t.Error("/api/config server object is missing admin_password_weak")
	}
}

func TestSettingsRequiresAuth(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()

	if w := authedGet(t, h, "/api/settings", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /api/settings = %d, want 401", w.Code)
	}
	if w := postJSON(t, h, "/api/settings", `{"api_bind":"0.0.0.0"}`, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated POST /api/settings = %d, want 401", w.Code)
	}
	if ws.settings.APIBind != "127.0.0.1" {
		t.Fatalf("an unauthenticated request changed the API gate to %q", ws.settings.APIBind)
	}
}

// api_bind is a live authorization gate: internal/api refuses non-loopback peers
// unless it is exactly 0.0.0.0. An unvalidated string here leaves the gate in a
// state that reads as "restricted" while the operator was told the API is public,
// or the reverse — so the handler has to reject anything else outright.
func TestSettingsPostRejectsBadInput(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	beforeIP, beforeBind := ws.settings.PublicIP, ws.settings.APIBind

	cases := []struct {
		name, body string
		want       int
	}{
		{"malformed json", `{"api_bind":`, http.StatusBadRequest},
		{"empty body", ``, http.StatusBadRequest},
		{"public_ip is a hostname", `{"public_ip":"example.com"}`, http.StatusBadRequest},
		{"public_ip is garbage", `{"public_ip":"999.1.1.1"}`, http.StatusBadRequest},
		{"api_bind is a typo", `{"api_bind":"0.0.0.1"}`, http.StatusBadRequest},
		{"api_bind is a wildcard host", `{"api_bind":"::"}`, http.StatusBadRequest},
		{"api_bind carries a port", `{"api_bind":"0.0.0.0:8080"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postJSON(t, h, "/api/settings", tc.body, tok)
			if w.Code != tc.want {
				t.Fatalf("POST %s = %d, want %d — %s", tc.body, w.Code, tc.want, w.Body.String())
			}
		})
	}

	if ws.settings.PublicIP != beforeIP || ws.settings.APIBind != beforeBind {
		t.Fatalf("a rejected request still mutated the settings: public_ip %q->%q, api_bind %q->%q",
			beforeIP, ws.settings.PublicIP, beforeBind, ws.settings.APIBind)
	}

	// A trailing space is the realistic typo, and it must not slip through as a
	// value the gate would then fail to recognise.
	if w := postJSON(t, h, "/api/settings", `{"api_bind":"0.0.0.0 "}`, tok); w.Code != http.StatusOK {
		t.Fatalf("a padded api_bind = %d, want 200 (trimmed then accepted) — %s", w.Code, w.Body.String())
	}
	if ws.settings.APIBind != "0.0.0.0" {
		t.Fatalf("api_bind = %q after a padded value, want the trimmed 0.0.0.0", ws.settings.APIBind)
	}
}

func TestSettingsPostRejectsOtherMethods(t *testing.T) {
	_, h, tok, cleanup := authedServer(t)
	defer cleanup()

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := authedRequest(t, h, method, "/api/settings", tok)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/settings = %d, want 405", method, w.Code)
		}
	}
}

func TestSettingsPostPersistsAndIsPartial(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	w := postJSON(t, h, "/api/settings", `{"public_ip":"198.51.100.77","api_bind":"0.0.0.0"}`, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/settings = %d, want 200 — %s", w.Code, w.Body.String())
	}
	view := decodeBody(t, w)
	if view["public_ip"] != "198.51.100.77" || view["api_bind"] != "0.0.0.0" {
		t.Fatalf("response view = %v, want the new values", view)
	}
	if ws.settings.PublicIP != "198.51.100.77" || ws.settings.APIBind != "0.0.0.0" {
		t.Fatalf("in-memory settings = %q/%q", ws.settings.PublicIP, ws.settings.APIBind)
	}

	// It has to reach the database, or the change reverts on the next restart while
	// the running process behaves as though it took.
	var persisted map[string]any
	if err := ws.db.GetSetting("server", &persisted); err != nil {
		t.Fatalf("GetSetting(server): %v", err)
	}
	if persisted["public_ip"] != "198.51.100.77" || persisted["api_bind"] != "0.0.0.0" {
		t.Fatalf("persisted settings = %v", persisted)
	}

	// An omitted field is left alone rather than blanked — the dashboard posts one
	// field at a time (the API toggle sends only api_bind).
	if w := postJSON(t, h, "/api/settings", `{"api_bind":"127.0.0.1"}`, tok); w.Code != http.StatusOK {
		t.Fatalf("partial POST = %d, want 200 — %s", w.Code, w.Body.String())
	}
	if ws.settings.PublicIP != "198.51.100.77" {
		t.Errorf("public_ip = %q after a bind-only post, want it untouched", ws.settings.PublicIP)
	}
	if ws.settings.APIBind != "127.0.0.1" {
		t.Errorf("api_bind = %q, want 127.0.0.1", ws.settings.APIBind)
	}
}

// The regenerate handler used to rotate on any method that was not GET, so a HEAD
// from a link-preview fetcher or a stray retry silently invalidated every
// integration the operator had built.
func TestRegenerateAPIKeyOnlyRotatesOnPost(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	original := ws.settings.APIKey

	if w := authedGet(t, h, "/api/settings/regenerate-api-key", tok); w.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200 — %s", w.Code, w.Body.String())
	} else if decodeBody(t, w)["api_key"] != original {
		t.Error("GET did not return the current key")
	}
	if ws.settings.APIKey != original {
		t.Fatal("GET rotated the key")
	}

	for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := authedRequest(t, h, method, "/api/settings/regenerate-api-key", tok)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", method, w.Code)
		}
		if ws.settings.APIKey != original {
			t.Fatalf("%s rotated the key", method)
		}
	}

	// The POST must carry the current password: rotation is a credential
	// change, and the gate re-authenticates the operator before it lands.
	w := postJSON(t, h, "/api/settings/regenerate-api-key", `{"current_password":"`+testAdminPassword+`"}`, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("POST = %d, want 200 — %s", w.Code, w.Body.String())
	}
	rotated, _ := decodeBody(t, w)["api_key"].(string)
	if rotated == "" || rotated == original {
		t.Fatalf("POST returned %q, want a new key", rotated)
	}
	if !strings.HasPrefix(rotated, "hdns_live_") {
		t.Errorf("rotated key = %q, want the hdns_live_ prefix", rotated)
	}
	if ws.settings.APIKey != rotated {
		t.Errorf("in-memory key = %q, want the rotated one", ws.settings.APIKey)
	}

	var persisted map[string]any
	if err := ws.db.GetSetting("server", &persisted); err != nil {
		t.Fatalf("GetSetting(server): %v", err)
	}
	if persisted["api_key"] != rotated {
		t.Errorf("persisted api_key = %v, want the rotated one — the process would honour a key that is not in the database", persisted["api_key"])
	}
}

func TestRegenerateAPIKeyRequiresAuth(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	original := ws.settings.APIKey

	if w := postJSON(t, ws.buildAdminHandler(), "/api/settings/regenerate-api-key", ``, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated rotate = %d, want 401", w.Code)
	}
	if ws.settings.APIKey != original {
		t.Fatal("an unauthenticated request rotated the API key")
	}
}
