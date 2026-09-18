package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdns/internal/crypto"
	"hyperdns/internal/service"
)

// postJSON issues a POST with a JSON body and returns the recorder.
func postJSON(t *testing.T, h http.Handler, path, body, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5555"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response body is not JSON (%d): %q", w.Code, w.Body.String())
	}
	return out
}

func login(t *testing.T, h http.Handler, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)
	return postJSON(t, h, "/api/auth/login", body, "")
}

func TestLoginAcceptsCorrectCredentials(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()

	w := login(t, h, "admin", testAdminPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)

	tok, _ := body["token"].(string)
	if !strings.HasPrefix(tok, "hdns_session_") {
		t.Fatalf("token = %q, want an hdns_session_ token", tok)
	}
	if body["username"] != "admin" {
		t.Errorf("username = %v, want admin", body["username"])
	}
	// The seeded password satisfies the policy, so nothing should be nagged about.
	if body["password_weak"] != false {
		t.Errorf("password_weak = %v, want false for a policy-compliant password", body["password_weak"])
	}
	if body["is_default_password"] != false {
		t.Errorf("is_default_password = %v, want false", body["is_default_password"])
	}
	// A response must never echo the credential back in any form.
	if strings.Contains(w.Body.String(), testAdminPassword) {
		t.Error("the login response contains the password")
	}

	// The token must actually open a protected route.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	mw := httptest.NewRecorder()
	h.ServeHTTP(mw, req)
	if mw.Code != http.StatusOK {
		t.Fatalf("/api/auth/me with a fresh token = %d, want 200", mw.Code)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	cases := []struct {
		name, user, pass string
	}{
		{"wrong password", "admin", testAdminPassword + "x"},
		{"wrong username", "root", testAdminPassword},
		{"empty password", "admin", ""},
		{"empty username", "", testAdminPassword},
		{"both empty", "", ""},
		{"password is the stored hash", "admin", ws.settings.AdminPassword},
		{"case-shifted password", "admin", strings.ToUpper(testAdminPassword)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh server per case, so the lockout from earlier cases does not
			// mask a genuine acceptance.
			ws2, _, cleanup2 := setupTestWebServer(t)
			defer cleanup2()
			w := login(t, ws2.buildAdminHandler(), tc.user, tc.pass)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("login(%q, %q) = %d, want 401 — body %s", tc.user, tc.pass, w.Code, w.Body.String())
			}
		})
	}
}

// Releases before v1.5.0 stored the password as plaintext. Those records must
// still authenticate, or upgrading the binary locks the operator out of a live
// server — and they must not be reported as healthy.
func TestLoginAcceptsLegacyPlaintextRecord(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	ws.settings.AdminPassword = "legacy-plaintext-pw"
	h := ws.buildAdminHandler()

	w := login(t, h, "admin", "legacy-plaintext-pw")
	if w.Code != http.StatusOK {
		t.Fatalf("a stored plaintext password must still log in: %d %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["password_weak"] != true {
		t.Errorf("password_weak = %v, want true — an unhashed record must be flagged", body["password_weak"])
	}
}

// The old handler substituted "admin" for an empty stored password, which made a
// blank settings record a working backdoor.
func TestLoginEmptyStoredPasswordIsNotABackdoor(t *testing.T) {
	for _, attempt := range []string{"", "admin", "anything"} {
		t.Run("submitted "+attempt, func(t *testing.T) {
			ws, _, cleanup := setupTestWebServer(t)
			defer cleanup()
			ws.settings.AdminPassword = ""

			w := login(t, ws.buildAdminHandler(), "admin", attempt)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("login with an empty stored password and %q = %d, want 401", attempt, w.Code)
			}
		})
	}
}

// An empty stored username must fall back to "admin" rather than accepting any
// username, which is what an unguarded ConstantTimeCompare against "" would do.
func TestLoginEmptyStoredUsernameFallsBackToAdmin(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.settings.AdminUsername = ""
	h := ws.buildAdminHandler()

	if w := login(t, h, "", testAdminPassword); w.Code != http.StatusUnauthorized {
		t.Fatalf("an empty submitted username = %d, want 401", w.Code)
	}
	if w := login(t, h, "admin", testAdminPassword); w.Code != http.StatusOK {
		t.Fatalf("username %q should fall back to admin: %d %s", "", w.Code, w.Body.String())
	}
}

func TestLoginLocksOutAfterRepeatedFailures(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()

	for i := range service.DefaultMaxFailedAttempts {
		if w := login(t, h, "admin", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	// The next attempt is refused before any comparison happens.
	w := login(t, h, "admin", "wrong")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", service.DefaultMaxFailedAttempts+1, w.Code)
	}
	// And the correct password is refused too — the lock is on the source, not on
	// the guess.
	if w := login(t, h, "admin", testAdminPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password while locked out = %d, want 429", w.Code)
	}
}

func TestLoginRejectsOversizedBody(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	huge := fmt.Sprintf(`{"username":"admin","password":%q}`, strings.Repeat("a", 2<<20))
	w := postJSON(t, ws.buildAdminHandler(), "/api/auth/login", huge, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized login body = %d, want 400", w.Code)
	}
}

func TestAuthMeRequiresAToken(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	w := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/api/auth/me without a token = %d, want 401", w.Code)
	}
}

// The dashboard API is structurally immune to CSRF, and the reason is worth pinning rather
// than rediscovering: authGate reads the token from the Authorization header or X-API-Key and
// from nowhere else. A browser attaches cookies to cross-site requests on its own, but it will
// not attach a custom header — that needs a CORS preflight the panel never answers — so a
// forged <img>, <form> or <script> from any other origin arrives with no credential at all.
//
// Which means the whole class is closed by one property: the token must never be accepted
// through a channel a browser fills in by itself. Every plausible "make it more convenient"
// change breaks that — a session cookie so the panel survives a refresh, a ?token= so a link
// can be shared, a form field so a plain HTML form works — and each of them turns every
// authenticated route into a CSRF target at once. There is no CSRF token anywhere in this
// codebase and the server never sends a Set-Cookie; with header-only auth neither is needed,
// and this test is what says so.
func TestAuthRejectsCredentialsFromBrowserFilledChannels(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()

	tok := decodeBody(t, login(t, h, "admin", testAdminPassword))["token"].(string)

	// The control. Same token, sent the one way the panel actually sends it — so the
	// rejections below are about the channel and not about a token the server dislikes.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the control request failed: /api/auth/me with a Bearer header = %d, want 200. "+
			"The rest of this test proves nothing if the token itself is not good.", w.Code)
	}

	for _, tc := range []struct {
		name   string
		method string
		path   string
		setup  func(*http.Request)
	}{
		{
			// <img src="/api/auth/me">, and the cookie rides along.
			name:   "session cookie",
			method: http.MethodGet,
			path:   "/api/auth/me",
			setup:  func(r *http.Request) { r.Header.Set("Cookie", "hdns_session="+tok) },
		},
		{
			name:   "cookie named token",
			method: http.MethodGet,
			path:   "/api/auth/me",
			setup:  func(r *http.Request) { r.Header.Set("Cookie", "token="+tok) },
		},
		{
			// The documented exception for EventSource, which cannot send headers. It is scoped
			// to the two SSE routes on purpose — a token in a query string lands in access logs,
			// browser history and Referer headers — so it must not work here.
			name:   "query parameter",
			method: http.MethodGet,
			path:   "/api/auth/me?token=" + tok,
			setup:  func(r *http.Request) {},
		},
		{
			// The classic vector: a cross-site <form> can POST urlencoded fields to any origin
			// without script and without a preflight.
			name:   "form field",
			method: http.MethodPost,
			path:   "/api/auth/me",
			setup: func(r *http.Request) {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.method == http.MethodPost {
				body = strings.NewReader("token=" + tok)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.RemoteAddr = "203.0.113.7:5555"
			tc.setup(req)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s carrying the session token as a %s = %d, want 401.\n"+
					"A browser supplies this channel by itself on a cross-site request, so "+
					"accepting it here makes every authenticated route forgeable from any page "+
					"the operator visits while logged in.", tc.method, tc.path, tc.name, w.Code)
			}
		})
	}
}

// /api/diagnostics/run opens TCP connections to eight named endpoints on every call. Behind
// the gate that is a diagnostic; reachable without one it is an amplifier that answers to
// anybody. The handler is POST-only now, but the verb is not what this test is about: the
// assertion is that the gate runs *before* the handler, so an unauthorized call is refused
// without dialing anything — which is also why this test needs no network. GET is probed
// alongside POST for exactly that reason. A GET must come back 401 from the gate and not 405
// from the handler; the latter would mean the method check ran first, and a route that
// answers 405 before it answers 401 is telling an unauthenticated caller which verbs it takes.
func TestDiagnosticsRunIsNotReachableWithoutAToken(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/api/diagnostics/run", nil)
		req.RemoteAddr = "203.0.113.7:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s /api/diagnostics/run without a token = %d, want 401 — an unauthenticated "+
				"caller could make the resolver dial eight external hosts per request.", method, w.Code)
		}
	}
}

func TestAuthMeReportsWeakFlag(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()

	tok := decodeBody(t, login(t, h, "admin", testAdminPassword))["token"].(string)

	// Flip the flag the way a boot-time migration of a legacy password would.
	ws.settings.AdminPasswordWeak = true

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/api/auth/me = %d, want 200", w.Code)
	}
	body := decodeBody(t, w)
	if body["password_weak"] != true || body["is_default_password"] != true {
		t.Fatalf("expected both weak flags true, got %v", body)
	}
	if _, leaked := body["admin_password"]; leaked {
		t.Error("/api/auth/me exposes the password field")
	}
}

// authedServer returns a server plus a live session token.
func authedServer(t *testing.T) (*WebServer, http.Handler, string, func()) {
	t.Helper()
	ws, _, cleanup := setupTestWebServer(t)
	h := ws.buildAdminHandler()
	tok, ok := decodeBody(t, login(t, h, "admin", testAdminPassword))["token"].(string)
	if !ok {
		cleanup()
		t.Fatal("could not obtain a session token")
	}
	return ws, h, tok, cleanup
}

func TestConfigServerNoOpDoesNotMintASession(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	before := ws.sessions.Count()
	w := postJSON(t, h, "/api/config/server", `{}`, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("empty credential change = %d, want 200 — %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["changed"] != false {
		t.Errorf("changed = %v, want false", body["changed"])
	}
	if _, has := body["token"]; has {
		t.Error("a no-op credential change handed out a session token")
	}
	if after := ws.sessions.Count(); after != before {
		t.Errorf("session count went %d -> %d on a no-op", before, after)
	}
}

func TestConfigServerRequiresCurrentPassword(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	stored := ws.settings.AdminPassword

	cases := []string{
		`{"admin_password":"Zx9-replacement-phrase"}`,
		`{"admin_password":"Zx9-replacement-phrase","current_password":"wrong-one"}`,
		`{"admin_password":"Zx9-replacement-phrase","current_password":""}`,
		`{"admin_username":"newadmin"}`,
	}
	for _, body := range cases {
		w := postJSON(t, h, "/api/config/server", body, tok)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", body, w.Code)
		}
	}
	if ws.settings.AdminPassword != stored {
		t.Fatal("a rejected change still modified the stored password")
	}
	if ws.settings.AdminUsername != "admin" {
		t.Fatal("a rejected change still modified the username")
	}
}

func TestConfigServerEnforcesPasswordPolicy(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	stored := ws.settings.AdminPassword

	weak := []string{"admin", "short", "password123", "aaaaaaaaaaaa", "abcdefghijkl", "hyperdns"}
	for _, pw := range weak {
		body := fmt.Sprintf(`{"admin_password":%q,"current_password":%q}`, pw, testAdminPassword)
		w := postJSON(t, h, "/api/config/server", body, tok)
		if w.Code != http.StatusBadRequest {
			t.Errorf("setting password %q = %d, want 400", pw, w.Code)
			continue
		}
		// The operator has to be told what is wrong with it, not just "failed".
		msg, _ := decodeBody(t, w)["error"].(string)
		if strings.TrimSpace(msg) == "" {
			t.Errorf("rejecting %q returned no reason", pw)
		}
	}
	if ws.settings.AdminPassword != stored {
		t.Fatal("a policy rejection still modified the stored password")
	}
}

func TestConfigServerChangesPasswordAndRevokesSessions(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	// A second dashboard session, which must also be revoked.
	otherTok := decodeBody(t, login(t, h, "admin", testAdminPassword))["token"].(string)

	const newPass = "Kq4-amber-tunnel-road"
	body := fmt.Sprintf(`{"admin_password":%q,"current_password":%q}`, newPass, testAdminPassword)
	w := postJSON(t, h, "/api/config/server", body, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("password change = %d, want 200 — %s", w.Code, w.Body.String())
	}
	resp := decodeBody(t, w)
	if resp["changed"] != true {
		t.Errorf("changed = %v, want true", resp["changed"])
	}
	newTok, _ := resp["token"].(string)
	if !strings.HasPrefix(newTok, "hdns_session_") {
		t.Fatalf("replacement token = %q, want an hdns_session_ token", newTok)
	}

	// Stored form: a hash, and nothing resembling either plaintext.
	if !crypto.IsPasswordHash(ws.settings.AdminPassword) {
		t.Fatalf("stored password is not a hash: %q", ws.settings.AdminPassword)
	}
	if strings.Contains(ws.settings.AdminPassword, newPass) {
		t.Fatal("the stored hash contains the plaintext")
	}
	if ws.settings.AdminPasswordWeak {
		t.Error("AdminPasswordWeak stayed set after a compliant password was accepted")
	}

	// Every pre-change token is dead, including the caller's original one.
	if ws.sessions.Validate(tok) {
		t.Error("the caller's old token survived the password change")
	}
	if ws.sessions.Validate(otherTok) {
		t.Error("a second session survived the password change")
	}
	if !ws.sessions.Validate(newTok) {
		t.Error("the replacement token is not valid")
	}

	// The change is durable and the old password is gone.
	if w := login(t, h, "admin", testAdminPassword); w.Code != http.StatusUnauthorized {
		t.Errorf("the old password still logs in: %d", w.Code)
	}
	if w := login(t, h, "admin", newPass); w.Code != http.StatusOK {
		t.Errorf("the new password does not log in: %d %s", w.Code, w.Body.String())
	}

	// And it reached the database, not just the in-memory copy.
	var persisted map[string]any
	if err := ws.db.GetSetting("server", &persisted); err != nil {
		t.Fatalf("GetSetting(server): %v", err)
	}
	stored, _ := persisted["admin_password"].(string)
	if !crypto.IsPasswordHash(stored) {
		t.Fatalf("persisted admin_password is not a hash: %q", stored)
	}
	if strings.Contains(stored, newPass) || strings.Contains(stored, testAdminPassword) {
		t.Fatal("a plaintext password reached the database")
	}
}

func TestConfigServerChangesUsername(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	body := fmt.Sprintf(`{"admin_username":"operator","current_password":%q}`, testAdminPassword)
	w := postJSON(t, h, "/api/config/server", body, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("username change = %d, want 200 — %s", w.Code, w.Body.String())
	}
	resp := decodeBody(t, w)
	if resp["username"] != "operator" {
		t.Errorf("username = %v, want operator", resp["username"])
	}
	// A username-only change does not touch the password, so sessions stay valid
	// and no replacement token is issued.
	if _, has := resp["token"]; has {
		t.Error("a username-only change rotated the session")
	}
	if !ws.sessions.Validate(tok) {
		t.Error("a username-only change revoked the caller's session")
	}

	if w := login(t, h, "admin", testAdminPassword); w.Code != http.StatusUnauthorized {
		t.Errorf("the old username still logs in: %d", w.Code)
	}
	if w := login(t, h, "operator", testAdminPassword); w.Code != http.StatusOK {
		t.Errorf("the new username does not log in: %d %s", w.Code, w.Body.String())
	}
}

// A rename plus a password equal to the new name must be caught in one request.
func TestConfigServerValidatesAgainstTheIncomingUsername(t *testing.T) {
	_, h, tok, cleanup := authedServer(t)
	defer cleanup()

	body := fmt.Sprintf(`{"admin_username":"quietlanternriver","admin_password":"quietlanternriver","current_password":%q}`, testAdminPassword)
	w := postJSON(t, h, "/api/config/server", body, tok)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("password equal to the new username = %d, want 400 — %s", w.Code, w.Body.String())
	}
}

func TestConfigServerRejectsBadUsername(t *testing.T) {
	_, h, tok, cleanup := authedServer(t)
	defer cleanup()

	bad := []string{strings.Repeat("u", 65), " padded", "padded "}
	for _, u := range bad {
		body := fmt.Sprintf(`{"admin_username":%q,"current_password":%q}`, u, testAdminPassword)
		w := postJSON(t, h, "/api/config/server", body, tok)
		if w.Code != http.StatusBadRequest {
			t.Errorf("username %q = %d, want 400", u, w.Code)
		}
	}
}

func TestConfigServerRejectsGetAndUnauthenticated(t *testing.T) {
	_, h, tok, cleanup := authedServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/config/server", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/config/server = %d, want 405", w.Code)
	}

	if w := postJSON(t, h, "/api/config/server", `{}`, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated credential change = %d, want 401", w.Code)
	}
	if w := postJSON(t, h, "/api/config/server", `{}`, "hdns_session_deadbeef"); w.Code != http.StatusUnauthorized {
		t.Errorf("forged token = %d, want 401", w.Code)
	}
}

func TestSecurityHeadersIncludeCSP(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(w, req)

	want := map[string]string{
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": contentSecurityPolicy,
		// Nothing this server hosts belongs in a search index — not the panel, and
		// least of all a subscription URL, which is itself the credential.
		// Cache-Control is deliberately not in this map: it is per-route, because the
		// embedded assets override the middleware's no-store with no-cache so they
		// can still answer 304.
		"X-Robots-Tag": "noindex, nofollow",
	}
	for k, v := range want {
		if got := w.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	for _, directive := range []string{"default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'"} {
		if !strings.Contains(contentSecurityPolicy, directive) {
			t.Errorf("CSP is missing %q", directive)
		}
	}
}

// Verification is gated so an unauthenticated flood cannot take the whole CPU.
func TestKDFGateIsBounded(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	if cap(ws.kdfGate) < 1 {
		t.Fatalf("kdfGate capacity = %d, want at least 1", cap(ws.kdfGate))
	}
	if cap(ws.kdfGate) > 4 {
		t.Fatalf("kdfGate capacity = %d, want no more than 4", cap(ws.kdfGate))
	}

	// Concurrent verifications must all resolve correctly and release the gate.
	done := make(chan bool, 8)
	for range 8 {
		go func() {
			ok, _ := ws.verifyAdminPassword("admin", testAdminPassword)
			done <- ok
		}()
	}
	for range 8 {
		if !<-done {
			t.Fatal("a concurrent verification of the correct password failed")
		}
	}
	if len(ws.kdfGate) != 0 {
		t.Fatalf("kdfGate has %d slots still held; a path forgot to release", len(ws.kdfGate))
	}
}
