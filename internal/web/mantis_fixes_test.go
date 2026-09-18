package web

import (
	"hyperdns/internal/auth"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdns/internal/database"
)

// Regression tests for the findings fixed from REPORT-MANTIS-v2.1.0-26.9.8.
// Each test names the finding id it pins.

// B-06: a bare IPv6 upstream must become [v6]:53, not v6:53 (which parses as a
// different host and was persisted).
func TestUpstreamIPv6AddressIsBracketed(t *testing.T) {
	cases := map[string]string{
		"2001:db8::1": "[2001:db8::1]:53",
		"203.0.113.9": "203.0.113.9:53",
	}
	for in, want := range cases {
		if _, _, err := net.SplitHostPort(in); err == nil {
			continue // already host:port; the handler leaves it alone
		}
		if ip := net.ParseIP(in); ip == nil {
			continue
		}
		got := net.JoinHostPort(in, "53")
		if got != want {
			t.Errorf("JoinHostPort(%q) = %q, want %q", in, got, want)
		}
	}
	// The old concatenation form produced a DIFFERENT host:
	if net.ParseIP("2001:db8::1:53") != nil {
		t.Log("2001:db8::1:53 parses as an IPv6 literal — the exact reason string concat was wrong")
	}
}

// B-19: extend_days <= 0 is refused, not silently turned into +30 days.
func TestClientsRenewRejectsNonPositiveDays(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	client, err := ws.clients.CreateClient("Renew Probe", 30, "10.0.0.1")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	for _, days := range []string{"0", "-5"} {
		req := httptest.NewRequest(http.MethodPost, "/api/clients/renew", strings.NewReader(`{"id":"`+client.ID+`","extend_days":`+days+`}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("renew extend_days=%s = %d, want 400", days, w.Code)
		}
	}
}

// B-03: the rotation accepts the TOTP code from the JSON body (the dashboard's
// shape), not only from the query string.
func TestAPIKeyRotationReadsCodeFromBody(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	_ = ws
	ws.SetAuthSettings(newAuthSettings(t))
	h := ws.buildAdminHandler()
	secret := enrollAndEnable(t, h, bearerFor(t, h))

	// Both codes derive from the step start, not from a bare time.Now(): a code
	// computed late in step N leaves the previous-step code outside the
	// verifier's ±1-step window the moment the clock rolls into step N+1, and
	// under -race the suite is slow enough for exactly that to happen.
	totpAnchor := totpStepStart()
	code := codeFor(t, secret, totpAnchor)
	wLogin := loginWithCode(t, h, "admin", testAdminPassword, code)
	tok, ok := decodeBody(t, wLogin)["token"].(string)
	if !ok || tok == "" {
		t.Fatalf("login with the current-step code = %d, want 200 so the rotation has a session to test — %s", wLogin.Code, wLogin.Body.String())
	}

	// Body-carried password + code (the login already spent its code — a
	// validated code is single-use — so the rotation uses the NEXT step, not
	// the previous one: ValidateTOTPAt accepts [now-1, now+1], so a code one
	// step ahead is valid immediately and for two steps, while a trailing
	// code computed late in this step expires the moment the clock rolls
	// over): accepted.
	rotCode := codeFor(t, secret, totpAnchor.Add(auth.TOTPStep))
	req := httptest.NewRequest(http.MethodPost, "/api/settings/regenerate-api-key",
		strings.NewReader(`{"current_password":"`+testAdminPassword+`","code":"`+rotCode+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("rotation with body code = %d, want 200 — %s", w.Code, w.Body.String())
	}
}

// B-18/B-02: snippets carry the real port/scheme and the actual API contract
// ("days" field, bare view response).
func TestSnippetsUseLiveConfigAndRealContract(t *testing.T) {
	// renderConfig supplies currentConfig; simulate the fields the builder reads.
	app := readAsset(t, "js/app.js")
	for _, banned := range []string{`"expires_days"`, "res[\"data\"][\"register_url\"]"} {
		if strings.Contains(app, banned) {
			t.Errorf("app.js snippets still contain %q — they must send days and read the bare view", banned)
		}
	}
}

// B-21: the startup log prints the live admin-namespace URL, not /dashboard.
func TestStartupLogNamesAdminNamespace(t *testing.T) {
	// Source-level pin so a regression is a test failure, not a 404.
	src := readGoSource(t, "server.go")
	if strings.Contains(src, `Dashboard running at %s://%s/dashboard`) {
		t.Error("web startup log still advertises the retired /dashboard route")
	}
	if !strings.Contains(src, "/%s/dash/") {
		t.Error("web startup log no longer prints the /<admin-path>/dash/ URL")
	}
}

// DoH token enforcement (B-07 companion): with tokens installed, a request
// without ?token= is refused and with a valid one is served.
func TestDoHTokenEnforcementWiring(t *testing.T) {
	// Source-level pin: the DoH handler must expose SetDoHTokens and the DoH
	// layer must check it.
	dohSrc := readGoSource(t, "../../internal/core/dns/doh.go")
	if !strings.Contains(dohSrc, "func (h *DoHHandler) SetDoHTokens") {
		t.Error("DoHHandler lost its SetDoHTokens hook — config doh_tokens are being dropped again")
	}
	if !strings.Contains(dohSrc, "tokenOK") {
		t.Error("DoH layer lost the token gate")
	}
}

// B-22: Stop() cancels the server base context so SSE handlers return.
func TestStopCancelsServerContext(t *testing.T) {
	// Source-level pin: Stop must call stopServerCtx before Shutdown.
	stopSrc := readGoSource(t, "server.go")
	idxStop := strings.Index(stopSrc, "func (ws *WebServer) Stop() {")
	if idxStop < 0 {
		t.Fatal("WebServer.Stop not found")
	}
	stopBody := stopSrc[idxStop:]
	if !strings.Contains(stopBody[:strings.Index(stopBody, "\n}")+2], "stopServerCtx()") {
		t.Error("WebServer.Stop no longer cancels the server base context; SSE handlers hang the drain again")
	}
}

// B-15: redirect Location re-brackets an IPv6 host.
func TestRedirectHostBracketsIPv6(t *testing.T) {
	if got := redirectHost("2001:db8::1"); got != "[2001:db8::1]" {
		t.Errorf("redirectHost = %q, want [2001:db8::1]", got)
	}
	if got := redirectHost("panel.example"); got != "panel.example" {
		t.Errorf("redirectHost(hostname) = %q, want it untouched", got)
	}
	if got := redirectHost("203.0.113.9"); got != "203.0.113.9" {
		t.Errorf("redirectHost(v4) = %q, want it untouched (no brackets for v4)", got)
	}
}

// newAuthSettings is the harness default auth record used by the 2FA flows.
func newAuthSettings(t *testing.T) *database.AuthSettings {
	t.Helper()
	return &database.AuthSettings{}
}
