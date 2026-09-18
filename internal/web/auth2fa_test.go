package web

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdns/internal/auth"
	"hyperdns/internal/database"
)

// jsLineCommentRe strips // comments from a slice of js/app.js, so a scan can
// pin the order of real code without the code's own explanation of itself
// counting as an occurrence.
var jsLineCommentRe = regexp.MustCompile(`//[^\n]*`)

// Phase 6 (v2.1) test suite: TOTP two-factor end-to-end, the LDAP login paths
// against a fake authenticator, the second-factor gates on credential
// mutations, and the structural guarantee that no auth secret serialises.

// fakeLDAP records the calls it saw and answers from a table, so every branch
// of the login mode logic is exercised without a real directory.
type fakeLDAP struct {
	mu       sync.Mutex
	calls    []string
	failAll  bool
	accepted map[string]bool // username+":"+password that succeed
}

func (f *fakeLDAP) Authenticate(username, password string, cfg auth.LDAPConfig) error {
	f.mu.Lock()
	f.calls = append(f.calls, username+":"+password)
	_, ok := f.accepted[username+":"+password]
	fail := f.failAll
	f.mu.Unlock()
	if fail || !ok {
		return errFakeRejected
	}
	return nil
}

var errFakeRejected = &fakeErr{"invalid credentials"}

type fakeErr struct{ msg string }

func (e *fakeErr) Error() string { return e.msg }

// totpStepStart returns the start of the current TOTP step. Tests derive every
// code from this rather than from a bare time.Now(): a code computed late in
// step N drops out of the verifier's ±1-step window the moment the clock rolls
// into step N+1, so a login answered a few seconds late could see a stale code
// and answer 401 — the body then has no token, and an unguarded assertion
// panics instead of reporting the failure. Anchoring to the step start keeps
// the previous-, current- and next-step codes all valid for the whole step.
//
// This is only meaningful because the suite keeps the login KDF cheap in
// tests (see crypto.HashPasswordWithCost): a derivation that takes seconds
// per login ages a code out of its window whatever the anchor, and the flake
// this comment replaced was exactly that, not a step-boundary race.
func totpStepStart() time.Time {
	step := int64(auth.TOTPStep / time.Second)
	return time.Unix((time.Now().Unix()/step)*step, 0)
}

// codeFor derives the 6-digit code a correct authenticator would show for the
// secret at now — an independent derivation (HMAC-SHA1, dynamic truncation) so
// the endpoint tests do not validate the implementation against itself.
func codeFor(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(at.Unix())/uint64(auth.TOTPStep/time.Second))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint64(sum[off])&0x7f)<<24 | uint64(sum[off+1])<<16 | uint64(sum[off+2])<<8 | uint64(sum[off+3])
	return fmt.Sprintf("%06d", v%1000000)
}

// loginWithCode posts a full three-factor login (username, password, TOTP code).
func loginWithCode(t *testing.T, h http.Handler, user, pass, code string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(
		`{"username":`+strconv.Quote(user)+`,"password":`+strconv.Quote(pass)+`,"code":`+strconv.Quote(code)+`}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// enrollAndEnable runs the full 2FA enrollment through the real endpoints:// setup (with password), then enable with the code the test derives from the
// returned secret. It is the same journey the operator's browser makes.
func enrollAndEnable(t *testing.T, h http.Handler, tok string) string {
	t.Helper()

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	w := post("/api/auth/2fa/setup", `{"username":"admin","current_password":"`+testAdminPassword+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("2fa setup = %d — %s", w.Code, w.Body.String())
	}
	secret, _ := decodeBody(t, w)["secret"].(string)
	if secret == "" {
		t.Fatal("setup returned no secret")
	}
	code := codeFor(t, secret, totpStepStart())

	w = post("/api/auth/2fa/enable", `{"username":"admin","current_password":"`+testAdminPassword+`","code":"`+code+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("2fa enable = %d — %s", w.Code, w.Body.String())
	}
	return secret
}

func TestTwoFactorEnrollmentFlow(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetAuthSettings(&database.AuthSettings{})
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	if ws.authSettings.TOTPEnabledNow() {
		t.Fatal("2FA enabled before enrollment")
	}

	secret := enrollAndEnable(t, h, tok)
	if !ws.authSettings.TOTPEnabledNow() {
		t.Fatal("enrollment finished but TOTPEnabledNow is false")
	}
	if ws.authSettings.GetPendingSecret() != "" {
		t.Error("a confirmed enrollment left a pending secret behind")
	}
	if ws.authSettings.GetTOTPSecret() != secret {
		t.Error("the confirmed secret is not the enrollment secret")
	}
	// The enable response deleted every session: the token that enrolled is dead.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("the enrolling session survived the enable; 2FA must kill sessions")
	}
}

func TestTwoFactorGatesLogins(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetAuthSettings(&database.AuthSettings{})
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)
	enrollAndEnable(t, h, tok)

	login := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.7:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// Right password, no code: refused with the shared string, and the body
	// carries twofactor_required — the flag the login form reveals the code
	// field for.
	w := login(`{"username":"admin","password":"` + testAdminPassword + `"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("login without a code = %d, want 401", w.Code)
	}
	if !decodeBody(t, w)["twofactor_required"].(bool) {
		t.Errorf("login without a code did not set twofactor_required — the form would never reveal the code field: %s", w.Body.String())
	}
	// Right password, wrong code: refused, still flagged as needing the factor.
	if w = login(`{"username":"admin","password":"` + testAdminPassword + `","code":"000000"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("login with a wrong code = %d, want 401", w.Code)
	}
	// Wrong password with a right-looking code: refused, and NOT flagged —
	// this is the case that used to be indistinguishable from a missing
	// second factor, and flagging it would leak that a password was wrong
	// versus missing a factor. The form keys the 2FA row on this flag, so a
	// plain bad password must never surface the TWO-FACTOR CODE box.
	if w = login(`{"username":"admin","password":"nope-nope-nope-nope","code":"123456"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("login with a wrong password = %d, want 401", w.Code)
	}
	if decodeBody(t, w)["twofactor_required"] != nil {
		t.Errorf("a wrong password set twofactor_required — the first-time login form would show a 2FA prompt on an install with 2FA off: %s", w.Body.String())
	}
	// The three failures above spent this address's lockout budget, which is
	// exactly the interaction the unlock endpoint exists for (Phase C): clear
	// the lockout, then prove the correct second factor gets in.
	// The 2FA enable flow wiped every dashboard session, so `tok` is dead —
	// the master API key is the credential that survives it, and it is what
	// the TUI uses over loopback in production. Two-factor is on, so the
	// unlock carries a current code: an endpoint that undoes a security
	// control must not be cheaper to reach than the control it undoes.
	// One anchor for every code this test spends, pinned to the step start: a
	// code computed late in step N ages out of the verifier's ±1-step window
	// the moment the clock rolls into step N+1, and under -race the suite is
	// slow enough for exactly that to happen between spending two codes.
	totpAnchor := totpStepStart()
	unlockCode := codeFor(t, ws.authSettings.GetTOTPSecret(), totpAnchor)
	unlock := httptest.NewRequest(http.MethodPost, "/api/auth/unlock", strings.NewReader(`{"code":"`+unlockCode+`"}`))
	unlock.Header.Set("Content-Type", "application/json")
	unlock.Header.Set("X-API-Key", ws.settings.GetAPIKey())
	unlock.RemoteAddr = "203.0.113.7:5555"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, unlock)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock after the failures = %d — %s", w.Code, w.Body.String())
	}

	// A validated code is single-use now (replay guard), so the login needs a
	// different step than the unlock above — the NEXT step, not the previous
	// one: ValidateTOTPAt's window is [now-1, now+1], so a previous-step code
	// computed late in step N ages out the instant the clock reaches step N+1,
	// while a next-step code is already valid and stays valid for two whole
	// steps. See TestValidateTOTPAcceptsSkewWindow for the window itself.
	code := codeFor(t, ws.authSettings.GetTOTPSecret(), totpAnchor.Add(auth.TOTPStep))
	if w := login(`{"username":"admin","password":"` + testAdminPassword + `","code":"` + code + `"}`); w.Code != http.StatusOK {
		t.Errorf("login with both factors = %d, want 200 — %s", w.Code, w.Body.String())
	}
}

// TestLoginFormRevealSurvivesErrorMessage pins the field report: with 2FA
// enabled, the dashboard's login overlay answered a correct password with
// "Invalid credentials" and never revealed the TWO-FACTOR CODE row. The cause
// was an ordering bug in the submit handler, not the server: errorMessage()
// consumes the response body with res.text(), and the second-factor check
// afterwards called res.clone().json() — clone() on an already-read Response
// throws, the catch swallowed it, and the reveal never fired. The body must be
// read exactly once and both decisions taken from that one parse.
func TestLoginFormRevealSurvivesErrorMessage(t *testing.T) {
	app := readAsset(t, "js/app.js")

	// Slice out the !res.ok branch of the login submit handler. The anchor is
	// the fetch line that names the login route — "if (!res.ok) {" alone also
	// matches clientAction and every other handler in the file.
	anchor := "fetch(api('/api/auth/login')"
	start := strings.Index(app, anchor)
	if start < 0 {
		t.Fatal("js/app.js has no /api/auth/login fetch — the scan is broken")
	}
	rel := strings.Index(app[start:], "if (!res.ok) {")
	if rel < 0 {
		t.Fatal("the login handler has no failure branch — the scan is broken")
	}
	start += rel
	// The branch ends at the first "return;" after the reveal guard.
	end := strings.Index(app[start:], "return;")
	if end < 0 {
		t.Fatal("could not find the end of the login handler's failure branch")
	}
	branch := app[start : start+end]

	// The broken ordering was: await errorMessage(res, ...) — which consumes the
	// body via res.text() — followed by res.clone().json(). clone() on a used
	// Response throws, the catch swallowed it, and the reveal never fired. A
	// clone taken BEFORE the first read is the correct pattern, so what is
	// pinned here is the order: the clone must precede the errorMessage call.
	// Comments are stripped first — the branch's own explanation names
	// errorMessage(), which would otherwise count as the call itself.
	code := jsLineCommentRe.ReplaceAllString(branch, "")
	cloneIdx := strings.Index(code, "res.clone()")
	msgIdx := strings.Index(code, "errorMessage(")
	if cloneIdx >= 0 && msgIdx >= 0 && cloneIdx > msgIdx {
		t.Errorf("the login failure branch clones the response only after errorMessage() " +
			"has consumed the body — clone() on a used Response throws, the catch swallows " +
			"it, and the twofactor_required reveal never fires")
	}
	if msgIdx >= 0 && cloneIdx < 0 {
		t.Errorf("the login failure branch consumes the body through errorMessage() with no " +
			"clone taken first — the twofactor_required check afterwards can never read the body")
	}
	// The flag must still be read inside the branch, or the code row can never
	// be revealed.
	if !strings.Contains(branch, "twofactor_required") {
		t.Error("the login failure branch no longer reads twofactor_required — the code row can never be revealed")
	}
}

// TestFirstLoginNeverAsksForTwoFactor pins the field report: on an install
// where 2FA has never been enrolled, a failed first login must not be answered
// with twofactor_required — the login form showed a TWO-FACTOR CODE box to an
// operator logging in for the very first time.
func TestFirstLoginNeverAsksForTwoFactor(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	// The harness's default auth record: no enrollment, no secret, 2FA off.
	if ws.authSettings.TOTPEnabledNow() {
		t.Fatal("a fresh harness must not have 2FA enabled")
	}
	h := ws.buildAdminHandler()

	// A wrong password on a first login: 401 with the shared message and no
	// second-factor flag.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(
		`{"username":"admin","password":"totally-wrong-password","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("first login with a wrong password = %d, want 401", w.Code)
	}
	if decodeBody(t, w)["twofactor_required"] != nil {
		t.Errorf("a 2FA-free install answered a first login with twofactor_required — the operator is shown a code box that can never be right: %s", w.Body.String())
	}

	// And the correct first login needs no code at all.
	if w := login(t, h, "admin", testAdminPassword); w.Code != http.StatusOK {
		t.Errorf("first login with the right password = %d, want 200 — %s", w.Code, w.Body.String())
	}
}

func TestTwoFactorDisableRequiresBothFactors(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetAuthSettings(&database.AuthSettings{})
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)
	enrollAndEnable(t, h, tok)

	// The enrollment wiped the enrolling session; log back in with a code.
	code := codeFor(t, ws.authSettings.GetTOTPSecret(), totpStepStart())
	wCode := loginWithCode(t, h, "admin", testAdminPassword, code)
	gotTok, ok := decodeBody(t, wCode)["token"].(string)
	if !ok || gotTok == "" {
		t.Fatalf("login with the current-step code = %d, want 200 so the disable flow has a session to test — %s", wCode.Code, wCode.Body.String())
	}
	tok = gotTok

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/disable", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// Password only: the disable must not go through — this is the one call
	// that would silently remove the second factor.
	if w := post(`{"username":"admin","current_password":"` + testAdminPassword + `"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("disable without a code = %d, want 401", w.Code)
	}
	if !ws.authSettings.TOTPEnabledNow() {
		t.Fatal("2FA was disabled without a code")
	}

	// Both factors: disabled, sessions wiped.
	code = codeFor(t, ws.authSettings.GetTOTPSecret(), totpStepStart())
	w := post(`{"username":"admin","current_password":"` + testAdminPassword + `","code":"` + code + `"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("disable with both factors = %d — %s", w.Code, w.Body.String())
	}
	if ws.authSettings.TOTPEnabledNow() || ws.authSettings.GetTOTPSecret() != "" {
		t.Error("disable left credential material behind")
	}
}

func TestSecondFactorGatesCredentialChanges(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetAuthSettings(&database.AuthSettings{})
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)
	enrollAndEnable(t, h, tok)
	// enrollAndEnable killed the session; log in again with a code.
	code := codeFor(t, ws.authSettings.GetTOTPSecret(), totpStepStart())
	tok2, ok := decodeBody(t, login(t, h, "admin", testAdminPassword))["token"].(string)
	_ = tok2
	if !ok {
		// login() without a code now fails by design; log in WITH one.
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`","code":"`+code+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.7:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		tok2, ok = decodeBody(t, w)["token"].(string)
		if !ok {
			t.Fatalf("could not re-login under 2FA: %s", w.Body.String())
		}
	}

	// Password change without a code: refused even with the right current
	// password — a hijacked session must not rotate the credential.
	req := httptest.NewRequest(http.MethodPost, "/api/config/server", strings.NewReader(
		`{"admin_password":"NewStrong-Passw0rd!","current_password":"`+testAdminPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok2)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("password change without a code = %d, want 401", w.Code)
	}

	// API-key rotation: the current password is asked for unconditionally
	// (rotation IS a credential change), so a bare session is 403 before the
	// code is even consulted; with the password but no code it is 401.
	req = httptest.NewRequest(http.MethodPost, "/api/settings/regenerate-api-key", strings.NewReader(``))
	req.Header.Set("Authorization", "Bearer "+tok2)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("api-key rotation without a password = %d, want 403", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/settings/regenerate-api-key",
		strings.NewReader(`{"current_password":"`+testAdminPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok2)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("api-key rotation with password but no code = %d, want 401", w.Code)
	}

	// With a code from a different step than the login spent (a validated
	// code is single-use): both go through. The next step, not the previous
	// one — the skew window is asymmetric in practice, see the unlock test.
	code2 := codeFor(t, ws.authSettings.GetTOTPSecret(), totpStepStart().Add(auth.TOTPStep))
	req = httptest.NewRequest(http.MethodPost, "/api/config/server", strings.NewReader(
		`{"admin_password":"NewStrong-Passw0rd!","current_password":"`+testAdminPassword+`","code":"`+code2+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok2)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("password change with a code = %d — %s", w.Code, w.Body.String())
	}
}

func TestLDAPLoginPaths(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetAuthSettings(&database.AuthSettings{})
	fake := &fakeLDAP{accepted: map[string]bool{
		"admin:directory-pass": true,
		"jane:directory-pass":  true,
	}}
	ws.SetLDAPAuthenticator(fake)
	h := ws.buildAdminHandler()

	if err := ws.authSettings.SetLDAP(true, "ldaps://dir.example:636", "cn=svc,dc=example,dc=com", "svc-secret", "ou=people,dc=example,dc=com", "uid", "ldap", func(a *database.AuthSettings) error {
		return ws.db.SetSetting("auth", a)
	}); err != nil {
		t.Fatalf("SetLDAP: %v", err)
	}

	login := func(user, pass string) *httptest.ResponseRecorder {
		return login(t, h, user, pass)
	}

	// LDAP-only mode: a local credential is refused, the directory
	// credential for the ADMIN ACCOUNT is accepted, and every other entry
	// under the BaseDN is refused even though the directory accepted it —
	// the panel decides who may log in, one admin account, always.
	if w := login("admin", testAdminPassword); w.Code != http.StatusUnauthorized {
		t.Errorf("local login under ldap-only mode = %d, want 401", w.Code)
	}
	if w := login("jane", "directory-pass"); w.Code != http.StatusUnauthorized {
		t.Errorf("a non-admin directory user = %d, want 401 (the directory validates credentials; the panel picks the account)", w.Code)
	}
	if w := login("admin", "directory-pass"); w.Code != http.StatusOK {
		t.Errorf("directory login for the admin account = %d, want 200 — %s", w.Code, w.Body.String())
	}
	if ws.sessions.Count() == 0 {
		t.Error("a successful LDAP login minted no session")
	}
	// Every failure was a failure of the directory, not of the local record.
	fake.mu.Lock()
	calls := len(fake.calls)
	fake.mu.Unlock()
	if calls < 2 {
		t.Errorf("the fake authenticator saw %d calls, want at least one per attempt", calls)
	}

	// Switch to local: the directory is not consulted at all.
	if err := ws.authSettings.SetLDAP(true, "ldaps://dir.example:636", "cn=svc,dc=example,dc=com", "svc-secret", "ou=people,dc=example,dc=com", "uid", "local", func(a *database.AuthSettings) error {
		return ws.db.SetSetting("auth", a)
	}); err != nil {
		t.Fatalf("SetLDAP local: %v", err)
	}
	fake.mu.Lock()
	before := len(fake.calls)
	fake.mu.Unlock()
	if w := login("admin", testAdminPassword); w.Code != http.StatusOK {
		t.Errorf("local login under local mode = %d, want 200", w.Code)
	}
	fake.mu.Lock()
	after := len(fake.calls)
	fake.mu.Unlock()
	if after != before {
		t.Error("local mode consulted the directory")
	}

	// Both mode: a directory failure falls back to the local record.
	if err := ws.authSettings.SetLDAP(true, "ldaps://dir.example:636", "cn=svc,dc=example,dc=com", "svc-secret", "ou=people,dc=example,dc=com", "uid", "both", func(a *database.AuthSettings) error {
		return ws.db.SetSetting("auth", a)
	}); err != nil {
		t.Fatalf("SetLDAP both: %v", err)
	}
	if w := login("admin", testAdminPassword); w.Code != http.StatusOK {
		t.Errorf("both-mode fallback login = %d, want 200", w.Code)
	}
}

func TestLDAPSettingsNeverEchoBindPassword(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetAuthSettings(&database.AuthSettings{})
	h := ws.buildAdminHandler()

	// The mode switch deletes sessions by design, so every POST re-logs in.
	// The saves below use mode "both" so the local login keeps working for the
	// re-login (ldap-only would lock the test out of its own harness).
	relogin := func() string {
		return decodeBody(t, login(t, h, "admin", testAdminPassword))["token"].(string)
	}

	post := func(body string) *httptest.ResponseRecorder {
		tok := relogin()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/ldap", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	w := post(`{"current_password":"` + testAdminPassword + `","enabled":"true","ldap_server_url":"ldaps://dir.example:636","ldap_bind_dn":"cn=svc,dc=example,dc=com","ldap_bind_password":"super-secret","ldap_base_dn":"ou=people,dc=example,dc=com","ldap_user_attr":"uid","ldap_login_mode":"both"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("LDAP save = %d — %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "super-secret") {
		t.Fatal("the bind password came back in the response")
	}

	// GET must not leak it either.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/ldap", nil)
	req.Header.Set("Authorization", "Bearer "+relogin())
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "super-secret") {
		t.Fatal("GET /api/auth/ldap echoed the bind password")
	}

	// A partial save without the password field preserves the stored one —
	// then GET still carries nothing.
	w = post(`{"current_password":"` + testAdminPassword + `","enabled":"true","ldap_server_url":"ldaps://dir2.example:636","ldap_base_dn":"ou=x,dc=example,dc=com","ldap_login_mode":"both"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("partial LDAP save = %d — %s", w.Code, w.Body.String())
	}
	if ws.authSettings.StoredBindPassword() != "super-secret" {
		t.Error("a partial save wiped the stored bind password")
	}
	if strings.Contains(w.Body.String(), "super-secret") {
		t.Error("the partial-save response echoed the bind password")
	}
}

func TestAuthSnapshotCarriesNoSecrets(t *testing.T) {
	// Structural, not behavioural: walk the snapshot type and fail on any field
	// whose name suggests a credential. A future field named to evade this is
	// a review problem, but the obvious accidents are caught here.
	st := reflect.TypeFor[database.AuthSnapshot]()
	for i := 0; i < st.NumField(); i++ {
		name := strings.ToLower(st.Field(i).Name)
		for _, banned := range []string{"secret", "password", "credential"} {
			if strings.Contains(name, banned) {
				t.Errorf("AuthSnapshot field %q carries a credential-shaped name; "+
					"the snapshot must not be able to hold secrets", st.Field(i).Name)
			}
		}
	}
}

// TestLDAPSettingsRejectNonLDAPURLS pins the scheme check: a bare host or an
// https:// URL is refused rather than dialed blind.
func TestLDAPSettingsRejectNonLDAPURLS(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetAuthSettings(&database.AuthSettings{})
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	for _, url := range []string{"dir.example:636", "https://dir.example", "ftp://dir.example"} {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/ldap", strings.NewReader(
			`{"current_password":"`+testAdminPassword+`","enabled":"true","ldap_server_url":"`+url+`","ldap_base_dn":"ou=x,dc=example,dc=com"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("LDAP URL %q was accepted (%d), want 400", url, w.Code)
		}
	}
}

// TestTOTPCodeCannotBeReplayedAcrossGatedEndpoints: the single-use invariant.
// One validated code must not authorise a second gated operation, and least of
// all a different one — a code seen at login must not buy a key rotation, a
// lockout unlock, or a directory re-point. The RFC 6238 one-time-use rule
// applies per verifier; the cross-endpoint part is HyperDNS's own invariant,
// and this is the test that owns it.
func TestTOTPCodeCannotBeReplayedAcrossGatedEndpoints(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.SetAuthSettings(&database.AuthSettings{})
	h := ws.buildAdminHandler()
	secret := enrollAndEnable(t, h, bearerFor(t, h))

	// One anchor for every code this test spends, pinned to the start of the
	// current step so the previous-, current- and next-step codes are all valid
	// for the whole step. The suite keeps the login KDF cheap in tests, so the
	// three derivations and their logins complete well inside one step.
	anchor := totpStepStart()
	codeA := codeFor(t, secret, anchor)

	// Login with the code: accepted, and the code is now spent.
	if w := loginWithCode(t, h, "admin", testAdminPassword, codeA); w.Code != http.StatusOK {
		t.Fatalf("login with the fresh code = %d, want 200 — %s", w.Code, w.Body.String())
	}

	// The SAME code on a DIFFERENT gated endpoint: refused. The unlock route
	// is the one that also accepts the master key, which makes it the highest
	// value target for a captured code.
	codeB := codeFor(t, secret, anchor.Add(-auth.TOTPStep))
	wPrev := loginWithCode(t, h, "admin", testAdminPassword, codeB)
	tok, ok := decodeBody(t, wPrev)["token"].(string)
	if !ok || tok == "" {
		t.Fatalf("login with the previous-step code = %d, want 200 so the guard has a session to test — %s", wPrev.Code, wPrev.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/unlock", strings.NewReader(`{"code":"`+codeA+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("the login's spent code was accepted for unlock: %d, want 401", w.Code)
	}

	// A different valid code still works: the guard refuses REUSE, not the
	// mechanism. This third code belongs to the next step — the previous one
	// was spent by the login that minted the session above, and the current
	// one by the first.
	codeC := codeFor(t, secret, anchor.Add(+auth.TOTPStep))
	req = httptest.NewRequest(http.MethodPost, "/api/auth/unlock", strings.NewReader(`{"code":"`+codeC+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("a fresh code was refused: %d, want 200 — %s", w.Code, w.Body.String())
	}
}
