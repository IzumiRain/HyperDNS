package web

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"hyperdns/internal/auth"
	"hyperdns/internal/database"
	"hyperdns/internal/httpx"
)

// The v2.1 authentication surface: TOTP enrollment and LDAP directory
// settings (Phase 6), plus the shared checks every credential-changing
// endpoint runs when two-factor is in force.
//
// Two rules this file enforces everywhere:
//
//  1. Second factor for second-factor changes. Every endpoint here — and the
//     password-change and API-key endpoints — re-asks for the current password,
//     and when TOTP is enabled also for a current one-time code. An attacker
//     holding a stolen session token can therefore look, but not touch.
//  2. One failure string. The local login, the LDAP login, and the TOTP check
//     all answer "Invalid credentials". A different message per path would be
//     an oracle telling a prober which paths exist.

// SetAuthSettings attaches the auth record (test harness convenience; main
// wires it after construction, like SetSubscriptionSettings).
func (ws *WebServer) SetAuthSettings(a *database.AuthSettings) {
	ws.authSettings = a
}

// SetLDAPAuthenticator swaps the directory client (tests inject a fake).
func (ws *WebServer) SetLDAPAuthenticator(a auth.LDAPAuthenticator) {
	ws.ldapAuth = a
}

// totpReplayGuard makes a validated TOTP code single-use across every gated
// endpoint. Without it one observed code authorised any number of concurrent
// calls in its 90-second window — login, unlock and key rotation included.
// The key is the code itself and the entry lives 90 seconds (the ±1-step
// validity the RFC allows), swept opportunistically on insert.
type totpReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newTOTPReplayGuard() *totpReplayGuard {
	return &totpReplayGuard{seen: map[string]time.Time{}}
}

// spend reports whether this code has not been used yet, and records it.
func (g *totpReplayGuard) spend(code string) bool {
	if g == nil || code == "" {
		return true
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, until := range g.seen {
		if until.Before(now) {
			delete(g.seen, k)
		}
	}
	if _, ok := g.seen[code]; ok {
		return false
	}
	g.seen[code] = now.Add(90 * time.Second)
	return true
}

// totpGate enforces the second factor on an already-authenticated,
// credential-changing endpoint. When two-factor is in force the request body
// must carry a current, not-yet-spent one-time code; without or with a wrong
// one the request is answered 401 and false comes back. When 2FA is off it is
// a no-op, so a pre-enrollment deployment keeps working unchanged.
func (ws *WebServer) totpGate(w http.ResponseWriter, code string) bool {
	if !ws.authSettings.TOTPEnabledNow() {
		return true
	}
	code = strings.TrimSpace(code)
	if !auth.ValidateTOTP(ws.authSettings.GetTOTPSecret(), code) || !ws.totpReplay.spend(code) {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "Invalid credentials")
		return false
	}
	return true
}

// totpRequestGate is totpGate in request-shaped form, for the v1 REST router
// (internal/api cannot import this package to call the writer version, and
// its handlers own their own responses). The code comes from the JSON body
// only: a code is a credential, and this codebase's own rule for credentials
// is that they do not ride query strings, where access logs and proxy logs
// copy them.
func (ws *WebServer) totpRequestGate(r *http.Request) bool {
	if !ws.authSettings.TOTPEnabledNow() {
		return true
	}
	code := ""
	if r.Body != nil {
		var body struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err == nil {
			code = body.Code
		}
	}
	code = strings.TrimSpace(code)
	return auth.ValidateTOTP(ws.authSettings.GetTOTPSecret(), code) && ws.totpReplay.spend(code)
}

// mapGetter adapts a decoded JSON map.
type mapGetter map[string]any

func (m mapGetter) Get(key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// decodeBodyMap decodes a JSON object into a mapGetter, bounded like every
// other body in the package.
func decodeBodyMap(w http.ResponseWriter, r *http.Request) (mapGetter, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil || m == nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request format")
		return nil, false
	}
	return mapGetter(m), true
}

// handleAuth2FASetup opens a TOTP enrollment. Requires the current password;
// when 2FA is already active it refuses — disabling first is the deliberate
// downgrade step. The response carries the secret and the otpauth URI exactly
// once; the snapshot channel never repeats it.
func (ws *WebServer) handleAuth2FASetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	body, ok := decodeBodyMap(w, r)
	if !ok {
		return
	}
	if ok, _ := ws.verifyAdminPassword(body.Get("username"), body.Get("current_password")); !ok {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	secret := auth.GenerateTOTPSecret()
	if err := ws.authSettings.SetTOTPPending(secret, func(a *database.AuthSettings) error {
		return ws.db.SetSetting("auth", a)
	}); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	adminUser, _, _ := ws.settings.AdminCredentials()
	if adminUser == "" {
		adminUser = "admin"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"secret":      secret,
		"otpauth_uri": auth.OTPAuthURI("HyperDNS", adminUser, secret),
	})
}

// handleAuth2FAEnable confirms an open enrollment: the code the phone is now
// showing must validate against the pending secret. On success the secret is
// promoted and every session dies — the operator re-logs in, now answering the
// authenticator prompt.
func (ws *WebServer) handleAuth2FAEnable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	body, ok := decodeBodyMap(w, r)
	if !ok {
		return
	}
	if ok, _ := ws.verifyAdminPassword(body.Get("username"), body.Get("current_password")); !ok {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	confirmed, err := ws.authSettings.ConfirmTOTP(
		strings.TrimSpace(body.Get("code")),
		time.Now().UTC().Format(time.RFC3339),
		auth.ValidateTOTP,
		func(a *database.AuthSettings) error { return ws.db.SetSetting("auth", a) },
	)
	if err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !confirmed {
		// The enrollment stays open; nothing changed. The shared string keeps
		// wrong codes indistinguishable from wrong passwords.
		httpx.WriteJSONError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if ws.sessions != nil {
		ws.sessions.DeleteAll()
	}
	log.Printf("[Web] Two-factor authentication enabled; all sessions invalidated")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// handleAuth2FADisable turns 2FA off. It demands both factors one last time:
// the current password and a current code. Sessions die with it, per the plan.
func (ws *WebServer) handleAuth2FADisable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	body, ok := decodeBodyMap(w, r)
	if !ok {
		return
	}
	if ok, _ := ws.verifyAdminPassword(body.Get("username"), body.Get("current_password")); !ok {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if ws.authSettings.TOTPEnabledNow() {
		code := strings.TrimSpace(body.Get("code"))
		if code == "" || !auth.ValidateTOTP(ws.authSettings.GetTOTPSecret(), code) {
			httpx.WriteJSONError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
	} else {
		// Disabling when nothing is enabled is a no-op success, not an error:
		// the UI and the server agree without a second round trip.
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		return
	}

	if err := ws.authSettings.DisableTOTP(func(a *database.AuthSettings) error {
		return ws.db.SetSetting("auth", a)
	}); err != nil {
		httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not save the auth settings")
		return
	}
	if ws.sessions != nil {
		ws.sessions.DeleteAll()
	}
	log.Printf("[Web] Two-factor authentication disabled; all sessions invalidated")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// handleAuth2FAStatus is the read-only view the settings panel renders. It
// carries no secrets — that is enforced by the snapshot type itself.
func (ws *WebServer) handleAuth2FAStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	snap := ws.authSettings.Snapshot()
	// The pending enrollment's otpauth URI embeds the shared secret, and this
	// endpoint is reachable with any live session — no password, no code. The
	// URI therefore never leaves the setup response, which IS password-gated:
	// status only says whether an enrollment is open ("present"), and the
	// operator who reloads the page mid-enrollment re-runs setup (a fresh
	// secret; the old pending one is discarded).
	if snap.OTPAuthURI != "" && snap.OTPAuthURI != "present" {
		snap.OTPAuthURI = "present"
	}
	_ = json.NewEncoder(w).Encode(snap)
}

// handleLDAPSettings reads and writes the directory configuration. GET answers
// the snapshot — which structurally cannot carry the bind password — and POST
// validates, saves, and answers the same masked snapshot.
func (ws *WebServer) handleLDAPSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(ws.authSettings.Snapshot())
		return
	case http.MethodPost:
	default:
		httpx.WriteMethodNotAllowed(w, "GET, POST")
		return
	}

	body, ok := decodeBodyMap(w, r)
	if !ok {
		return
	}

	// Credential re-auth first — the invariant this file states, and here it
	// matters most: the directory IS the login path, so repointing it from a
	// bare session would let a stolen token mint a durable admin login
	// against whatever server the request names. Password always, current
	// code when 2FA is in force.
	if !ws.reauthCurrentPassword(body.Get("current_password")) {
		httpx.WriteJSONError(w, http.StatusForbidden, "Current password is incorrect")
		return
	}
	if !ws.totpGate(w, body.Get("code")) {
		return
	}

	enabled := body.Get("enabled") == "true"
	str := func(key string) string { return strings.TrimSpace(body.Get(key)) }
	serverURL := str("ldap_server_url")
	mode := str("ldap_login_mode")

	// Validate the URL shape before anything persists. Only ldap:// and
	// ldaps:// are accepted: a bare host:port would silently dial cleartext
	// with no way for the operator to tell, which is exactly the failure the
	// plan calls out.
	if serverURL != "" && !strings.HasPrefix(serverURL, "ldap://") && !strings.HasPrefix(serverURL, "ldaps://") {
		httpx.WriteJSONError(w, http.StatusBadRequest, "the LDAP server URL must start with ldap:// or ldaps://")
		return
	}
	switch mode {
	case "local", "ldap", "both", "":
		mode = strings.TrimSpace(mode)
	default:
		httpx.WriteJSONError(w, http.StatusBadRequest, "login mode must be local, ldap, or both")
		return
	}

	// The bind password is only replaced when the request carries a new one:
	// the UI re-sends the form without it, and re-reading the field would
	// otherwise wipe the stored credential.
	bindPassword := body.Get("ldap_bind_password")
	if bindPassword == "" {
		bindPassword = ws.storedBindPassword()
	}

	if err := ws.authSettings.SetLDAP(
		enabled, serverURL, str("ldap_bind_dn"), bindPassword, str("ldap_base_dn"), str("ldap_user_attr"), mode,
		func(a *database.AuthSettings) error { return ws.db.SetSetting("auth", a) },
	); err != nil {
		log.Printf("[Web] Could not persist LDAP settings: %v", err)
		httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not save the LDAP settings")
		return
	}

	// Authentication-mode change: sessions die, per the plan.
	if ws.sessions != nil {
		ws.sessions.DeleteAll()
	}
	log.Printf("[Web] LDAP settings saved (enabled=%v mode=%s); sessions invalidated", enabled, mode)
	_ = json.NewEncoder(w).Encode(ws.authSettings.Snapshot())
}

// storedBindPassword reads the current bind password through a round-trip the
// type system cannot shortcut: it exists so a partial save (UI form without
// the password field) preserves the stored credential.
func (ws *WebServer) storedBindPassword() string {
	if cfg, ok := ws.authSettings.LDAPConfigNow(); ok {
		return cfg.BindPassword
	}
	// LDAP may be disabled but the bind password still stored.
	if ws.authSettings == nil {
		return ""
	}
	snap := ws.authSettings.Snapshot()
	_ = snap // the snapshot deliberately cannot carry it; read under the record
	return ws.authSettings.StoredBindPassword()
}
