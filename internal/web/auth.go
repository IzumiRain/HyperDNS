// Authentication and credentials: what decides whether a request may reach a
// dashboard handler, and the two endpoints that change the credentials it checks
// against.
//
// One admin account, one master API key, and server-side sessions that a
// password change wipes. Every login runs the same KDF whether or not the
// username exists — an early return on an unknown name would turn response time
// into a username oracle — and the KDF runs behind a bounded gate so an
// unauthenticated flood cannot spend the CPU the resolver exists to use.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"runtime"
	"strings"

	"hyperdns/internal/auth"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/httpx"
	"hyperdns/internal/netutil"
	"hyperdns/internal/service"
)

// kdfConcurrency is how many password verifications may run at once: half the
// cores, at least one, never more than four. The remaining cores stay free for
// DNS, which is the reason the box exists. Login is not a throughput-sensitive
// path — one operator, a handful of attempts — so a small bound costs nothing
// real and denies an unauthenticated caller the whole CPU.
func kdfConcurrency() int {
	n := runtime.NumCPU() / 2
	if n < 1 {
		return 1
	}
	if n > 4 {
		return 4
	}
	return n
}

// verifyAdminPassword compares a submitted credential pair against the stored
// admin record under the KDF gate. It reports whether the pair authenticates and
// whether the stored password is flagged as failing the current policy.
//
// Both comparisons are unconditional: returning early on an unknown username
// would make the response time reveal whether a name exists, and would skip the
// KDF, turning username enumeration into a timing oracle.
func (ws *WebServer) verifyAdminPassword(username, password string) (ok bool, weak bool) {
	adminUser, adminPass, weak := ws.settings.AdminCredentials()

	if adminUser == "" {
		adminUser = "admin"
	}

	// Bound concurrent KDF work. The gate is only entered once the cheap checks
	// are done so a flood of malformed requests cannot occupy a slot.
	ws.kdfGate <- struct{}{}
	passMatch := crypto.VerifyPassword(adminPass, password)
	<-ws.kdfGate

	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(adminUser)) == 1
	return userMatch && passMatch, weak
}

// reauthCurrentPassword re-authenticates the operator before a credential
// change lands. The KDF is bounded by the same gate as login, so a flood of
// forged re-auth attempts cannot spend the resolver's CPU either. Every
// endpoint that rotates a credential calls this first: a hijacked session
// token must be able to look, but never to touch.
func (ws *WebServer) reauthCurrentPassword(password string) bool {
	_, verifier, _ := ws.settings.AdminCredentials()
	ws.kdfGate <- struct{}{}
	defer func() { <-ws.kdfGate }()
	return crypto.VerifyPassword(verifier, password)
}

// adminPasswordNeedsAttention reports whether the dashboard should keep nagging
// for a password change: either the stored password was flagged as weak when it
// was hashed, or it is still plaintext because a hash could not be written.
func (ws *WebServer) adminPasswordNeedsAttention() bool {
	_, verifier, weak := ws.settings.AdminCredentials()
	return weak || !crypto.IsPasswordHash(verifier)
}

// requireAuth gates dashboard APIs behind a valid session token (Bearer header
// or X-API-Key) or the master REST API key.
func (ws *WebServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return ws.authGate(next, false)
}

// requireAuthStream is requireAuth plus ?token=, which only EventSource needs
// because it cannot send headers. It is deliberately not accepted everywhere: a
// token in a query string is copied into access logs, browser history and
// Referer headers, so the exception is scoped to the two SSE routes.
//
// The method guard is inside the gate rather than in front of it, so an
// unauthenticated caller is told to authenticate rather than told which verbs the
// route takes.
func (ws *WebServer) requireAuthStream(next http.HandlerFunc) http.HandlerFunc {
	return ws.authGate(streamGetOnly(next), true)
}

// streamGetOnly refuses every verb but GET on an event stream.
//
// The SSE handler had no method guard of its own, and it is the one handler in the
// project where that costs something other than tidiness: it reserves one of
// maxSSEClients subscriber slots for the life of the connection. A POST or a PUT
// took a slot exactly as a GET did.
//
// HEAD is refused too, which is against this project's usual reading of RFC 9110
// §9.1 — a resource that serves GET should serve HEAD. The reason is the same one
// that applies to the subscriber-portal routes: net/http runs the handler for a
// HEAD and discards whatever it writes, and this handler does not return. So a
// HEAD holds a subscriber slot for as long as the caller keeps the connection
// open while being structurally unable to deliver a single event — it pays the
// whole cost of the thing the slot cap exists to ration, and receives nothing.
// The URL is also the one place in this codebase where a credential legitimately
// appears in a query string, which is precisely the shape that gets pasted into a
// chat window and fetched by a preview crawler.
func streamGetOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpx.WriteMethodNotAllowed(w, "GET")
			return
		}
		next(w, r)
	}
}

func (ws *WebServer) authGate(next http.HandlerFunc, allowQueryToken bool) http.HandlerFunc {
	// The v2.2.0 scope rule rides through here: tokenAuthorized is
	// sessions-only, so the dashboard mux refuses the master REST key.
	return ws.authGateWith(ws.tokenAuthorized, next, allowQueryToken)
}

// tokenAuthorized accepts a live dashboard session or the master API key
// (compared in constant time to prevent timing attacks).
//
// v2.2.0 scoping: the master REST key no longer authorizes dashboard admin
// routes. One credential passing both surfaces meant a leaked REST key (the
// one credential that rides HTTP headers in integrations and CI logs) was a
// full panel takeover — settings, credentials, LDAP mode, everything. The
// REST key keeps its full power on /api/v1|/api/v2 (the API router's own
// SecurityMiddleware); here, only a real dashboard session counts.
func (ws *WebServer) tokenAuthorized(token string) bool {
	return ws.sessionValid(token)
}

// tokenAuthorizedWithMasterKey is the recovery-path variant: a live session,
// or the master key (constant-time). Mounted on exactly one route —
// /api/auth/unlock, the lockout lifeline the root-local TUI calls with the
// key because it has no dashboard session to present.
func (ws *WebServer) tokenAuthorizedWithMasterKey(token string) bool {
	if ws.sessionValid(token) {
		return true
	}
	if strings.HasPrefix(token, crypto.APIKeyPrefix) {
		return subtle.ConstantTimeCompare([]byte(token), []byte(ws.settings.GetAPIKey())) == 1
	}
	return false
}

// requireAuthWithMasterKey is requireAuth plus the master-key acceptance
// above. One route may use it; everything else uses requireAuth.
func (ws *WebServer) requireAuthWithMasterKey(next http.HandlerFunc) http.HandlerFunc {
	return ws.authGateWith(ws.tokenAuthorizedWithMasterKey, next, false)
}

func (ws *WebServer) authGateWith(authorized func(string) bool, next http.HandlerFunc, allowQueryToken bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowQueryToken && ws.sseTicketAuthorized(r) {
			next(w, r)
			return
		}
		token := r.Header.Get("X-API-Key")
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}
		if token == "" || !authorized(token) {
			w.Header().Set("Content-Type", "application/json")
			httpx.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: session expired, please login again")
			return
		}
		next(w, r)
	}
}

func (ws *WebServer) sessionValid(token string) bool {
	return ws.sessions != nil && ws.sessions.Validate(token)
}

// documentSessionCookie is the name of the HttpOnly cookie that gates the SPA
// document (not the APIs). The dashboard is a bearer-token app — the JS keeps a
// token in memory and sends it as Authorization on every /api/* call — but a
// browser *navigation* to /<admin>/dash/ carries no header, so before this
// cookie the shell HTML was served to anyone who knew the path and only then did
// the JS notice there was no token and redirect to /login. That pre-auth render
// is the flash this cookie removes: the document route now redirects server-side
// when the cookie is missing or dead, so the shell never reaches an
// unauthenticated browser. It authorizes nothing else — every state-changing
// call still requires the bearer header, so adding a cookie introduces no CSRF
// surface on the API.
const documentSessionCookie = "hdns_doc_session"

// setDocumentSessionCookie records the freshly minted session as the document
// gate. Scoped to the admin path so it is never sent to the public root or the
// subscriber portal; HttpOnly so script cannot read it; Secure whenever the
// request arrived over TLS (the panel's normal mode) so it is not echoed on a
// plaintext downgrade.
func (ws *WebServer) setDocumentSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     documentSessionCookie,
		Value:    token,
		Path:     "/" + ws.adminPath(),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearDocumentSessionCookie expires the document gate at logout, so a back
// button after sign-out lands on the login page rather than the shell.
func (ws *WebServer) clearDocumentSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     documentSessionCookie,
		Value:    "",
		Path:     "/" + ws.adminPath(),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// documentSessionValid reports whether the request carries a live document-gate
// cookie. It gates only the SPA shell; API authorization is unchanged.
func (ws *WebServer) documentSessionValid(r *http.Request) bool {
	c, err := r.Cookie(documentSessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return ws.sessionValid(c.Value)
}

func (ws *WebServer) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// POST only, checked ahead of the lockout counter. Logging in is not idempotent and the
	// credentials are read from the body, so no other verb could ever have succeeded — but they
	// reached the decode and were answered 400, which reads as "your payload is malformed" when
	// the real answer is "wrong verb". A rejected verb is also not a credential guess, so it must
	// not spend one of the attempts that lock the address out.
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}

	// The lockout key is the effective client when it is trustworthy — i.e. the
	// address a DECLARED proxy forwarded — and the immediate peer otherwise.
	// Keying on a spoofable value (A-01/B-09) let an attacker rotate it per
	// request and brute-force without ever hitting the lockout, while also
	// growing the tracker map without bound.
	clientIP := netutil.ClientIP(r)

	if ws.loginLimiter != nil && ws.loginLimiter.IsBlocked(clientIP) {
		httpx.WriteJSONError(w, http.StatusTooManyRequests, "Too many failed login attempts. This address is locked for 10 minutes (the operator can unlock it sooner: Settings → Login Lockouts).")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		// Code is the TOTP value when two-factor is enabled, and is ignored
		// otherwise (an enrolled operator who has since disabled 2FA re-logs
		// with their stored autofill intact).
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request format or payload too large")
		return
	}

	// Two credential sources, ordered by the auth record's login mode: the
	// local record, the directory, or the directory falling back to the local
	// record. All of them collapse to one boolean and one failure string — a
	// prober must not learn which paths exist from an answer.
	ok, weak := false, false
	mode := ws.authSettings.GetLDAPLoginMode()
	ldapTried := false
	if cfgSnap, ldapOn := ws.authSettings.LDAPConfigNow(); ldapOn && (mode == "ldap" || mode == "both") {
		ldapTried = true
		cfg := auth.LDAPConfig{
			ServerURL:    cfgSnap.ServerURL,
			BindDN:       cfgSnap.BindDN,
			BindPassword: cfgSnap.BindPassword,
			BaseDN:       cfgSnap.BaseDN,
			UserAttr:     cfgSnap.UserAttr,
		}
		if ws.ldapAuth.Authenticate(req.Username, req.Password, cfg) == nil {
			// The directory decides whether the credentials are real; this
			// panel decides who may log in. The daemon has exactly one admin
			// account, so only the entry naming that account may pass —
			// without this check every user under the BaseDN would
			// authenticate into full panel admin.
			adminUser, _, _ := ws.settings.AdminCredentials()
			if adminUser == "" {
				adminUser = "admin"
			}
			if subtle.ConstantTimeCompare([]byte(req.Username), []byte(adminUser)) == 1 {
				ok = true
			}
		} else if mode == "both" {
			// The directory did not take the credentials; "both" means the
			// local record still gets its chance.
			ok, weak = ws.verifyAdminPassword(req.Username, req.Password)
		}
	} else if !ldapTried {
		ok, weak = ws.verifyAdminPassword(req.Username, req.Password)
	}

	// Second factor. Checked only after a primary factor has already passed:
	// asking for a code up front would confirm that 2FA is on without any
	// credential at all.
	//
	// A failure here answers with twofactor_required so the login form can
	// reveal the code field for exactly this case. The generic "Invalid
	// credentials" body alone gave the front end no way to tell "wrong
	// password" from "right password, missing second factor" — so the form
	// revealed the 2FA row on every bad password, and a first-time operator
	// was presented with a TWO-FACTOR CODE box on an install where 2FA had
	// never been enrolled. The flag tells the truth without turning the
	// response into an oracle: it only ever appears after the primary
	// credential has already verified, so an unauthenticated prober learns
	// nothing they could not learn by guessing the password correctly.
	twofactorRequired := false
	if ok && ws.authSettings.TOTPEnabledNow() {
		code := strings.TrimSpace(req.Code)
		// The replay guard makes the login code single-use too: a code
		// captured at login must not also authorise a rotation or an unlock.
		if !auth.ValidateTOTP(ws.authSettings.GetTOTPSecret(), code) || !ws.totpReplay.spend(code) {
			ok = false
			twofactorRequired = true
		}
	}

	if !ok {
		if ws.loginLimiter != nil {
			ws.loginLimiter.RecordFailure(clientIP)
		}
		if twofactorRequired {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":              "Invalid credentials",
				"twofactor_required": true,
			})
			return
		}
		httpx.WriteJSONError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if ws.loginLimiter != nil {
		ws.loginLimiter.RecordSuccess(clientIP)
	}

	// Mint a real server-side session token (hdns_session_...) that the
	// requireAuth middleware validates on every subsequent dashboard call.
	var token string
	if ws.sessions != nil {
		token = ws.sessions.Create()
	} else {
		tokBytes := make([]byte, 16)
		_, _ = rand.Read(tokBytes)
		token = "hdns_session_" + hex.EncodeToString(tokBytes)
	}

	adminUser, _, _ := ws.settings.AdminCredentials()
	if adminUser == "" {
		adminUser = "admin"
	}

	needsAttention := weak || ws.adminPasswordNeedsAttention()

	// The document-gate cookie rides alongside the JSON token: the JS uses the
	// token for API calls, the cookie lets the server refuse the shell to an
	// unauthenticated navigation without a flash.
	ws.setDocumentSessionCookie(w, r, token)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":    token,
		"username": adminUser,
		// password_weak is the accurate name: the stored password fails the current
		// policy, which is no longer the same thing as literally being "admin".
		"password_weak": needsAttention,
		// is_default_password is kept because shipped dashboards read it. It carries
		// the same value now and can go once no old asset bundle is in the field.
		"is_default_password": needsAttention,
	})
}

// presentedSessionToken returns the bearer credential the caller authenticated
// with, using the same derivation authGate uses. It is the only honest input to
// a logout: the request must revoke the exact session it arrived on, never a
// token named in a body an attacker controls.
func presentedSessionToken(r *http.Request) string {
	token := r.Header.Get("X-API-Key")
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	return token
}

// handleAuthLogout revokes the presented dashboard session server-side.
//
// The dashboard's "Sign Out" button used to only drop the token from
// localStorage, which is not a logout: the session stayed live on the daemon for
// the rest of its 24-hour lifetime, so any copy of that token — a shared
// browser, a proxy log, a captured Authorization header — kept full dashboard
// access after the operator believed they had signed out.
//
// Exactly one session dies: the one this request carried. Sibling sessions (the
// operator's phone, a second tab on another machine) are deliberately untouched
// — DeleteAll is the credential-change hammer, not what a sign-out button means.
// The master REST key is refused rather than accepted-and-ignored, so a caller is
// never told a credential was retired when nothing happened.
func (ws *WebServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	token := presentedSessionToken(r)
	if !strings.HasPrefix(token, service.SessionTokenPrefix) {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Not a dashboard session: the REST API key has no session to revoke")
		return
	}
	if ws.sessions != nil {
		ws.sessions.Delete(token)
	}
	ws.clearDocumentSessionCookie(w, r)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (ws *WebServer) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Read-only, so GET and HEAD and nothing else. It answered every verb before, including the
	// POST a cross-site form can send — the session gate rejects that first, but an endpoint
	// that agrees to a verb it has no meaning for is one more thing the gate has to be right about.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	username, _, _ := ws.settings.AdminCredentials()
	if username == "" {
		username = "admin"
	}
	// The password itself is a hash by this point and cannot be inspected, so the
	// nag comes from the flag recorded when it was hashed.
	needsAttention := ws.adminPasswordNeedsAttention()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"username":            username,
		"password_weak":       needsAttention,
		"is_default_password": needsAttention,
	})
}

// handleConfigServer changes the admin credentials.
//
// Three rules that the previous version did not follow: the current password has
// to be supplied before either credential moves, so a hijacked session or a
// cross-site request cannot silently take the account over; the new password is
// held to the same strength policy the installer applies, and the reason for a
// rejection is returned so the operator can act on it; and a request that
// changes nothing does not mint a session, which used to hand out a fresh token
// to anyone who could reach the endpoint with an empty body.
func (ws *WebServer) handleConfigServer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		AdminUsername   string `json:"admin_username"`
		AdminPassword   string `json:"admin_password"`
		CurrentPassword string `json:"current_password"`
		// Code is the second factor, required when 2FA is enabled: a hijacked
		// session plus a stolen password must still not be enough to rotate the
		// credential the session lives on.
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	// Second factor, checked before the re-auth KDF so a wrong code costs the
	// attacker nothing but the request itself.
	if !ws.totpGate(w, req.Code) {
		return
	}

	// The credentials are read once, up front. This handler used to hold a write
	// lock across its whole body — including the deliberately slow re-auth KDF —
	// which meant every dashboard login stalled behind a password change. The lock
	// now lives inside UpdateAndPersist and covers only the apply-and-store step,
	// which is the part that has to be atomic.
	currentUser, currentVerifier, _ := ws.settings.AdminCredentials()
	if currentUser == "" {
		currentUser = "admin"
	}

	wantUser := req.AdminUsername != "" && req.AdminUsername != currentUser
	wantPass := req.AdminPassword != ""
	if !wantUser && !wantPass {
		// Nothing to do. Say so plainly instead of issuing a token.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":  true,
			"changed":  false,
			"username": currentUser,
		})
		return
	}

	// Re-authenticate before touching anything.
	ws.kdfGate <- struct{}{}
	reauth := crypto.VerifyPassword(currentVerifier, req.CurrentPassword)
	<-ws.kdfGate
	if !reauth {
		clientIP := netutil.ClientIP(r)
		log.Printf("[Web] Rejected credential change from %s: current password did not match", clientIP)
		httpx.WriteJSONError(w, http.StatusForbidden, "Current password is incorrect")
		return
	}

	newUser := currentUser
	if wantUser {
		if len(req.AdminUsername) > 64 || strings.TrimSpace(req.AdminUsername) != req.AdminUsername {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Username must be at most 64 characters with no leading or trailing spaces")
			return
		}
		newUser = req.AdminUsername
	}

	var hashed string
	if wantPass {
		// Validate against the username that will be in force, so a rename plus a
		// password equal to the new name is caught in the same request.
		if err := crypto.ValidatePasswordStrength(newUser, req.AdminPassword); err != nil {
			// The policy's own reason goes back verbatim: "too short" and "must not
			// contain the username" call for different second attempts, and a generic
			// rejection makes the operator guess which one they hit.
			httpx.WriteJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		var herr error
		hashed, herr = crypto.HashPassword(req.AdminPassword)
		if herr != nil {
			log.Printf("[Web] Could not hash the new admin password: %v", herr)
			httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not store the new password")
			return
		}
	}

	// Everything validated. UpdateAndPersist applies and stores under one lock and
	// restores every field if the write fails, so the running process and the
	// database cannot disagree about the password.
	if err := ws.settings.UpdateAndPersist(
		func(m *database.MutableSettings) {
			m.AdminUsername = newUser
			if wantPass {
				m.AdminPassword = hashed
				// The new password passed the current policy, so the nag is satisfied.
				m.AdminPasswordWeak = false
			}
		},
		func(s *database.ServerSettings) error { return ws.db.SetSetting("server", s) },
	); err != nil {
		log.Printf("[Web] Could not persist the admin credentials: %v", err)
		httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not save settings")
		return
	}

	resp := map[string]any{
		"success":  true,
		"changed":  true,
		"username": newUser,
	}

	if wantPass {
		// A password change invalidates every session, including the caller's, so
		// a stolen token stops working. The caller gets one replacement.
		if ws.sessions != nil {
			ws.sessions.DeleteAll()
			resp["token"] = ws.sessions.Create()
		}
		log.Printf("[Web] Admin password changed; all sessions invalidated")
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func (ws *WebServer) handleRegenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		key := ws.settings.GetAPIKey()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"api_key": key,
			"data": map[string]string{
				"api_key": key,
			},
		})
		return
	case http.MethodPost:
		// Fall through to rotation. The second factor is enforced below the
		// body decode, so the gate can read the code the rotation request
		// carries.
	default:
		// Anything else used to rotate the key, so a HEAD from a link-preview
		// fetcher or a stray retry silently invalidated every integration. HEAD is
		// refused here rather than served, which is the one place in this codebase
		// that is true: the body a HEAD would not receive is the key itself, and
		// the verb reaches this endpoint only by accident.
		httpx.WriteMethodNotAllowed(w, "GET, POST")
		return
	}

	// The second factor gates the rotation when 2FA is on. GET (the read above)
	// is not gated: showing the key to an authenticated operator is its
	// documented purpose, and the panel cannot rotate what it cannot read.
	//
	// The current password is asked for unconditionally (v2.2.0 remediation):
	// rotation IS a credential change, and with 2FA off a hijacked session
	// used to be able to rotate the master key with nothing but the session.
	//
	// v2.1.0 B-03 remediation: the code is read from the JSON BODY — the same
	// place /api/config/server reads it from — with the query string kept as a
	// fallback. The previous query-only form made rotation impossible from the
	// dashboard (the panel posts a JSON body and had nowhere to put a code),
	// so an operator with 2FA on had to disable 2FA to rotate a leaked key.
	var payload struct {
		CurrentPassword string `json:"current_password"`
		Code            string `json:"code"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&payload)
	}
	if !ws.reauthCurrentPassword(payload.CurrentPassword) {
		clientIP := netutil.ClientIP(r)
		log.Printf("[Web] Rejected API key rotation from %s: current password did not match", clientIP)
		httpx.WriteJSONError(w, http.StatusForbidden, "Current password is incorrect")
		return
	}
	code := r.URL.Query().Get("code")
	if payload.Code != "" {
		code = payload.Code
	}
	if !ws.totpGate(w, code) {
		return
	}

	newKey := crypto.GenerateAPIKey()

	// Without the rollback inside UpdateAndPersist the running process would honour
	// a key that is not in the database, so the operator's integrations would work
	// until the next restart and then all fail at once.
	if err := ws.settings.UpdateAndPersist(
		func(m *database.MutableSettings) { m.APIKey = newKey },
		func(s *database.ServerSettings) error { return ws.db.SetSetting("server", s) },
	); err != nil {
		log.Printf("[Web] Could not persist the regenerated API key: %v", err)
		httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not save the new API key")
		return
	}
	log.Printf("[Web] REST API key regenerated")

	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"api_key": newKey,
		"data": map[string]string{
			"api_key": newKey,
		},
	})
}

// handleRegenerateAdminPath swaps the hidden admin namespace for a freshly
// generated one, on the request of an already-authenticated operator.
//
// The regeneration is a destructive act dressed as a settings change: every
// bookmark, dashboard tab, SSE stream, REST integration and reverse-proxy rule
// that names the old path stops working the moment this returns, because
// BuildHandler's router reads the path from the settings on every request. That
// immediacy is the point — the plan's transition behaviour is "old path dies at
// once", which is what makes a leaked path revocable — but it must never happen
// by accident, so the body has to carry an explicit confirmation flag and
// anything else is refused with an explanation rather than a bare 400.
//
// Every session is deleted along with the path. The operator who regenerated it
// holds a token minted while the old namespace was live, and the whole point of
// the workflow is that the old coordinates can no longer be trusted; re-login at
// the new URL is one form and no data was lost.
func (ws *WebServer) handleRegenerateAdminPath(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Confirm {
		httpx.WriteJSONError(w, http.StatusBadRequest,
			`Regenerating the admin path requires {"confirm":true} — every bookmark, integration and session under the old path stops working immediately`)
		return
	}

	newPath := GenerateAdminPath()

	// UpdateAndPersist rolls the field back if the database write fails, so the
	// running router and the stored record cannot end up naming two different
	// namespaces.
	if err := ws.settings.UpdateAndPersist(
		func(m *database.MutableSettings) { m.AdminPath = newPath },
		func(s *database.ServerSettings) error { return ws.db.SetSetting("server", s) },
	); err != nil {
		log.Printf("[Web] Could not persist the regenerated admin path: %v", err)
		httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not save the new admin path")
		return
	}

	if ws.sessions != nil {
		ws.sessions.DeleteAll()
	}
	log.Printf("[Web] Admin path regenerated; all sessions invalidated")

	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":    true,
		"admin_path": newPath,
		"data": map[string]string{
			"admin_path": newPath,
		},
	})
}

// handleSubscriptionSettings reads and writes the subscriber-surface record
// (v2.1 Phase 4). GET returns the snapshot; POST validates, persists atomically,
// and reports exactly what happened — including the restart question this build
// never has to ask, because the subscription origin is rendered per request
// rather than bound at startup.
//
// The certificate rule is checked at save time, not at restart time: a
// subscription domain that differs from the panel's must already carry a
// certificate naming it, so an operator cannot hand out links to an origin the
// daemon cannot serve.
func (ws *WebServer) handleSubscriptionSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		snap := ws.subSettings.Snapshot()
		_ = json.NewEncoder(w).Encode(snap)
		return
	case http.MethodPost:
		// Fall through to the save path.
	default:
		httpx.WriteMethodNotAllowed(w, "GET, POST")
		return
	}

	if ws.subSettings == nil {
		httpx.WriteJSONError(w, http.StatusInternalServerError, "subscription settings are not initialised")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in SubscriptionSettingsInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// ThemeCSS is bounded here already, ahead of Phase 7's full sanitiser: a
	// multi-megabyte "stylesheet" is a memory lever whether or not it is
	// malicious, and the limit is cheap to enforce at the door.
	const maxThemeCSS = 64 * 1024
	if len(in.ThemeCSS) > maxThemeCSS {
		httpx.WriteJSONError(w, http.StatusBadRequest, "the custom CSS exceeds the 64 KiB limit")
		return
	}

	normalized, problem := ws.sanitizeSubscriptionSnapshot(in)
	if problem != "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, problem)
		return
	}

	// Validate the certificate relationship against the NORMALISED values
	// before anything persists. The probe borrows the live records' pointers —
	// it is read-only and lives for this request, so there is nothing to
	// serialise and nothing to race: no goroutine outside this handler can
	// reach it.
	probe := &database.SubscriptionSettings{
		Enabled:             normalized.Enabled,
		Domain:              normalized.Domain,
		Port:                normalized.Port,
		URIPath:             normalized.URIPath,
		Title:               normalized.Title,
		ThemeCSS:            normalized.ThemeCSS,
		CertPath:            normalized.CertPath,
		KeyPath:             normalized.KeyPath,
		UsePanelCertificate: normalized.UsePanelCertificate,
	}
	saved := &WebServer{settings: ws.settings, tlsSettings: ws.tlsSettings, subSettings: probe}
	if problem := saved.validateSubscriptionCertificate(); problem != "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, problem)
		return
	}

	if err := ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled:             normalized.Enabled,
		Domain:              normalized.Domain,
		Port:                normalized.Port,
		URIPath:             normalized.URIPath,
		Title:               normalized.Title,
		ThemeCSS:            normalized.ThemeCSS,
		CertPath:            normalized.CertPath,
		KeyPath:             normalized.KeyPath,
		UsePanelCertificate: normalized.UsePanelCertificate,
		// The sanitiser derived this from the port the operator submitted —
		// dropping it here would silently unmark every deliberate portal
		// port, and the next panel-port change would copy-follow it.
		PortExplicit: normalized.PortExplicit,
	}, func(s *database.SubscriptionSettings) error { return ws.db.SetSetting("subscription", s) }); err != nil {
		log.Printf("[Web] Could not persist subscription settings: %v", err)
		httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not save the subscription settings")
		return
	}

	// Rebind the dedicated subscriber listener to match what was just saved.
	// Without this the port field only affected the text of future links, and an
	// operator who changed it got a URL nothing answered on until the next
	// restart — which is precisely the "this card does nothing" report.
	//
	// A bind failure does not roll the save back: the record is persisted and the
	// portal routes remain reachable on the panel's own port, so the honest
	// answer is to report the conflict rather than to pretend the change did not
	// happen. listener_error carries the reason so the card can show it.
	listenerErr := ws.bindSubscriberListener(context.Background(), false)

	log.Printf("[Web] Subscription settings saved (domain=%q use_panel_cert=%v enabled=%v port=%d)",
		normalized.Domain, normalized.UsePanelCertificate, normalized.Enabled, normalized.Port)

	resp := map[string]any{
		"success": true,
		// restart_required is stated rather than implied: the whole record —
		// including the subscriber listener — now applies live, and the field
		// stays so a future dedicated-listener mode can flip it without changing
		// the response contract.
		"restart_required": false,
		"subscription":     ws.subSettings.Snapshot(),
		// The recomputed origin, because the saved record changes it: the client
		// cards build Reg Link and Bot Card URLs from the origin the config
		// endpoint carries, and a save that left the dashboard on the old port
		// handed out links nothing answered on — the exact report this endpoint
		// exists to prevent.
		"subscription_origin": ws.subscriptionOrigin(),
	}
	if listenerErr != nil {
		resp["listener_error"] = listenerErr.Error()
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAuthUnlock lifts login lockouts on an authenticated operator's word.
// POST /<admin-path>/api/auth/unlock, body {"ip":"203.0.113.9"} (optional —
// empty clears every tracked address). Behind requireAuth and, when 2FA is
// on, behind totpGate: the endpoint exists precisely to undo a security
// control, so it must not be cheaper to reach than the control itself. This
// is what the TUI's "unlock" entry calls, which is the only way to reach the
// tracker's in-memory state without restarting the daemon.
func (ws *WebServer) handleAuthUnlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		Code string `json:"code"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "the request body could not be read as JSON")
		return
	}
	// Second factor first: a stolen dashboard session must not be able to
	// unlock brute-force attempts against itself.
	if !ws.totpGate(w, req.Code) {
		return
	}

	ip := strings.TrimSpace(req.IP)
	if ip != "" {
		if cleared := ws.loginLimiter.Reset(ip); cleared {
			log.Printf("[Web] Login lockout cleared for %s by the operator", ip)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "cleared": 1, "ip": ip})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "cleared": 0, "ip": ip})
		}
		return
	}
	cleared := ws.loginLimiter.ResetAll()
	log.Printf("[Web] Login lockouts cleared for %d address(es) by the operator", cleared)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "cleared": cleared})
}
