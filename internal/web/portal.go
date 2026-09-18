// Subscriber portal: the two public, token-authenticated routes a reseller's
// customer actually visits (/sub/<token>, /ip/<token>) plus the JSON endpoint the
// page's sync button calls (/api/sub/<token>).
//
// The token in the path is the credential. Nothing here is behind requireAuth,
// so every value that reaches the page is treated as untrusted.
package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"hyperdns/internal/database"
	"hyperdns/internal/httpx"
	"hyperdns/internal/netutil"
	"hyperdns/internal/service"
	"hyperdns/internal/version"
)

// handleSubDataAPI serves the subscriber portal's read-only JSON, keyed by the
// token in the path (v2.1.0 Phase B / Mantis C-03: this endpoint no longer
// registers anything — the write moved to the secret-gated POST /ip/<token>).
// Unauthenticated by design: the token is the portal's read credential, and
// everything it returns is display data.
func (ws *WebServer) handleSubDataAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/sub/")
	token = strings.TrimSpace(strings.TrimSuffix(token, "/"))
	token = strings.TrimSuffix(token, "/sync")

	client, err := ws.clients.LookupByToken(token)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"error":"Invalid or expired subscription token"}`))
		return
	}

	// The portal page stays read-only even for an expired, suspended or
	// quota-drained account; the registration API is where the gates bite.
	// ViewClient folds the pending traffic ledger in, so the quota figures the
	// page renders are the ones the resolver actually enforces.
	clientIP := netutil.ClientIP(r)

	serverDNS := ws.settings.GetPublicIP()
	if serverDNS == "" || serverDNS == "127.0.0.1" || serverDNS == "0.0.0.0" {
		// v2.1.0 B-16 remediation: a bare Host (no port — the default on port
		// 80) is just as trustworthy as host:port here; both are display-only
		// values the HTML handler already accepts. SplitHostPort failed on the
		// bare form and left server_dns at 127.0.0.1 while the HTML page of the
		// same portal showed the right address.
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		if host != "" && host != "localhost" && host != "127.0.0.1" && host != "0.0.0.0" {
			serverDNS = host
		}
	}

	// The encrypted transports are addressed by name, not by address; see the
	// ServerHost comment on portalData. A JSON consumer of this endpoint needs the
	// same distinction the HTML page makes, or it builds a DoT string from an IP
	// that Android will not accept.
	serverHost := serverDNS
	if ws.tlsSettings != nil {
		if d := ws.tlsSettings.GetDomain(); d != "" {
			serverHost = d
		}
	}

	// RegisterIP hands back the record as it is stored, so its counter is only as
	// fresh as the last flush — up to a flush interval behind. Quota enforcement
	// compares against the live total, so reporting the stored one let a subscriber
	// whose traffic had already been cut off read a page that still showed quota
	// left. ViewClient folds the pending bytes in and answers the two questions the
	// page would otherwise have to answer for itself — am I over my limit, and when
	// does the allowance come back — using the daemon's own rule rather than a second
	// copy of it in JavaScript.
	view := ws.clients.ViewClient(client)

	// The view embeds the whole stored record, and two of its fields are not
	// display data. register_secret is the WRITE credential: this endpoint is
	// unauthenticated and reached by anyone holding the portal link, so serving
	// the secret here would collapse the out-of-band separation the whole Phase B
	// design rests on (Mantis C-03) — a leaked link alone would again be enough
	// to move the binding. The note is the operator's private comment about the
	// customer, never shown on the portal either.
	view.RegisterSecret = ""
	view.Note = ""

	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"client":      &view,
		"detected_ip": clientIP,
		"server_dns":  serverDNS,
		// server_host is the DoT/DoH name; server_dns stays the plain-DNS address so
		// existing consumers keep working.
		"server_host":        serverHost,
		"has_domain":         serverHost != serverDNS,
		"traffic_used_bytes": view.TrafficUsedBytes,
		"traffic_limit_gb":   view.TrafficLimitGB,
		"expires_at":         view.ExpiresAt,

		// Flat copies of the computed figures, so a client of this endpoint does not
		// have to reach into the nested object for them. Absent, not zero, when the
		// account has no cycle.
		"next_traffic_reset": view.NextTrafficReset,
		"quota_exceeded":     view.QuotaExceeded,
	})
}

// handleSubscriptionPage renders the subscriber portal at GET /sub/<token>.
//
// Phase B (Mantis C-01..C-03): this route no longer writes anything. Opening a
// portal link used to re-bind the subscription's single allowed address to
// whoever fetched it — the write rode on a GET that a chat preview, a prefetch
// or anyone holding the pasted link could fire. The page is now a pure overview
// (identity, live address detection, quota, expiry, endpoints and guides), and
// the one write left in the subscriber's world is the deliberate, secret-gated
// POST to /ip/<token> below.
func (ws *WebServer) handleSubscriptionPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	token = strings.TrimSpace(strings.TrimSuffix(token, "/"))

	clientIP := netutil.ClientIP(r)
	client, err := ws.clients.LookupByToken(token)
	if err != nil {
		status := portalStatusInvalid
		if errors.Is(err, database.ErrClientExpired) {
			status = portalStatusExpired
		}
		ws.renderIPResultPage(w, r, status, clientIP, nil, "")
		return
	}

	serverDNS := ws.serverDNSForDisplay(r)
	// The page is an overview: the status line says so, and the register card
	// below is where a binding moves.
	ws.renderIPResultPage(w, r, portalStatusOverview, clientIP, client, serverDNS)
}

// serverDNSForDisplay resolves the address the portal advertises as the plain
// DNS server. Host-derived values stay display-only: persisting one would let
// any unauthenticated caller rewrite the server's advertised address.
func (ws *WebServer) serverDNSForDisplay(r *http.Request) string {
	serverDNS := ws.settings.GetPublicIP()
	reqHost := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		reqHost = h
	}
	if reqHost != "" && reqHost != "127.0.0.1" && reqHost != "localhost" && reqHost != "0.0.0.0" {
		if serverDNS == "" || serverDNS == "127.0.0.1" || serverDNS == "0.0.0.0" || serverDNS == "example.com" {
			serverDNS = reqHost
		}
	}
	return serverDNS
}

// handleRegisterIPAPI is the subscriber's one write: POST /ip/<token> with the
// out-of-band register secret binds a new address to the subscription.
//
// Body (JSON): {"secret": "...", "ip": "203.0.113.9" (optional)}. With no "ip"
// the caller's own address is bound — the 1-click flow the portal page drives;
// with one, an explicit address is bound for subscribers whose gaming device
// sits behind a different NAT than the device holding the page.
//
// The gates run in this order, deliberately: token+secret first (a caller that
// fails here gets the same answer whether the token or the secret was wrong),
// then suspension, expiry, quota — each a distinct, actionable failure — then
// address validation, then the bind itself.
//
// Duplicate addresses across two DIFFERENT subscriptions are refused with 409
// and logged, never de-activating either account: shared CGNAT addresses are
// ordinary on Iranian mobile networks, and auto-disabling a paying account over
// one would be the cure killing the patient.
func (ws *WebServer) handleRegisterIPAPI(w http.ResponseWriter, r *http.Request) {
	// GET/HEAD answers with the explainer page instead of a bare 405: the old
	// GET on this address auto-registered the caller, so old bookmarks and
	// chat unfurls land here and deserve to be told what changed and where
	// their portal now lives — in both languages, with no script.
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		ws.handleIPPage(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/ip/")
	token = strings.TrimSpace(strings.TrimSuffix(token, "/"))

	var req struct {
		Secret string `json:"secret"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "the request body could not be read as JSON")
		return
	}

	// Forwarding headers are only believed from a trusted local/private hop:
	// this endpoint binds whatever address it sees to a subscription, so an
	// arbitrary caller must not be able to nominate one via X-Forwarded-For.
	clientIP := netutil.ClientIP(r)

	bindIP := req.IP
	if strings.TrimSpace(bindIP) == "" {
		bindIP = clientIP
	}

	client, alreadyPresent, err := ws.clients.RegisterIP(token, req.Secret, bindIP)
	if err != nil {
		// Each failure carries a machine-readable `reason` beside the human text.
		// The portal is bilingual and cannot ask the server which language the
		// reader chose, so it renders its own translated line from the reason
		// code. Without this the page showed one generic "wrong secret" for
		// every cause — a subscriber whose address was already bound to another
		// subscription, or whose plan had lapsed, was told their secret was
		// wrong and had no idea what to fix.
		status, reason, msg := http.StatusBadRequest, "invalid", err.Error()
		switch {
		case errors.Is(err, database.ErrClientNotFound):
			// Token unknown OR secret wrong — one answer for both (C-03).
			status, reason = http.StatusUnauthorized, "secret"
			msg = "Invalid subscription token or registration secret"
		case errors.Is(err, database.ErrClientSuspended):
			status, reason = http.StatusForbidden, "suspended"
			msg = "This subscription has been suspended. Contact your provider."
		case errors.Is(err, database.ErrClientExpired):
			status, reason = http.StatusForbidden, "expired"
			msg = "This subscription has expired."
		case errors.Is(err, database.ErrQuotaExceeded):
			status, reason = http.StatusForbidden, "quota"
			msg = "This subscription's traffic allowance is exhausted."
		case errors.Is(err, service.ErrDuplicateIPConflict):
			log.Printf("[Portal] IP %s is already bound to another subscription; bind request refused", bindIP)
			status, reason = http.StatusConflict, "conflict"
			msg = "This IP address is already registered to another subscription. Contact your provider."
		}
		if status == http.StatusBadRequest {
			// Bad address text and genuine failures share the 400: the caller
			// can retry either way, and the reason travels in the body.
			reason = "invalid"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "reason": reason})
		return
	}

	view := ws.clients.ViewClient(client)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":            true,
		"already_bound":      alreadyPresent,
		"bound_ip":           bindIP,
		"detected_ip":        clientIP,
		"server_dns":         ws.serverDNSForDisplay(r),
		"client":             &view,
		"traffic_used_bytes": view.TrafficUsedBytes,
		"traffic_limit_gb":   view.TrafficLimitGB,
		"quota_exceeded":     view.QuotaExceeded,
	})
}

// handleIPPage explains the API to a subscriber (or an old bookmark) that
// opened /ip/<token> with GET. The verb that used to auto-register is gone on
// purpose (C-03); this page says what the address is for and where the portal
// lives, in both languages, with no script.
func (ws *WebServer) handleIPPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	const page = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>HyperDNS — IP registration API</title>
  <link rel="stylesheet" href="/css/portal.css">
</head>
<body class="portal center">
  <div class="wrap wrap-narrow">
    <div class="card error-card">
      <div class="error-mark" aria-hidden="true"><i class="ico ico-info"></i></div>
      <div>
        <h1 class="title">IP registration API</h1>
        <p class="subtitle mono">این آدرس یک API است / This address is an API endpoint</p>
      </div>
      <div class="error-box">
        <div class="label">EN</div>
        <div class="value-lg mono" style="font-size:.9rem">POST your new address here with your registration secret.<br>Open your <b>/sub/…</b> portal link to manage your IP.</div>
      </div>
      <div class="error-box">
        <div class="label">FA</div>
        <div class="value-lg mono" style="font-size:.9rem">این آدرس برای ثبت برنامه‌ای آی‌پی است و با «رمز ثبت» کار می‌کند.<br>برای مدیریت آی‌پی، لینک پورتال <b>/sub/…</b> خود را باز کنید.</div>
      </div>
      <div class="footer">HyperDNS Secure Portal</div>
    </div>
  </div>
</body>
</html>`
	_, _ = w.Write([]byte(page))
}

// trafficCycleLabel names a quota cycle in the language the page is being rendered in.
// The second result is false for an account with no cycle and for a stored value this
// build does not recognise — an older record written by a newer binary, say — so an
// unknown name renders no row rather than a row promising a renewal on a date nothing
// will honour.
func trafficCycleLabel(cycle string, t portalText) (string, bool) {
	switch cycle {
	case service.TrafficCycleDaily:
		return t.CycleDaily, true
	case service.TrafficCycleWeekly:
		return t.CycleWeekly, true
	case service.TrafficCycleMonthly:
		return t.CycleMonthly, true
	}
	return "", false
}

// safeHostDisplay keeps only the characters a hostname or IP literal can legally
// contain. html/template escapes this value correctly wherever it lands, but the
// page also *shows* it as an address the subscriber is meant to type into a
// console or a router, and serverDNS can come from r.Host — which Go's Host
// validation lets through with ' ( ) and , intact. Filtering keeps the displayed
// address readable instead of turning junk into escaped junk.
func safeHostDisplay(s string) string {
	if len(s) > 253 {
		s = s[:253]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '.' || c == '-' || c == ':' || c == '[' || c == ']':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// portalData is everything the subscriber portal renders.
//
// It exists so the page is filled in by html/template instead of by string
// replacement. The previous renderer pasted values into raw HTML and had to
// remember, at each of ~30 uses, which context it was pasting into: HTML text, an
// attribute, a JS string literal inside a click-handler attribute, a CSS length. It
// escaped four of them by hand and left the rest — the UUID inside the copy
// handler's argument and the token inside its fetch URL among them — relying on
// those values only ever being generated server-side. html/template picks the
// escaper from the surrounding markup, so that assumption stops being load-bearing.
//
// The JS-string context is gone entirely now: nothing on the page is a script
// argument, because every value a control acts on is a data- attribute and the
// handlers live in /js/portal.js.
type portalData struct {
	// The negotiated presentation. Lang and Dir land in <html lang> and <html dir>;
	// Theme lands in data-theme, which is what makes portal.css's light palette
	// reachable at all. IsFa and IsLight exist because the two toggle links have to be
	// written out as literal branches: a class attribute on this page may not contain a
	// template action (portal_assets_test.go reads the literal attribute), so the
	// "switch to English" and "switch to light" markup cannot be built from a value.
	Lang    string
	Dir     string
	Theme   string
	IsFa    bool
	IsLight bool

	// T is the whole bundle. Every word on the page comes through it, which is what
	// keeps the two languages from drifting: a field the template reads must exist in
	// both bundles or the package will not compile.
	T portalText

	// StatusLine is the sentence under the topbar; StatusWarn picks the caveat icon
	// over the success one, again as two literal branches.
	StatusLine string
	StatusWarn bool

	// ErrTitle and ErrNote are the error card's two lines.
	ErrTitle string
	ErrNote  string

	ClientIP  string
	ServerDNS string
	// Title is the operator's brand line from the subscription settings
	// ("HyperDNS" when they never chose one). It replaces the literal product
	// name in the page title so a reseller's customers see the reseller's name.
	Title string
	// Version is the running build, for the footer. It is a field rather than a
	// literal in the template: the footer carried "v2.0.0-beta [HyperRAIN]" as
	// text through two releases after that version shipped, so every subscriber
	// of a v2.1 install was told the wrong version when they reported a problem.
	Version string
	// DoHPort and DoTPort are the operator-configured transport ports. The
	// template used to hardcode 8443/853 (v2.1.0 B-17 remediation), handing
	// every subscriber of a port-moved install a copy button for a dead
	// endpoint.
	DoHPort int
	DoTPort int
	// ThemeCSS is the operator's custom stylesheet, already sanitised and
	// wrapped in its own <style> element (or empty). template.CSS marks it as
	// raw text for html/template — the sanitiser above it is the primary
	// defence; this just stops double-escaping.
	ThemeCSS template.CSS
	// ServerHost is what DoT and DoH have to be addressed by: the configured
	// domain when there is one, falling back to ServerDNS when there is not.
	//
	// These cannot share one field. Plain DNS on port 53 takes an IP and only an
	// IP — a hostname in a router's DNS box or a PS5's network settings resolves
	// nowhere, since resolving it is what the address is for. DoT is the mirror
	// image: Android's Private DNS field accepts a hostname only and rejects an
	// address outright, and the TLS handshake needs a name to match against the
	// certificate anyway. Rendering ServerDNS in both places, which is what this
	// page did, handed every Android user an IP that their phone silently refuses.
	ServerHost string
	// HasDomain reports whether ServerHost is a real hostname rather than a
	// fallback IP, so the Private DNS instructions can say so instead of showing
	// a value that cannot work.
	HasDomain bool

	Name  string
	ID    string
	UUID  string
	Token string

	// RegisterAPIPath is the endpoint the register card posts to, built with
	// the token already in it. The secret itself is typed by the subscriber —
	// the page never carries it, so the portal link stays read-only material.
	RegisterAPIPath string

	TrafficDisplay   string
	TrafficRemaining string
	// TrafficPercent is a plain decimal because it lands in a CSS length.
	TrafficPercent string

	ExpiresAt string
	Days      int
	Hours     int
	Mins      int
	// ExpiresUnix is the same instant as a unix second, handed to the page so the
	// countdown can actually count. Days/Hours/Mins are the first paint — correct
	// before any script runs — and this is what keeps them correct afterwards.
	// Zero for a lifetime plan, which is also what tells portal.js there is nothing
	// to tick.
	ExpiresUnix int64
	// Lifetime selects the ∞ cell over the three countdown boxes. It used to render
	// as "9999 روز", which reads as a bug to the person paying for the plan.
	Lifetime bool

	// Policies holds display labels. Empty means the subscriber inherits every
	// rule the server has enabled, which the page says in words instead.
	Policies []string

	// The recurring-quota figures, taken from the daemon's own view of the record
	// rather than worked out here. A subscriber whose plan renews on the 31st needs
	// to be told the same date the resolver will actually reset on, and February is
	// where a second implementation of that arithmetic stops agreeing.
	//
	// HasCycle selects the row: an account with no cycle gets no promise of a reset,
	// because for it there is none — a spent limit stays spent until an operator
	// clears it.
	QuotaExceeded bool
	HasCycle      bool
	CycleLabel    string
	NextResetAt   string
}

// The portal's two pages are parsed once, at startup. A parse failure is a typo
// in a constant in this file — a programming error, not a runtime condition — so
// it should stop the binary rather than surface on a subscriber's first visit.
var (
	portalErrorTpl = template.Must(template.New("portal-error").Parse(portalErrorHTML))
	portalPageTpl  = template.Must(template.New("portal-page").Parse(portalPageHTML))
)

// renderPortal executes a portal template into a buffer before writing a byte of
// it. Executing straight into the ResponseWriter would commit 200 OK and half a
// page before a mid-template failure, leaving the subscriber looking at markup
// that stops inside a tag; buffering turns that into a clean 500 instead.
func renderPortal(w http.ResponseWriter, code int, tpl *template.Template, data portalData) {
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		log.Printf("[WEB] subscriber portal template %q failed: %v", tpl.Name(), err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

// wrapThemeCSS builds the <style> element the templates embed after the
// built-in stylesheet. An empty stylesheet produces an empty string, so a
// deployment with no branding emits no element at all. Callers pass CSS that
// has already been through SanitizeThemeCSS; the wrapper adds no trust.
func wrapThemeCSS(css string) template.CSS {
	if strings.TrimSpace(css) == "" {
		return ""
	}
	return template.CSS("<style>\n" + css + "\n</style>")
}

// renderIPResultPage writes either the subscriber portal or the error page.
//
// Language and theme are resolved here, before either template runs, because the error
// page carries no script at all and must not start carrying one — there is nothing on
// it to operate, and an inline script is exactly what the CSP does not have to be
// relaxed for today. A ?lang= or ?theme= in the URL both switches and remembers; a
// cookie carries it to the next visit; a first visit with neither falls back to
// Accept-Language for the language and to dark for the theme.
//
// Nothing here escapes by hand: every field of portalData is inserted by html/template,
// which picks the escaper from the surrounding markup. The one exception is ServerDNS,
// filtered by safeHostDisplay because the page shows it as an address to type into a
// console — see that function's comment.
func (ws *WebServer) renderIPResultPage(w http.ResponseWriter, r *http.Request, status portalStatus, clientIP string, client *database.Client, serverDNS string) {
	lang := negotiatePortalLang(w, r)
	theme := negotiatePortalTheme(w, r)
	t := portalBundle(lang)
	// The subtitle names the running build. It used to be a literal in the
	// template, so every release after v2.0.0-beta still told subscribers they
	// were on v2.0.0-beta; formatting it here keeps one source of truth.
	t.Subtitle = fmt.Sprintf(t.Subtitle, version.Display())

	// Two requests for the same URL now legitimately differ by cookie and by
	// Accept-Language. Saying so keeps a cache in front of this from serving one
	// subscriber's language to another — and the panel is routinely put behind one.
	w.Header().Add("Vary", "Cookie")
	w.Header().Add("Vary", "Accept-Language")

	data := portalData{
		Lang:      lang,
		Dir:       portalDir(lang),
		Theme:     theme,
		IsFa:      lang == portalLangFa,
		IsLight:   theme == portalThemeLight,
		T:         t,
		ClientIP:  clientIP,
		ServerDNS: safeHostDisplay(serverDNS),
		Title:     ws.subSettings.GetTitle(),
		Version:   version.Display(),
		DoHPort:   dohPortForDisplay(ws.dnsCfg),
		DoTPort:   dotPortForDisplay(ws.dnsCfg),
		// The operator's stylesheet lands after the built-in one, pre-sanitised:
		// <style>/<script> tags escaped, @import and external url() stripped, so
		// the page a subscriber loads cannot be turned into a data-exfiltration
		// surface by a reseller's "branding". Empty renders nothing.
		ThemeCSS: wrapThemeCSS(SanitizeThemeCSS(ws.subSettings.Snapshot().ThemeCSS)),
	}
	if data.ServerDNS == "" {
		data.ServerDNS = "127.0.0.1"
	}

	// Prefer the configured domain for the encrypted transports. GetDomain is the
	// name a certificate was actually issued for, so it is also the only name a
	// DoT client will accept during the handshake. The dedicated DoH/DoT domain
	// (v2.2.0) outranks the panel's: it is the name the 853/8443 listeners'
	// own certificate covers, which is the pair Android's Private DNS and the
	// DoH URL below actually handshake against.
	if ws.tlsSettings != nil {
		if d := safeHostDisplay(ws.tlsSettings.GetDoTDomain()); d != "" {
			data.ServerHost = d
			data.HasDomain = true
		} else if d := safeHostDisplay(ws.tlsSettings.GetDomain()); d != "" {
			data.ServerHost = d
			data.HasDomain = true
		}
	}
	if data.ServerHost == "" {
		data.ServerHost = data.ServerDNS
	}

	if !status.ok() || client == nil {
		data.ErrTitle, data.ErrNote = status.errText(t)
		renderPortal(w, status.httpStatus(), portalErrorTpl, data)
		return
	}
	data.StatusLine = status.line(t)
	data.StatusWarn = status.warn()

	data.Name = client.Name
	data.ID = client.ID
	data.UUID = client.UUID
	data.Token = client.Token
	data.RegisterAPIPath = "/ip/" + client.Token

	// The stored counter is only as fresh as the last flush. Quota enforcement uses
	// the live total, so showing the stored one meant a subscriber whose traffic had
	// already been cut off could read a page that still promised them quota. The
	// decorated copy also carries the daemon's own answer to "is this account over"
	// and "when does the allowance return", neither of which this page should be
	// working out for itself.
	view := ws.clients.ViewClient(client)

	usedMB := float64(view.TrafficUsedBytes) / (1024 * 1024)
	usedGB := usedMB / 1024
	limitGB := view.TrafficLimitGB
	data.QuotaExceeded = view.QuotaExceeded
	percent := 0.0
	data.TrafficDisplay = fmt.Sprintf("%.2f MB / Unlimited", usedMB)
	data.TrafficRemaining = t.Unlimited

	if limitGB > 0 {
		percent = (usedGB / limitGB) * 100.0
		if percent > 100.0 {
			// The bar is a CSS width; a subscriber over quota must not push it
			// past the track.
			percent = 100.0
		}
		remainingGB := limitGB - usedGB
		if remainingGB < 0 {
			remainingGB = 0
		}
		data.TrafficDisplay = fmt.Sprintf("%.2f GB / %.1f GB", usedGB, limitGB)
		data.TrafficRemaining = fmt.Sprintf("%.2f GB %s", remainingGB, t.WordRemaining)
	}
	data.TrafficPercent = fmt.Sprintf("%.1f", percent)

	// The renewal promise, and only when there is one to make. A limit with no cycle
	// gets no row at all: telling a subscriber their volume "returns" when nothing
	// will return it is the one thing worse than saying nothing.
	if label, ok := trafficCycleLabel(client.TrafficResetCycle, t); ok && limitGB > 0 && view.NextTrafficReset != nil {
		data.HasCycle = true
		data.CycleLabel = label
		data.NextResetAt = view.NextTrafficReset.Format("2006-01-02 15:04:05")
	}

	data.ExpiresAt = t.LifetimeLabel
	data.Lifetime = true
	if !client.ExpiresAt.IsZero() {
		data.ExpiresAt = client.ExpiresAt.Format("2006-01-02 15:04:05")
		data.ExpiresUnix = client.ExpiresAt.Unix()
		data.Lifetime = false
		if remaining := time.Until(client.ExpiresAt); remaining > 0 {
			data.Days = int(remaining.Hours() / 24)
			data.Hours = int(remaining.Hours()) % 24
			data.Mins = int(remaining.Minutes()) % 60
		}
	}

	// Display labels only: "enable_riot" reads as "RIOT" on the page. These used
	// to be escaped by hand here because they were pasted into markup; the
	// template does it now, and does it for the right context.
	for _, p := range client.CustomPolicies {
		label := strings.ToUpper(strings.ReplaceAll(strings.TrimPrefix(p, "enable_"), "_", " "))
		data.Policies = append(data.Policies, label)
	}

	renderPortal(w, status.httpStatus(), portalPageTpl, data)
}

// portalErrorHTML is shown for an unknown token or an expired subscription. It
// keeps the 200 status the previous renderer used: the page is the answer, and a
// 404 here would only make a reseller's customer think the link is broken rather
// than their plan finished.
//
// It carries no script at all — there is nothing on it to operate — and shares
// /css/portal.css with the page below. That is also why language and theme are
// resolved on the server: with no script here, a client-side preference would leave
// this page permanently in one language and one palette, and it is the page a
// subscriber whose plan just ended is most likely to be reading.
const portalErrorHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" dir="{{.Dir}}" data-theme="{{.Theme}}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark light">
  <meta name="robots" content="noindex, nofollow">
  <title>{{.T.ErrDocTitle}} — {{.Title}}</title>
  <link rel="stylesheet" href="/css/portal.css">
  {{.ThemeCSS}}
</head>
<body class="portal center">
  <div class="wrap wrap-narrow">
    <div class="card error-card">
      <div class="error-mark" aria-hidden="true"><i class="ico ico-x"></i></div>
      <div>
        <h1 class="title">{{.ErrTitle}}</h1>
        <p class="subtitle mono">{{.ErrNote}}</p>
      </div>
      <div class="error-box">
        <div class="label">{{.T.ErrIPLabel}}</div>
        <div class="value-lg value-bad mono">{{.ClientIP}}</div>
      </div>

      <!-- Both links are plain relative hrefs, so they work with no script and keep
           the token in the path. The handler writes a cookie when it sees the query,
           which is what carries the choice to the next visit and to the other page. -->
      <div class="tools">
        {{- if .IsFa}}
        <a class="btn" href="?lang=en" hreflang="en" title="{{.T.LangHint}}"><i class="ico ico-globe" aria-hidden="true"></i>English</a>
        {{- else}}
        <a class="btn" href="?lang=fa" hreflang="fa" title="{{.T.LangHint}}"><i class="ico ico-globe" aria-hidden="true"></i>فارسی</a>
        {{- end}}
        {{- if .IsLight}}
        <a class="btn" href="?theme=dark" title="{{.T.ThemeHint}}"><i class="ico ico-moon" aria-hidden="true"></i>{{.T.ThemeToDark}}</a>
        {{- else}}
        <a class="btn" href="?theme=light" title="{{.T.ThemeHint}}"><i class="ico ico-sun" aria-hidden="true"></i>{{.T.ThemeToLight}}</a>
        {{- end}}
      </div>

      <div class="footer">HyperDNS {{.Version}}</div>
    </div>
  </div>
</body>
</html>`

// portalPageHTML is the subscriber-facing page: identity, live IP, quota,
// countdown, the four DNS endpoints, and the per-device setup guides.
//
// Presentation lives in /css/portal.css and behaviour in /js/portal.js. Both used
// to be inline blocks inside this constant, layered on the 407 KB Tailwind Play-CDN
// JIT engine — so a reseller's customer, on a phone, on mobile data, on the page
// they are told to reopen every time their modem restarts, downloaded and ran
// 407 KB of JavaScript before this page had any styling at all. As external files
// they are 'self' (needing no CSP relaxation), ETagged and gzipped by static.go,
// and cached across visits instead of re-sent inside every page.
//
// Every value here is a field of portalData, and html/template picks the escaper
// from the surrounding markup — HTML text, an attribute, a CSS length. The
// JS-string context is gone: no value is a script argument any more, because each
// control carries what it acts on in a data- attribute.
const portalPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" dir="{{.Dir}}" data-theme="{{.Theme}}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark light">
  <!-- The URL of this page contains the subscription token; it is not for indexing. -->
  <meta name="robots" content="noindex, nofollow">
  <title>{{.T.DocTitle}} - {{.Name}} | {{.Title}}</title>
  <link rel="stylesheet" href="/css/portal.css">
  {{.ThemeCSS}}
</head>
<body class="portal">
  <div class="wrap">

    <div class="card topbar">
      <div class="brand">
        <div class="brand-logo" aria-hidden="true"><i class="ico ico-bolt"></i></div>
        <div class="brand-text">
          <div class="brand-row">
            <!-- The operator's brand line, not the generic bundle heading. Title
                 falls back to "HyperDNS" when unset (see GetTitle), so an install
                 that never touched the setting still renders a name — but one
                 that did now sees it on the page a subscriber actually opens,
                 not only in the browser tab. -->
            <h1 class="title">{{.Title}}</h1>
            <span class="pill pill-ok"><i class="ico ico-activity" aria-hidden="true"></i>{{.T.PillActive}}</span>
          </div>
          <p class="subtitle mono">{{.T.Subtitle}}</p>
        </div>
      </div>

      <!-- The two preference links are plain relative hrefs: they work with no script,
           they keep the token in the path, and the handler writes a cookie when it sees
           the query, which is what carries the choice to the next visit and to the
           error page. Only the sync button needs /js/portal.js. -->
      <div class="tools">
        {{- if .IsFa}}
        <a class="btn" href="?lang=en" hreflang="en" title="{{.T.LangHint}}"><i class="ico ico-globe" aria-hidden="true"></i>English</a>
        {{- else}}
        <a class="btn" href="?lang=fa" hreflang="fa" title="{{.T.LangHint}}"><i class="ico ico-globe" aria-hidden="true"></i>فارسی</a>
        {{- end}}
        {{- if .IsLight}}
        <a class="btn" href="?theme=dark" title="{{.T.ThemeHint}}"><i class="ico ico-moon" aria-hidden="true"></i>{{.T.ThemeToDark}}</a>
        {{- else}}
        <a class="btn" href="?theme=light" title="{{.T.ThemeHint}}"><i class="ico ico-sun" aria-hidden="true"></i>{{.T.ThemeToLight}}</a>
        {{- end}}
      </div>
    </div>

    <!-- What just happened, in one line. This is where a subscriber whose link was
         opened by a chat preview instead of by them is told the address was not
         registered and which button registers it. Two literal branches rather than one
         with a computed class: a class attribute here may not contain a template
         action, because portal_assets_test.go inventories the attribute as written. -->
    <div class="card">
      {{- if .StatusWarn}}
      <div class="hint"><i class="ico ico-warn" aria-hidden="true"></i>{{.StatusLine}}</div>
      {{- else}}
      <div class="hint"><i class="ico ico-check" aria-hidden="true"></i>{{.StatusLine}}</div>
      {{- end}}
    </div>


    <!-- The one write the portal still offers, and what protects it: the
         out-of-band registration secret. The page itself never carries it — the
         subscriber pastes what their provider handed them — so the link stays
         read-only material (Mantis C-03). The button posts to the secret-gated
         /ip/<token> API, and the toast + the detected-IP value update from its
         JSON. -->
    <div class="card" id="register-card">
      <div class="hd-title"><i class="ico ico-refresh" aria-hidden="true"></i>{{.T.CardRegister}}</div>
      <div class="label">{{.T.LabelSecret}}</div>
      <div class="reg-row">
        <input type="password" id="register-secret" class="reg-input" autocomplete="off"
               placeholder="{{.T.PlaceholderSecret}}" aria-label="{{.T.LabelSecret}}">
        <button type="button" class="btn btn-primary" id="register-btn" data-reg="{{.RegisterAPIPath}}"><i class="ico ico-refresh" aria-hidden="true"></i>{{.T.BtnRegister}}</button>
      </div>
      <div class="hint"><i class="ico ico-info" aria-hidden="true"></i>{{.T.HintSecret}}</div>
    </div>


    <div class="grid2">

      <div class="card">
        <div class="hd">
          <span class="hd-title">{{.T.CardIdentity}}</span>
          <span class="pill pill-info mono">ID: {{.ID}}</span>
        </div>
        <div>
          <div class="label">{{.T.LabelAccount}}</div>
          <div class="value-lg">{{.Name}}</div>
        </div>
        <div>
          <div class="label">{{.T.LabelUUID}}</div>
          <div class="copy-row">
            <span class="copy-row-val">{{.UUID}}</span>
            <button type="button" class="copy-btn" data-copy="{{.UUID}}" data-copied="{{.T.CopiedUUID}}">{{.T.BtnCopy}}</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="hd">
          <span class="hd-title">{{.T.CardIPStatus}}</span>
          <span class="pill pill-ok"><i class="ico ico-check" aria-hidden="true"></i>{{.T.PillBound}}</span>
        </div>
        <div>
          <div class="label">{{.T.LabelDetectedIP}}</div>
          <div class="value-lg value-ip mono" id="detected-ip">{{.ClientIP}}</div>
        </div>
        <div class="hint"><i class="ico ico-info" aria-hidden="true"></i>{{.T.HintModem}}</div>
      </div>

    </div>


    <div class="grid2">

      <div class="card">
        <div class="row">
          <span class="hd-title"><i class="ico ico-chart" aria-hidden="true"></i>{{.T.CardTraffic}}</span>
          <span class="figure mono" id="traffic-display">{{.TrafficDisplay}}</span>
        </div>

        <!-- The one server-rendered CSS value on the page. The exact spelling
             "width: N.N%", with the percent sign outside the action, is what
             html/template's CSS filter accepts; a value that carries its own '%'
             is rejected and the bar renders at zero width for every subscriber. -->
        <div class="meter">
          <div class="meter-fill" id="traffic-fill" style="width: {{.TrafficPercent}}%"></div>
        </div>

        <div class="split">
          <span>{{.T.LabelRemaining}}</span>
          <!-- data-word / data-unlimited hand the script the two fragments it needs to
               re-render this line after a sync. They are the same bundle fields Go used
               for the first paint, so pressing the button cannot change the wording —
               only the number. -->
          <span class="split-strong" id="traffic-remaining"
                data-word="{{.T.WordRemaining}}"
                data-unlimited="{{.T.Unlimited}}">{{.TrafficRemaining}}</span>
        </div>

        {{- if .HasCycle}}
        <!-- Only rendered for a plan that actually renews. The date is the daemon's
             own next boundary, not one recomputed here: a plan anchored on the 31st
             skips to the 28th in February and back to the 31st in March, and a
             second implementation of that is a second answer. -->
        <div class="split">
          <span>{{.T.LabelAutoRenew}} ({{.CycleLabel}}):</span>
          <span class="split-strong mono">{{.NextResetAt}}</span>
        </div>
        {{- end}}

        <!-- Both branches render the same element with the same id; only the hidden
             state differs, because /js/portal.js toggles it after a sync and cannot
             toggle what is not on the page. A class attribute must not be built from
             a template action — the class inventory in portal_assets_test.go reads
             the literal attribute — so this is written out twice rather than once
             with a conditional token. -->
        {{- if .QuotaExceeded}}
        <div class="row"><span class="pill pill-bad" id="quota-pill"><i class="ico ico-ban" aria-hidden="true"></i>{{.T.PillQuotaSpent}}</span></div>
        {{- else}}
        <div class="row"><span class="pill pill-bad is-gone" id="quota-pill"><i class="ico ico-ban" aria-hidden="true"></i>{{.T.PillQuotaSpent}}</span></div>
        {{- end}}
      </div>


      <div class="card">
        <div class="hd-title"><i class="ico ico-clock" aria-hidden="true"></i>{{.T.CardCountdown}}</div>

        {{- if .Lifetime}}
        <div class="count-inf"><i class="ico ico-infinity" aria-hidden="true"></i>{{.ExpiresAt}}</div>
        {{- else}}
        <!-- data-expires is a unix second. The three numbers below are the first
             paint — server-rendered, correct before any script runs — and the ids
             are what /js/portal.js rewrites every 30 seconds so they keep counting
             for a subscriber who leaves the page open. -->
        <div class="count3" data-expires="{{.ExpiresUnix}}">
          <div class="count-cell">
            <div class="count-num" id="cd-days">{{.Days}}</div>
            <div class="count-unit">{{.T.UnitDays}}</div>
          </div>
          <div class="count-cell">
            <div class="count-num" id="cd-hours">{{.Hours}}</div>
            <div class="count-unit">{{.T.UnitHours}}</div>
          </div>
          <div class="count-cell">
            <div class="count-num" id="cd-mins">{{.Mins}}</div>
            <div class="count-unit">{{.T.UnitMins}}</div>
          </div>
        </div>

        <div class="split">
          <span>{{.T.LabelEndDate}}</span>
          <span class="split-strong mono">{{.ExpiresAt}}</span>
        </div>
        {{- end}}
      </div>

    </div>


    <div class="card">
      <div class="hd-title"><i class="ico ico-gamepad" aria-hidden="true"></i>{{.T.CardPolicies}}</div>
      <div class="chips">
        {{- if .Policies}}
        {{- range .Policies}}
        <span class="chip"><i class="ico ico-gamepad" aria-hidden="true"></i>{{.}}</span>
        {{- end}}
        {{- else}}
        <span class="chip chip-all"><i class="ico ico-star" aria-hidden="true"></i>{{.T.PolicyAll}}</span>
        {{- end}}
      </div>
    </div>


    <div class="card">
      <div class="hd">
        <span class="hd-title"><i class="ico ico-globe" aria-hidden="true"></i>{{.T.CardEndpoints}}</span>
        <span class="pill pill-mute">{{.T.HintTapCopy}}</span>
      </div>

      <!-- Each endpoint is a real button rather than a div with a click handler:
           that is what makes it reachable by keyboard and announced as a control,
           and there is no role/tabindex pair to keep in sync. What gets copied is
           data-copy, read by the delegated listener in /js/portal.js. -->
      <div class="endpoints">
        <button type="button" class="copy-card" data-copy="{{.ServerDNS}}" data-copied="{{.T.CopiedPrimary}}">
          <span class="copy-card-top"><span>Primary DNS (IPv4):</span><span class="copy-card-tag"><i class="ico ico-clipboard" aria-hidden="true"></i>{{.T.BtnCopy}}</span></span>
          <span class="copy-card-val">{{.ServerDNS}}</span>
        </button>

        <button type="button" class="copy-card" data-copy="1.1.1.1" data-copied="{{.T.CopiedSecondary}}">
          <span class="copy-card-top"><span>Secondary DNS (IPv4):</span><span class="copy-card-tag"><i class="ico ico-clipboard" aria-hidden="true"></i>{{.T.BtnCopy}}</span></span>
          <span class="copy-card-val">1.1.1.1</span>
        </button>

        <button type="button" class="copy-card" data-copy="https://{{.ServerHost}}:{{.DoHPort}}/dns-query" data-copied="{{.T.CopiedDoH}}">
          <span class="copy-card-top"><span>DNS-over-HTTPS (DoH):</span><span class="copy-card-tag"><i class="ico ico-clipboard" aria-hidden="true"></i>{{.T.BtnCopy}}</span></span>
          <span class="copy-card-val">https://{{.ServerHost}}:{{.DoHPort}}/dns-query</span>
        </button>

        <button type="button" class="copy-card" data-copy="{{.ServerHost}}:{{.DoTPort}}" data-copied="{{.T.CopiedDoT}}">
          <span class="copy-card-top"><span>DNS-over-TLS (DoT):</span><span class="copy-card-tag"><i class="ico ico-clipboard" aria-hidden="true"></i>{{.T.BtnCopy}}</span></span>
          <span class="copy-card-val">{{.ServerHost}}:{{.DoTPort}}</span>
        </button>
      </div>
    </div>


    <div class="card">
      <div class="hd">
        <span class="hd-title"><i class="ico ico-smartphone" aria-hidden="true"></i>{{.T.CardGuide}}</span>
        <span class="hd-note">{{.T.GuideArrowNote}}</span>
      </div>

      <!-- A real tablist: role, aria-selected, aria-controls, and one tab in the tab
           order at a time, with arrow-key movement handled in /js/portal.js. The
           markup only has to declare data-tab; the script pairs it with data-panel.
           There is one set of panels for both languages, not one per language: the
           script and portal_assets_test.go both require exactly one visible panel and
           exactly one tab in the tab order, so the text comes from the bundle instead. -->
      <div class="tabs" role="tablist" aria-label="{{.T.GuideTabsAria}}">
        <button type="button" class="tab is-active" role="tab" id="tab-ps5" aria-controls="panel-ps5" aria-selected="true" tabindex="0" data-tab="ps5"><i class="ico ico-gamepad" aria-hidden="true"></i>{{.T.TabPs}}</button>
        <button type="button" class="tab" role="tab" id="tab-xbox" aria-controls="panel-xbox" aria-selected="false" tabindex="-1" data-tab="xbox"><i class="ico ico-gamepad" aria-hidden="true"></i>{{.T.TabXbox}}</button>
        <button type="button" class="tab" role="tab" id="tab-switch" aria-controls="panel-switch" aria-selected="false" tabindex="-1" data-tab="switch"><i class="ico ico-gamepad" aria-hidden="true"></i>{{.T.TabSwitch}}</button>
        <button type="button" class="tab" role="tab" id="tab-windows" aria-controls="panel-windows" aria-selected="false" tabindex="-1" data-tab="windows"><i class="ico ico-monitor" aria-hidden="true"></i>{{.T.TabWindows}}</button>
        <button type="button" class="tab" role="tab" id="tab-apple" aria-controls="panel-apple" aria-selected="false" tabindex="-1" data-tab="apple"><i class="ico ico-command" aria-hidden="true"></i>{{.T.TabApple}}</button>
        <button type="button" class="tab" role="tab" id="tab-android" aria-controls="panel-android" aria-selected="false" tabindex="-1" data-tab="android"><i class="ico ico-smartphone" aria-hidden="true"></i>{{.T.TabAndroid}}</button>
        <button type="button" class="tab" role="tab" id="tab-router" aria-controls="panel-router" aria-selected="false" tabindex="-1" data-tab="router"><i class="ico ico-wifi" aria-hidden="true"></i>{{.T.TabRouter}}</button>
      </div>


      <div class="panels">

        <!-- Every device panel has the same shape: a title, the ordered steps from the
             bundle, and one .snippet carrying the addresses. The addresses live in the
             snippet rather than mid-sentence because they are the only part a subscriber
             has to copy exactly, and because a step that interpolates {{.ServerDNS}}
             cannot come from a []string in the bundle. -->
        <div class="panel" id="panel-ps5" role="tabpanel" aria-labelledby="tab-ps5" data-panel="ps5">
          <div class="panel-title">{{.T.PsTitle}}</div>
          <ol class="steps">
            {{- range .T.PsSteps}}
            <li>{{.}}</li>
            {{- end}}
          </ol>
          <div class="snippet">Primary DNS: <b>{{.ServerDNS}}</b><br>Secondary DNS: <b>1.1.1.1</b></div>
        </div>

        <div class="panel is-hidden" id="panel-xbox" role="tabpanel" aria-labelledby="tab-xbox" data-panel="xbox">
          <div class="panel-title">{{.T.XboxTitle}}</div>
          <ol class="steps">
            {{- range .T.XboxSteps}}
            <li>{{.}}</li>
            {{- end}}
          </ol>
          <div class="snippet">Primary DNS: <b>{{.ServerDNS}}</b><br>Secondary DNS: <b>1.1.1.1</b></div>
        </div>

        <div class="panel is-hidden" id="panel-switch" role="tabpanel" aria-labelledby="tab-switch" data-panel="switch">
          <div class="panel-title">{{.T.SwitchTitle}}</div>
          <ol class="steps">
            {{- range .T.SwitchSteps}}
            <li>{{.}}</li>
            {{- end}}
          </ol>
          <div class="snippet">Primary DNS: <b>{{.ServerDNS}}</b><br>Secondary DNS: <b>1.1.1.1</b></div>
        </div>

        <div class="panel is-hidden" id="panel-windows" role="tabpanel" aria-labelledby="tab-windows" data-panel="windows">
          <div class="panel-title">{{.T.WinTitle}}</div>
          <ol class="steps">
            {{- range .T.WinSteps}}
            <li>{{.}}</li>
            {{- end}}
          </ol>
          <div class="snippet">Preferred DNS: <b>{{.ServerDNS}}</b><br>Alternate DNS: <b>1.1.1.1</b></div>
        </div>

        <div class="panel is-hidden" id="panel-apple" role="tabpanel" aria-labelledby="tab-apple" data-panel="apple">
          <div class="panel-title">{{.T.AppleTitle}}</div>
          <p class="para">{{.T.ApplePhone}}</p>
          <p class="para">{{.T.AppleMac}}</p>
          <div class="snippet">DNS: <b>{{.ServerDNS}}</b></div>
        </div>

        <div class="panel is-hidden" id="panel-android" role="tabpanel" aria-labelledby="tab-android" data-panel="android">
          <div class="panel-title">{{.T.AndroidTitle}}</div>
          <p class="para">{{.T.AndroidPrivate}}</p>
          {{- if .HasDomain}}
          <div class="snippet">Private DNS provider hostname: <b>{{.ServerHost}}</b></div>
          {{- else}}
          <div class="snippet">{{.T.AndroidNoDomain}}</div>
          {{- end}}
          <p class="para">{{.T.AndroidStatic}}</p>
          <div class="snippet">DNS 1: <b>{{.ServerDNS}}</b><br>DNS 2: <b>1.1.1.1</b></div>
        </div>

        <div class="panel is-hidden" id="panel-router" role="tabpanel" aria-labelledby="tab-router" data-panel="router">
          <div class="panel-title">{{.T.RouterTitle}}</div>
          <ol class="steps">
            {{- range .T.RouterSteps}}
            <li>{{.}}</li>
            {{- end}}
          </ol>
          <div class="snippet">Primary DNS: <b>{{.ServerDNS}}</b><br>Secondary DNS: <b>1.1.1.1</b></div>
        </div>

      </div>
    </div>


    <!-- role="status" with aria-live="polite" so a screen reader announces "کپی شد"
         without stealing focus or interrupting what is being read. The element stays
         in the DOM empty; /js/portal.js fills it and toggles .is-shown.

         It also carries the four messages the script shows. Putting them here rather
         than in portal.js keeps one spelling of each string per language and keeps the
         script free of Persian literals it would have to pick between at runtime. -->
    <div class="toast" id="toast" role="status" aria-live="polite"
         data-msg-copied="{{.T.MsgCopied}}"
         data-msg-copy-fail="{{.T.MsgCopyFail}}"
         data-msg-register-ok="{{.T.MsgRegisterOK}}"
         data-msg-register-fail="{{.T.MsgRegisterFail}}"
         data-msg-register-denied="{{.T.MsgRegisterDenied}}"
         data-msg-reason-secret="{{.T.MsgRegisterDenied}}"
         data-msg-reason-invalid="{{.T.MsgRegisterFail}}"
         data-msg-reason-suspended="{{.T.MsgRegisterSuspended}}"
         data-msg-reason-expired="{{.T.MsgRegisterExpired}}"
         data-msg-reason-quota="{{.T.MsgRegisterQuota}}"
         data-msg-reason-conflict="{{.T.MsgRegisterConflict}}"></div>

    <div class="footer">
      HyperDNS Smart Controller • UDP/TCP SmartDNS &amp; Transparent SNI Proxy Engine
    </div>

  </div>

  <!-- Last element in <body>, so the document is already parsed and the script needs
       no DOMContentLoaded wrapper. 'self' under the CSP, ETagged and gzipped by
       static.go, and cached across visits instead of re-sent inside every page. -->
  <script src="/js/portal.js"></script>
</body>
</html>`

// dohPortForDisplay / dotPortForDisplay resolve the transport ports the portal
// advertises, falling back to the RFC-documented defaults when the DNS config
// is absent (a test harness).
func dohPortForDisplay(cfg *database.DNSSettings) int {
	if cfg == nil || cfg.DoHPort == 0 {
		return 8443
	}
	return cfg.DoHPort
}

func dotPortForDisplay(cfg *database.DNSSettings) int {
	if cfg == nil || cfg.DoTPort == 0 {
		return 853
	}
	return cfg.DoTPort
}
