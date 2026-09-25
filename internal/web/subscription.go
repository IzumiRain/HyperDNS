package web

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The effective-URL layer (v2.1 plan §3.2).
//
// Before this file existed, every place that named a subscriber-facing origin
// reconstructed the address from whatever was at hand — the public IP, the
// request's Host header, the panel TLS domain — and each reconstruction
// disagreed with the others about which host was authoritative. These helpers
// make one answer per question, read the settings under their locks, and are
// the only code allowed to build an origin for display.
//
// Handlers must not rebuild URLs from r.Host except where a handler is
// explicitly resolving the visitor's own view of the server (the portal's
// display-only Host fallback, which never persists anything).

// effectivePanelDomain returns the hostname the panel presents: the configured
// TLS domain when there is one, else "" and the caller falls back to an IP.
func (ws *WebServer) effectivePanelDomain() string {
	if ws.tlsSettings != nil {
		if d := safeHostDisplay(ws.tlsSettings.GetDomain()); d != "" {
			return d
		}
	}
	return ""
}

// effectiveSubscriptionDomain returns the hostname a subscriber link should
// carry: the subscription record's own domain when set, else the panel domain,
// else the public IP — the exact chain the portal already used, now written
// once instead of twice.
func (ws *WebServer) effectiveSubscriptionDomain() string {
	if ws.subSettings != nil {
		if d := safeHostDisplay(ws.subSettings.GetDomain()); d != "" {
			return d
		}
	}
	if d := ws.effectivePanelDomain(); d != "" {
		return d
	}
	if p := ws.settings.GetPublicIP(); p != "" {
		return p
	}
	return ""
}

// subscriptionOrigin builds "scheme://host[:port]" for the subscriber surface.
// The scheme is the one the subscriber listener actually serves — a record with
// its own certificate pair is HTTPS even when the panel itself is plain HTTP,
// and a record reusing the panel's certificate follows the panel (see
// subscriberHTTPS). The links must say what the listener speaks, or a
// subscriber's browser posts the 1-click URL to a port that answers the wrong
// handshake. A port is appended only when it differs from the scheme's default,
// so the common deployments produce clean links.
//
// An empty result means the daemon genuinely has nothing to advertise — no
// domain, no public IP — and the caller shows a placeholder instead of a link
// that lies.
func (ws *WebServer) subscriptionOrigin() string {
	host := ws.effectiveSubscriptionDomain()
	if host == "" {
		return ""
	}
	scheme := "http"
	if ws.subscriberHTTPS() {
		scheme = "https"
	}
	port := 0
	if ws.subSettings != nil {
		port = ws.subSettings.GetPort()
	}
	// Fall through: WebPort is what the panel actually listens on.
	if port == 0 {
		port = ws.settings.WebPort
	}
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) || port <= 0 {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + strconv.Itoa(port)
}

// dohURL builds the DNS-over-HTTPS endpoint URL a client should configure.
// The addressable host prefers the dedicated DoH/DoT domain (the only name
// that domain's certificate is guaranteed to cover), then the panel domain,
// then the public IP. The port is the DoH listener's own — NOT the web port —
// and is suppressed only when it is the scheme default. Empty when there is
// no host to name.
//
// This is the single source of truth for the Connect Guide's DoH line, the
// portal's copy button, and the /api/config field the dashboard renders from;
// each of those three used to guess independently (web port, http scheme,
// hardcoded 8443), and no two guesses agreed.
func (ws *WebServer) dohURL() string {
	host := ""
	if ws.tlsSettings != nil {
		host = strings.TrimSpace(ws.tlsSettings.GetDoTDomain())
	}
	if host == "" {
		host = ws.effectivePanelDomain()
	}
	if host == "" {
		host = ws.effectiveSubscriptionDomain()
	}
	if host == "" {
		return ""
	}
	port := 0
	if ws.dnsCfg != nil {
		port = ws.dnsCfg.DoHPort
	}
	if port == 0 {
		port = 8443
	}
	if port == 443 {
		return "https://" + host + "/dns-query"
	}
	return "https://" + host + ":" + strconv.Itoa(port) + "/dns-query"
}

// registerLink returns the 1-click registration URL for a subscriber token —
// the string the dashboard copies, the QR code encodes, and the Telegram bot
// sends. Empty when the daemon has no origin to name; callers must render a
// "configure your public address" hint in that case rather than a broken URL.
func (ws *WebServer) registerLink(token string) string {
	if token == "" {
		return ""
	}
	origin := ws.subscriptionOrigin()
	if origin == "" {
		return ""
	}
	return origin + "/ip/" + token
}

// subscriptionLink returns the read-only portal URL for the token.
func (ws *WebServer) subscriptionLink(token string) string {
	if token == "" {
		return ""
	}
	origin := ws.subscriptionOrigin()
	if origin == "" {
		return ""
	}
	return origin + "/sub/" + token
}

// dashLoginURL returns the hidden login address as a display string, for the
// settings page's "your panel is at" line. It is addressed by the panel domain
// when one is configured and by the public IP when there is not, and it names
// the admin path — this is an authenticated operator's own view of their
// server, so naming the path here is the point.
func (ws *WebServer) dashLoginURL() string {
	snapshot := ws.tlsSettings.Snapshot()
	scheme := "http"
	if snapshot.PanelHTTPS {
		scheme = "https"
	}
	host := ws.effectivePanelDomain()
	if host == "" {
		host = ws.settings.GetPublicIP()
	}
	if host == "" {
		host = ws.settings.BindHost
	}
	if host == "" || host == "0.0.0.0" {
		host = "<server-address>"
	}
	port := ws.settings.WebPort
	base := scheme + "://" + host
	if port > 0 && !((scheme == "https" && port == 443) || (scheme == "http" && port == 80)) {
		base += ":" + strconv.Itoa(port)
	}
	return base + "/" + ws.adminPath() + "/dash/"
}

// subscriptionOriginSameAsPanel reports whether the subscription record points
// at the panel's own origin, which is what decides whether the panel
// certificate covers subscriber links and whether a separate pair is required
// at all (plan Phase 4 exit gate).
func (ws *WebServer) subscriptionOriginSameAsPanel() bool {
	if ws.subSettings == nil {
		return true
	}
	snap := ws.subSettings.Snapshot()
	if !snap.UsePanelCertificate {
		return false
	}
	// An unset subscription domain means "the panel's", by definition.
	domain := strings.TrimSpace(snap.Domain)
	if domain == "" {
		return true
	}
	panel := ws.effectivePanelDomain()
	if panel == "" {
		// No panel domain: the panel is addressed by IP, and an IP-named origin
		// is the same origin the portal always used.
		return strings.EqualFold(domain, ws.settings.GetPublicIP())
	}
	return strings.EqualFold(domain, panel)
}

// validateSubscriptionCertificate is the persistence-time check: a
// subscription origin that is NOT the panel's must have an ACME-issued pair
// for that exact name under certs/acme/. Saving a domain without the
// material to serve it is the field-report bug — the portal kept serving the
// OLD domain's certificate for the NEW name and every browser said "Not
// Secure". The pair is created by the Let's Encrypt button next to the
// domain field (POST /api/tls/issue, purpose=subscription), which applies
// the domain only after the certificate exists; manual path fields are gone
// from the UI and ignored here.
//
// Returns a human-readable problem, or "" when the configuration is usable.
func (ws *WebServer) validateSubscriptionCertificate() string {
	snap := ws.subSettings.Snapshot()
	domain := strings.TrimSpace(snap.Domain)
	if domain == "" {
		return "" // no custom domain: the panel's certificate serves
	}
	panel := ws.effectivePanelDomain()
	if panel == "" {
		// No panel domain: the panel is addressed by IP, and an IP-named
		// origin is the same origin the panel always served.
		panel = ws.settings.GetPublicIP()
	}
	if panel != "" && strings.EqualFold(domain, panel) {
		return "" // the panel's own name: the panel's certificate serves
	}
	certPath := filepath.Join(ws.acmeDir(), domain+".crt")
	keyPath := filepath.Join(ws.acmeDir(), domain+".key")
	if err := ValidatePanelCertificate(certPath, keyPath, domain); err != nil {
		return "the subscription domain has no issued certificate yet — click Let's Encrypt beside the domain field to obtain one (the domain is applied only after the certificate exists)"
	}
	return ""
}

// acmeDir names where this daemon's embedded ACME client stores issued
// pairs. It mirrors the layout choice in cmd/hyperdns/main.go: under
// /opt/hyperdns when installed, beside the working directory otherwise.
func (ws *WebServer) acmeDir() string {
	if ws.acmeManager != nil && ws.acmeManager.CertDir != "" {
		return ws.acmeManager.CertDir
	}
	if _, err := os.Stat("/opt/hyperdns"); err == nil {
		return "/opt/hyperdns/certs/acme"
	}
	return "certs/acme"
}

// sanitizeSubscriptionSnapshot validates and normalises an operator's
// subscription settings before they are persisted. It returns the corrected
// snapshot and a problem string; a non-empty problem means the caller must
// refuse the save (400) rather than silently storing something different from
// what the form showed.
func (ws *WebServer) sanitizeSubscriptionSnapshot(in SubscriptionSettingsInput) (SubscriptionSettingsInput, string) {
	out := in

	out.Title = strings.TrimSpace(out.Title)
	if out.Title == "" {
		out.Title = "HyperDNS"
	}
	if len(out.Title) > 64 {
		return in, "the title must be at most 64 characters"
	}

	out.URIPath = NormalizeURIPath(out.URIPath)
	if out.URIPath == "" {
		out.URIPath = "/sub"
	}
	// The portal routes are fixed in this build; the field may only carry the
	// value they already live at. Anything else is an intent to break every
	// subscriber link, and the UI has no way to make the daemon follow it.
	if out.URIPath != "/sub" {
		return in, "the subscription path is /sub in this build; a custom mount is not supported yet"
	}

	if out.Domain != "" {
		d := NormalizeDomain(out.Domain)
		if d == "" {
			return in, fmt.Sprintf("%q is not a usable hostname", in.Domain)
		}
		out.Domain = d
	}

	if out.Port < 0 || out.Port > 65535 {
		return in, "the port must be between 0 and 65535"
	}

	// Custom-CSS source (v2.4): the portal's stylesheet can come from the inline
	// textbox, a server-local file, or an http(s) URL the browser loads. Validate
	// the selector and the value that goes with it; the local file's existence is
	// checked at render time, not here, so an operator can point at a path they
	// are about to create.
	out.ThemeCSSSource = strings.ToLower(strings.TrimSpace(out.ThemeCSSSource))
	switch out.ThemeCSSSource {
	case "", "inline":
		out.ThemeCSSSource = "inline"
		out.ThemeCSSPath = ""
		out.ThemeCSSURL = ""
	case "local":
		out.ThemeCSSPath = strings.TrimSpace(out.ThemeCSSPath)
		out.ThemeCSSURL = ""
		if out.ThemeCSSPath == "" {
			return in, "choose a CSS file path, or switch the source away from local"
		}
		// The daemon runs on Linux, so an absolute path starts with "/". Check
		// the byte rather than filepath.IsAbs, whose answer is host-OS dependent
		// (a "/root/..." path is not "absolute" to a Windows test runner).
		if !strings.HasPrefix(out.ThemeCSSPath, "/") {
			return in, "the CSS file path must be absolute (e.g. /root/css/sub.css)"
		}
	case "url":
		out.ThemeCSSURL = strings.TrimSpace(out.ThemeCSSURL)
		out.ThemeCSSPath = ""
		u, err := url.Parse(out.ThemeCSSURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return in, "the CSS URL must be an absolute http:// or https:// address"
		}
		out.ThemeCSSURL = u.String()
	default:
		return in, "the CSS source must be inline, local or url"
	}

	// A subscription domain that is not the panel's own name is served by its
	// own ACME pair on a dedicated listener — and bindSubscriberListener only
	// binds that listener on a port that differs from the panel's. An equal
	// port (including 0, which resolves to the panel's) means "share the panel
	// listener", which serves the PANEL's certificate, so the subscriber link
	// opens with a hostname mismatch and nothing on the card explains why.
	// Refuse the save rather than store a record that silently breaks every
	// link: the operator's fix is to pick a free port, not to suspect TLS.
	if out.Domain != "" && !strings.EqualFold(out.Domain, ws.effectivePanelDomain()) &&
		(out.Port == 0 || out.Port == ws.settings.WebPort) {
		panelName := ws.effectivePanelDomain()
		if panelName == "" {
			panelName = ws.settings.GetPublicIP() // an IP-addressed panel
		}
		return in, fmt.Sprintf(
			"the subscription portal needs a port of its own when it does not use the panel's domain: "+
				"%s on the panel's port would be served the panel's certificate for %s, and subscribers would see a hostname mismatch — "+
				"choose a free port for the subscription portal and open it in the firewall",
			out.Domain, panelName)
	}

	// The explicit-port marker (v2.2.0 remediation): a port that is neither 0
	// nor the panel's current port is a deliberate choice, and a panel-port
	// change must not copy-follow it — the boot-time drift repair and the
	// live copy-follow both read this flag. Returning the port to the panel's
	// clears it, so the record rides the panel again.
	out.PortExplicit = out.Port != 0 && out.Port != ws.settings.WebPort

	// v2.2.0: a distinct subscription domain is served by its ACME pair, so
	// the record's cert fields are derived here rather than accepted from the
	// form. The same-domain and empty-domain cases ride the panel certificate.
	// The pair's existence is checked by validateSubscriptionCertificate; this
	// only makes sure the stored record points at the right place so a
	// restart serves the same certificate the live listener just switched to.
	out.CertPath = ""
	out.KeyPath = ""
	out.UsePanelCertificate = true
	if out.Domain != "" && !strings.EqualFold(out.Domain, ws.effectivePanelDomain()) {
		out.UsePanelCertificate = false
		out.CertPath = filepath.Join(ws.acmeDir(), out.Domain+".crt")
		out.KeyPath = filepath.Join(ws.acmeDir(), out.Domain+".key")
	}
	return out, ""
}

// SubscriptionSettingsInput is the shape the settings handler decodes. It is a
// distinct type rather than a snapshot so the JSON contract stays decoupled
// from the storage type: a field the UI must not set (ListenIP in this build)
// is simply absent here.
type SubscriptionSettingsInput struct {
	Enabled             bool   `json:"enabled"`
	Domain              string `json:"domain"`
	Port                int    `json:"port"`
	URIPath             string `json:"uri_path"`
	Title               string `json:"title"`
	ThemeCSS            string `json:"theme_css"`
	ThemeCSSSource      string `json:"theme_css_source"`
	ThemeCSSPath        string `json:"theme_css_path"`
	ThemeCSSURL         string `json:"theme_css_url"`
	CertPath            string `json:"cert_path"`
	KeyPath             string `json:"key_path"`
	UsePanelCertificate bool   `json:"use_panel_certificate"`
	// PortExplicit is derived, never accepted from the form: the sanitiser
	// sets it from the relationship between the submitted port and the
	// panel's. It rides the input struct only so the normalised result can
	// carry it into the snapshot that is persisted.
	PortExplicit bool `json:"-"`
}
