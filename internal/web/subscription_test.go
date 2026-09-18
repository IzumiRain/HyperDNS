package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdns/internal/database"
	"hyperdns/internal/service/acme"
)

// Phase 4 (v2.1): the effective-URL layer and the subscription settings record.

// TestSubscriptionOriginFallsBackThroughTheChain pins the host chain the plan
// names: the record's own domain, else the panel domain, else the public IP.
// Two origins disagreeing about which host is authoritative is how links end up
// pointing at a name nothing resolves.
func TestSubscriptionOriginFallsBackThroughTheChain(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	// Nothing configured: the public IP is the last resort.
	ws.tlsSettings = &database.TLSSettings{}
	ws.subSettings = &database.SubscriptionSettings{}
	ws.settings.PublicIP = "203.0.113.10"
	ws.settings.WebPort = 8080
	if got := ws.effectiveSubscriptionDomain(); got != "203.0.113.10" {
		t.Errorf("with no domains configured, host = %q, want the public IP", got)
	}

	// Panel domain configured: the subscription host is the panel's.
	ws.tlsSettings.Domain = "panel.example"
	if got := ws.effectiveSubscriptionDomain(); got != "panel.example" {
		t.Errorf("with only the panel domain, host = %q, want panel.example", got)
	}

	// Subscription domain of its own: it wins.
	ws.subSettings.Domain = "sub.example"
	if got := ws.effectiveSubscriptionDomain(); got != "sub.example" {
		t.Errorf("with a subscription domain, host = %q, want sub.example", got)
	}
}

// TestRegisterLinkSchemeAndPort pins the link shape: TLS panel yields https, a
// non-default port is carried, and a default port is not.
func TestRegisterLinkSchemeAndPort(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	ws.tlsSettings = &database.TLSSettings{Domain: "panel.example", PanelHTTPS: true}
	ws.subSettings = &database.SubscriptionSettings{Domain: "panel.example"}
	ws.settings.WebPort = 8443
	ws.settings.PublicIP = "203.0.113.10"

	link := ws.registerLink("tok123")
	if link != "https://panel.example:8443/ip/tok123" {
		t.Errorf("registerLink = %q, want https://panel.example:8443/ip/tok123", link)
	}

	// Port 443 is the https default and must not be appended.
	ws.settings.WebPort = 443
	if link := ws.registerLink("tok123"); link != "https://panel.example/ip/tok123" {
		t.Errorf("registerLink with port 443 = %q, want the port-free form", link)
	}

	// Plain HTTP panel. Both domains are cleared, because a configured panel
	// domain forces HTTPS at startup — a record with a domain and
	// PanelHTTPS=false is not a state the daemon can actually run in. The
	// v2.2.0 rule is that a leftover subscription domain that matches nothing
	// is a distinct name, which would need its own certificate; that record
	// cannot exist through the UI (the save refuses it), so the reachable
	// plain-HTTP state here has no subscription domain either.
	ws.tlsSettings.PanelHTTPS = false
	ws.tlsSettings.Domain = ""
	ws.subSettings.Domain = ""
	ws.settings.WebPort = 8080
	if link := ws.registerLink("tok123"); link != "http://203.0.113.10:8080/ip/tok123" {
		t.Errorf("registerLink over http = %q, want http://203.0.113.10:8080/ip/tok123", link)
	}

	// No origin at all: an empty link the caller must treat as "configure me".
	ws.tlsSettings.Domain = ""
	ws.subSettings.Domain = ""
	ws.settings.PublicIP = ""
	if link := ws.registerLink("tok123"); link != "" {
		t.Errorf("registerLink with no origin = %q, want empty", link)
	}
}

// TestSubscriptionOriginSameAsPanel pins the certificate-relationship decision:
// panel certificate by default, separate mode when the operator says so or
// names a different domain.
func TestSubscriptionOriginSameAsPanel(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	ws.tlsSettings = &database.TLSSettings{Domain: "panel.example"}
	ws.subSettings = &database.SubscriptionSettings{UsePanelCertificate: true}
	ws.settings.PublicIP = "203.0.113.10"

	if !ws.subscriptionOriginSameAsPanel() {
		t.Error("an unset subscription domain must read as the panel origin")
	}

	ws.subSettings.Domain = "PANEL.example"
	if !ws.subscriptionOriginSameAsPanel() {
		t.Error("domain comparison is case-insensitive: PANEL.example is panel.example")
	}

	ws.subSettings.Domain = "sub.example"
	ws.subSettings.UsePanelCertificate = true
	if ws.subscriptionOriginSameAsPanel() {
		t.Error("a different domain with the panel-cert flag is still a different origin")
	}

	ws.subSettings.Domain = "panel.example"
	ws.subSettings.UsePanelCertificate = false
	if ws.subscriptionOriginSameAsPanel() {
		t.Error("the same domain with the panel-cert flag off means the operator intends a separate pair")
	}
}

// TestSubscriptionSettingsRequireSeparateCertificate proves the v2.2.0
// save-time gate: a subscription origin that is not the panel's must have an
// ACME-issued pair for that exact name under certs/acme/<domain>/ — located
// by the daemon, never accepted from form fields — and the check runs before
// persistence. This is the field-report bug: a domain change without a
// certificate for the new name left the portal serving the old cert.
func TestSubscriptionSettingsRequireSeparateCertificate(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	// Isolated CertDir so no leaked pair can satisfy the check.
	ws.SetACMEManager(acme.NewManager("", "", filepath.Join(t.TempDir(), "acme"), nil))

	ws.tlsSettings = &database.TLSSettings{Domain: "panel.example"}

	ws.subSettings = &database.SubscriptionSettings{Domain: "panel.example", UsePanelCertificate: true}
	if problem := ws.validateSubscriptionCertificate(); problem != "" {
		t.Errorf("same-origin mode reported %q, want no problem", problem)
	}

	// Different domain, no ACME pair on disk: refusing the save is the whole
	// point, and the refusal must name the Let's Encrypt button.
	ws.subSettings.Domain = "sub.example"
	ws.subSettings.CertPath = "certs/manual.pem" // legacy form paths are ignored
	ws.subSettings.KeyPath = "certs/manual.key"
	problem := ws.validateSubscriptionCertificate()
	if problem == "" {
		t.Fatal("a different subscription domain with no certificate was accepted")
	}
	if !strings.Contains(problem, "Let's Encrypt") {
		t.Errorf("the refusal does not point at the button: %q", problem)
	}

	// The right pair where the ACME client would have written it: accepted.
	// A chain-signed pair, since the self-signed refusal is in force for
	// named domains.
	acmeDir := ws.acmeDir()
	if err := os.MkdirAll(acmeDir, 0o700); err != nil {
		t.Fatalf("mkdir acme dir: %v", err)
	}
	certPath, keyPath, _ := writeTestChainPair(t, "sub.example")
	if err := os.Rename(certPath, filepath.Join(acmeDir, "sub.example.crt")); err != nil {
		t.Fatalf("move cert: %v", err)
	}
	if err := os.Rename(keyPath, filepath.Join(acmeDir, "sub.example.key")); err != nil {
		t.Fatalf("move key: %v", err)
	}
	if problem := ws.validateSubscriptionCertificate(); problem != "" {
		t.Errorf("a valid ACME pair for sub.example was refused: %s", problem)
	}
}

// TestSubscriptionPortCollisionIsRefused pins the guard that keeps an operator
// from saving a distinct subscription domain on the panel's own port. Such a
// record is silently broken: bindSubscriberListener treats an equal port as
// "the panel already serves this", so the subscriber surface rides the panel
// listener and is served the PANEL's certificate — every link opens with a
// hostname mismatch and nothing on the card explains why.
func TestSubscriptionPortCollisionIsRefused(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.tlsSettings = &database.TLSSettings{Domain: "panel.example"}
	panelPort := ws.settings.WebPort

	cases := []struct {
		name     string
		in       SubscriptionSettingsInput
		wantProb bool
	}{
		{
			name:     "distinct domain on the panel's port",
			in:       SubscriptionSettingsInput{Enabled: true, Domain: "sub.example", Port: panelPort},
			wantProb: true,
		},
		{
			name:     "distinct domain on port 0, which resolves to the panel's",
			in:       SubscriptionSettingsInput{Enabled: true, Domain: "sub.example", Port: 0},
			wantProb: true,
		},
		{
			name:     "distinct domain on its own port",
			in:       SubscriptionSettingsInput{Enabled: true, Domain: "sub.example", Port: panelPort + 1},
			wantProb: false,
		},
		{
			name:     "the panel's own name on the panel's port",
			in:       SubscriptionSettingsInput{Enabled: true, Domain: "panel.example", Port: panelPort},
			wantProb: false,
		},
		{
			name:     "no custom domain on the panel's port",
			in:       SubscriptionSettingsInput{Enabled: true, Domain: "", Port: panelPort},
			wantProb: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, problem := ws.sanitizeSubscriptionSnapshot(tc.in)
			if tc.wantProb {
				if problem == "" {
					t.Fatal("a distinct subscription domain on the panel's port was accepted")
				}
				// The refusal must tell the operator what to do, not just that
				// something is wrong — the fix is a port, not a TLS setting.
				if !strings.Contains(problem, "port") {
					t.Errorf("the refusal does not point at the port: %q", problem)
				}
				return
			}
			if problem != "" {
				t.Errorf("this configuration should be accepted but was refused: %s", problem)
			}
		})
	}

	// An IP-addressed panel has no name to compare against, so any named
	// subscription domain is a distinct origin that still needs its own port.
	// The refusal must name the public IP rather than emit an empty name.
	ws.tlsSettings = &database.TLSSettings{}
	_, problem := ws.sanitizeSubscriptionSnapshot(SubscriptionSettingsInput{
		Enabled: true, Domain: "sub.example", Port: panelPort,
	})
	if problem == "" {
		t.Fatal("an IP-addressed panel accepted a named subscription domain on its own port")
	}
	if !strings.Contains(problem, ws.settings.GetPublicIP()) {
		t.Errorf("the refusal does not name the panel's IP: %q", problem)
	}
}

// TestSubscriptionSettingsHandler pins the endpoint contract: 405 for other
// verbs, GET returns the snapshot, POST persists through the database record,
// and the response states whether a restart is needed (it is not, in this
// build).
func TestSubscriptionSettingsHandler(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.tlsSettings = &database.TLSSettings{Domain: "panel.example"}
	ws.subSettings = &database.SubscriptionSettings{}
	h := ws.buildAdminHandler()

	// Verb guard, authenticated so the method decision is what is under test.
	tok := bearerFor(t, h)
	req := httptest.NewRequest(http.MethodDelete, "/api/settings/subscription", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /api/settings/subscription = %d, want 405", w.Code)
	}

	// GET carries the defaults.
	req = httptest.NewRequest(http.MethodGet, "/api/settings/subscription", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET subscription settings = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"title"`) {
		t.Errorf("GET body has no title field: %.120s", w.Body.String())
	}

	// POST persists; the stored record matches.
	body := `{"enabled":true,"domain":"panel.example","port":8080,"uri_path":"/sub","title":"ResellerDNS","theme_css":"","use_panel_certificate":true,"cert_path":"","key_path":""}`
	req = httptest.NewRequest(http.MethodPost, "/api/settings/subscription", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST subscription settings = %d — %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"restart_required":true`) {
		t.Error("the response claims a restart is required; the subscription record applies live")
	}
	var stored database.SubscriptionSettings
	if err := ws.db.GetSetting("subscription", &stored); err != nil {
		t.Fatalf("the record was not persisted: %v", err)
	}
	if stored.Title != "ResellerDNS" {
		t.Errorf("stored title = %q, want ResellerDNS", stored.Title)
	}

	// The response carries the recomputed origin. The client cards build their
	// Reg Link and Bot Card URLs from the origin the config carries, so a save
	// that did not hand the new one back left the dashboard copying links to
	// the port that was just replaced — reachable listener, stale URLs.
	var saved struct {
		Origin string `json:"subscription_origin"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatalf("decode save response: %v", err)
	}
	if !strings.HasPrefix(saved.Origin, "https://panel.example") {
		t.Errorf("subscription_origin = %q, want the recomputed https origin", saved.Origin)
	}

	// And the origin moves when the port does, with no restart and no re-fetch.
	req = httptest.NewRequest(http.MethodPost, "/api/settings/subscription",
		strings.NewReader(`{"enabled":true,"domain":"panel.example","port":9090,"uri_path":"/sub","use_panel_certificate":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("port-change POST = %d — %s", w.Code, w.Body.String())
	}
	saved.Origin = ""
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatalf("decode port-change response: %v", err)
	}
	if saved.Origin != "https://panel.example:9090" {
		t.Errorf("subscription_origin after the port change = %q, want https://panel.example:9090", saved.Origin)
	}

	// An unusable path is refused outright rather than stored.
	req = httptest.NewRequest(http.MethodPost, "/api/settings/subscription", strings.NewReader(`{"title":"X","uri_path":"/custom"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST with a custom path = %d, want 400 — this build serves /sub only", w.Code)
	}
}

// TestSubscriptionDefaultsSeedOnce pins the migration: a pre-v2.1 database with
// no subscription record is seeded from the panel origin exactly once, and a
// restart never rewrites an operator's choices.
func TestSubscriptionDefaultsSeedOnce(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.tlsSettings = &database.TLSSettings{Domain: "panel.example"}
	ws.settings.WebPort = 8080
	ws.subSettings = &database.SubscriptionSettings{}

	persistCalls := 0
	persist := func(s *database.SubscriptionSettings) error {
		persistCalls++
		return nil
	}

	seeded, err := database.EnsureSubscriptionDefaults(ws.subSettings, "panel.example", 8080, persist)
	if err != nil || !seeded {
		t.Fatalf("first seed = %v, %v; want seeded", seeded, err)
	}
	if ws.subSettings.Title != "HyperDNS" || ws.subSettings.URIPath != "/sub" || !ws.subSettings.UsePanelCertificate || !ws.subSettings.Enabled {
		t.Errorf("seed does not carry the documented defaults (title=%q path=%q panel-cert=%v enabled=%v)",
			ws.subSettings.Title, ws.subSettings.URIPath, ws.subSettings.UsePanelCertificate, ws.subSettings.Enabled)
	}
	if ws.subSettings.Domain != "panel.example" || ws.subSettings.Port != 8080 {
		t.Errorf("seed origin = %s:%d, want the panel origin", ws.subSettings.Domain, ws.subSettings.Port)
	}

	// An operator edit.
	ws.subSettings.Domain = "sub.example"
	ws.subSettings.Title = "ResellerDNS"

	seeded, err = database.EnsureSubscriptionDefaults(ws.subSettings, "panel.example", 8080, persist)
	if err != nil {
		t.Fatalf("second seed errored: %v", err)
	}
	if seeded {
		t.Error("the second EnsureSubscriptionDefaults reported a seed; the record already exists")
	}
	if ws.subSettings.Domain != "sub.example" || ws.subSettings.Title != "ResellerDNS" {
		t.Errorf("a restart rewrote the operator's record: domain=%q title=%q", ws.subSettings.Domain, ws.subSettings.Title)
	}
}

// TestPortalTitleComesFromSubscriptionSettings pins the one user-visible piece
// Phase 4 already ships: the portal page title carries the operator's brand.
func TestPortalTitleComesFromSubscriptionSettings(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.subSettings = &database.SubscriptionSettings{Title: "ResellerDNS"}

	client, err := ws.clients.CreateClient("Title Probe", 30, "10.0.0.1")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	h := ws.BuildHandler()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /ip/%s = %d", client.Token, w.Code)
	}
	if !strings.Contains(w.Body.String(), "<title>") || !strings.Contains(w.Body.String(), "ResellerDNS") {
		t.Errorf("the portal page does not carry the configured title — body %.300s", w.Body.String())
	}
}

// Phase 7: the operator's stylesheet reaches the subscriber pages sanitised,
// after the built-in stylesheet, and only as CSS.
func TestPortalThemeCSSRendering(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.subSettings = &database.SubscriptionSettings{
		Title: "ResellerDNS",
		// One safe rule plus the three things the sanitiser must neutralise:
		// an external @import, an exfiltration url(), and a script tag.
		ThemeCSS: ".card{border-color:#ff0;} @import url(https://evil.example/x.css); " +
			".a{background:url(https://evil.example/pixel.png);} <script>alert(1)</script>",
	}

	client, err := ws.clients.CreateClient("CSS Probe", 30, "10.0.0.1")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	h := ws.BuildHandler()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /ip/%s = %d", client.Token, w.Code)
	}
	body := w.Body.String()

	// The safe rule survives and lands after the built-in stylesheet.
	if !strings.Contains(body, ".card{border-color:#ff0;}") {
		t.Error("the safe custom CSS did not reach the page")
	}
	cssIdx := strings.Index(body, ".card{border-color")
	builtIdx := strings.Index(body, "/css/portal.css")
	if cssIdx < 0 || builtIdx < 0 || cssIdx < builtIdx {
		t.Errorf("the custom CSS must follow the built-in stylesheet (css=%d built=%d)", cssIdx, builtIdx)
	}
	// The dangerous constructs are gone.
	for _, banned := range []string{"@import", "evil.example", "<script>alert(1)</script>"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(banned)) {
			t.Errorf("the page contains %q after sanitising", banned)
		}
	}
}

// An empty stylesheet emits no <style> element at all.
func TestPortalThemeCSSEmptyRendersNothing(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.subSettings = &database.SubscriptionSettings{ThemeCSS: "   "}

	client, err := ws.clients.CreateClient("CSS Empty Probe", 30, "10.0.0.1")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	h := ws.BuildHandler()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /ip/%s = %d", client.Token, w.Code)
	}
	if strings.Count(w.Body.String(), "<style>") != 0 {
		t.Error("an empty theme rendered a style element")
	}
}

// The Swagger viewer is vendored (rework Phase 4): the docs page must link it
// same-origin and the assets must be served inside the admin namespace — no
// CDN, no off-origin request, no CSP exception.
func TestSwaggerDocsAreVendoredSameOrigin(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	// The API layer reads the admin path from settings; production always has
	// one (main.go seeds it). Pin it here so the docs links and the router agree.
	ws.settings.AdminPath = "a1b2c3d4e5f60718"
	// The docs page is a keyless route and therefore bind-gated; this test is
	// about the vendored viewer, not the gate, so the harness serves as a
	// Public API install.
	ws.settings.APIBind = "0.0.0.0"
	h := ws.BuildHandler()
	ap := ws.AdminPath()

	// The docs page loads under the admin namespace.
	req := httptest.NewRequest(http.MethodGet, "/"+ap+"/api/v1/docs", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET docs = %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "unpkg.com") {
		t.Error("the docs page still references the CDN")
	}
	for _, asset := range []string{"/" + ap + "/swagger/swagger-ui.css", "/" + ap + "/swagger/swagger-ui-bundle.js"} {
		if !strings.Contains(body, asset) {
			t.Errorf("the docs page does not link the vendored asset %q", asset)
		}
	}
	// The vendored assets themselves are served same-origin under the admin
	// namespace and resolve where the page's relative href expects.
	for _, rel := range []string{"/" + ap + "/swagger/swagger-ui.css", "/" + ap + "/swagger/swagger-ui-bundle.js"} {
		req := httptest.NewRequest(http.MethodGet, rel, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 — the vendored viewer is missing", rel, w.Code)
		}
	}
}
