package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The dashboard document is one 156 KB HTML file assembled by hand, and twice
// now a single missing or extra </div> has shipped. The failure mode is not a
// broken page — the parser recovers — it is a page that looks almost right: the
// stray close ends the layout wrapper early, and every element after it (the
// Connect tab, the desktop footer, the mobile nav) is reparented to <body>.
// Body is a row-wise flex container, so the footer that should sit under the
// content column renders beside it, at the right edge of the screen.
//
// These tests are structural, not stylistic: they pin the consequences the
// misnesting had, so the next hand-edit that unbalances a tag fails here rather
// than in a screenshot from an operator.

// TestIndexHTMLSectionsAreDivBalanced counts <div> against </div> per top-level
// tab. A section whose counts differ is one that steals a close from (or
// donates one to) its neighbours, which is how the footer ended up outside main.
func TestIndexHTMLSectionsAreDivBalanced(t *testing.T) {
	doc := readAsset(t, "index.html")
	sections := []string{
		"tab-dashboard", "tab-clients", "tab-policy",
		"tab-stream", "tab-api", "tab-rules", "tab-connect",
	}
	pos := make([]int, len(sections))
	for i, id := range sections {
		pos[i] = strings.Index(doc, `id="`+id+`"`)
		if pos[i] < 0 {
			t.Fatalf("index.html has no section id=%q — the document was restructured "+
				"and this test needs the new anchors", id)
		}
	}
	openRe, closeRe := regexp.MustCompile(`<div\b`), regexp.MustCompile(`</div>`)
	// The last tab runs to the end of the content column, not the end of the
	// document: the footer lives inside <main> after it (see the test below), and
	// counting it here would report a balance error that is not one.
	contentEnd := strings.Index(doc, "<!-- FOOTER")
	if contentEnd < 0 {
		contentEnd = len(doc)
	}
	for i, id := range sections {
		end := contentEnd
		for _, p := range pos {
			if p > pos[i] && p < end {
				end = p
			}
		}
		seg := doc[pos[i]:end]
		opens, closes := len(openRe.FindAllString(seg, -1)), len(closeRe.FindAllString(seg, -1))
		if opens != closes {
			t.Errorf("index.html section %s has %d <div> and %d </div> (delta %+d) — "+
				"an unbalanced tab steals a close from the next one, which reparents the "+
				"tabs after it (and the footer) onto <body>",
				id, opens, closes, opens-closes)
		}
	}
}

// TestIndexHTMLFooterIsInsideMain is the specific consequence above, asserted on
// its own because it is the user-visible symptom that was reported twice.
func TestIndexHTMLFooterIsInsideMain(t *testing.T) {
	doc := readAsset(t, "index.html")
	mainOpen := strings.Index(doc, "<main")
	mainClose := strings.Index(doc, "</main>")
	footerOpen := strings.Index(doc, "<footer")
	footerClose := strings.Index(doc, "</footer>")
	if mainOpen < 0 || mainClose < 0 || footerOpen < 0 || footerClose < 0 {
		t.Fatalf("index.html is missing one of main/footer (main=%d/%d footer=%d/%d)",
			mainOpen, mainClose, footerOpen, footerClose)
	}
	if !(mainOpen < footerOpen && footerClose < mainClose) {
		t.Errorf("the footer is not inside <main> (main %d..%d, footer %d..%d) — outside "+
			"it the footer becomes a flex item of <body> and renders at the right edge of "+
			"the page instead of under the content column",
			mainOpen, mainClose, footerOpen, footerClose)
	}
}

func TestIndexHTMLHasAccessibleDocumentAnchors(t *testing.T) {
	doc := readAsset(t, "index.html")
	checks := map[string]string{
		"skip link":           `<a href="#main-content" class="skip-link">`,
		"main target":         `<main id="main-content"`,
		"page heading":        `<h1 id="login-title"`,
		"query log caption":   `<caption class="sr-only">Live DNS query log</caption>`,
		"enabled field group": `<fieldset class="contents">`,
	}
	for name, fragment := range checks {
		if !strings.Contains(doc, fragment) {
			t.Errorf("index.html is missing %s (%q)", name, fragment)
		}
	}
}

func TestIndexHTMLFormsHaveExplicitLabels(t *testing.T) {
	doc := readAsset(t, "index.html")
	for _, pair := range [][2]string{
		{"login-username", "ADMIN USERNAME"}, {"login-password", "PASSWORD"}, {"login-code", "TWO-FACTOR CODE"},
		{"edit-client-name", "Email / Client Name"}, {"edit-client-traffic", "Traffic Limit (GB)"},
		{"edit-client-traffic-cycle", "Auto Reset"}, {"edit-client-expiry", "Expiry (Gregorian)"},
		{"edit-client-ip", "Manual IP Address (Optional)"}, {"edit-client-uuid", "UUID (RFC 4122 v4)"},
		{"edit-client-secret", "Registration Secret (IP register)"}, {"edit-client-note", "Comment / Note"},
		{"client-name-input", "CLIENT NAME / LABEL"},
		{"client-traffic-input", "Traffic Limit (GB)"}, {"client-traffic-cycle", "Auto Reset"},
		{"add-client-expiry", "Expiry (Gregorian)"},
		{"client-initial-ip", "INITIAL IP ADDRESS (OPTIONAL)"},
	} {
		if !strings.Contains(doc, `for="`+pair[0]+`"`) {
			t.Errorf("form control %s has no explicit label (%s)", pair[0], pair[1])
		}
	}
}

func TestIndexHTMLMobileNavigationMeetsTargetSize(t *testing.T) {
	doc := readAsset(t, "index.html")
	if strings.Count(doc, `class="mobile-nav-item`) != 7 {
		t.Error("the mobile navigation must carry its seven targets")
	}
	// Sizing lives once in css/style.css's .mobile-nav-item rule (a documented
	// 40px target inside the 48px bar — above WCAG 2.2 SC 2.5.8's 24px floor),
	// not repeated across seven class lists. The markup used to also carry a
	// min-h-[44px] utility that style.css silently overrode to 40px, so it
	// declared an intent the page never honoured; a per-item height class back
	// in the markup means the two sources disagree again.
	if strings.Contains(doc, `mobile-nav-item min-h-[`) || strings.Contains(doc, `min-h-[44px]" data-tab`) {
		t.Error("mobile navigation targets carry a per-item height class — sizing " +
			"belongs to the single .mobile-nav-item rule in css/style.css, and a class " +
			"the stylesheet overrides is a declaration the page never honours")
	}
	css := readCSSRules(t, "css/style.css")
	if !strings.Contains(css, ".mobile-nav-item {") || !strings.Contains(css, "min-height: 40px;") {
		t.Error("css/style.css no longer gives .mobile-nav-item its 40px minimum height — " +
			"the mobile targets are unsized and fall below the WCAG 2.5.8 24px floor")
	}
}

// TestIndexHTMLHasNoMojibake guards the other half of the same report. The
// document is embedded in the binary and was shipped with cp1252-misdecoded
// UTF-8 baked in: the Persian labels read "ÙØ§Ø±Ø3ÛŒ" and em-dashes, bullets and
// curly quotes were all double-encoded. The markers below only ever appear as
// mojibake, so legitimate UTF-8 (including Persian) passes untouched.
func TestIndexHTMLHasNoMojibake(t *testing.T) {
	doc := readAsset(t, "index.html")
	for _, marker := range []string{"\u00c3", "\u00c2", "\u00d9", "\u00db", "\u00e2\u20ac"} {
		if i := strings.Index(doc, marker); i >= 0 {
			line := 1 + strings.Count(doc[:i], "\n")
			t.Errorf("index.html line %d contains the mojibake sequence %q — this file is "+
				"embedded in the binary and served verbatim, so it reaches the browser "+
				"exactly as written", line, marker)
		}
	}
	for _, b := range []byte(doc) {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			t.Errorf("index.html contains control byte 0x%02x", b)
			break
		}
	}
}

// TestSubscriberSurfaceServesNoAdminRoutes pins the allow-list on the dedicated
// subscriber listener. The port it binds is public by design — the operator
// advertises it in every subscriber link — so the panel, the REST API, DoH and
// the SPA must not be reachable there. This is the test that fails if someone
// "simplifies" subscriberSurface by handing it the admin handler.
func TestSubscriberSurfaceServesNoAdminRoutes(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.subscriberSurface()

	// A real token: the token-scoped routes answer 404 for an unknown one by
	// design, so a made-up token would look like a blocked route.
	client, err := ws.clients.CreateClient("Surface Check", 30, "")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	// blockedBody is exactly what http.NotFound writes. Comparing the body
	// rather than the status is what separates "the allow-list refused this"
	// from "the route ran and answered 404 for its own reasons".
	const blockedBody = "404 page not found\n"

	public := []string{
		"/sub/" + client.Token,
		"/ip/" + client.Token,
		"/api/sub/" + client.Token,
		"/css/portal.css",
		"/js/portal.js",
		"/fonts/vazirmatn-var.woff2",
	}
	for _, p := range public {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Body.String() == blockedBody {
			t.Errorf("subscriberSurface blocked the public route %s — the portal is the "+
				"whole point of the listener", p)
		}
	}

	// Every one of these exists on the panel listener. On the public port each
	// must be indistinguishable from a path that does not exist.
	private := []string{
		"/", "/dash/home", "/" + ws.AdminPath() + "/dash/",
		"/api/clients", "/api/config", "/api/stats", "/api/auth/login",
		"/dns-query", "/js/app.js", "/css/style.css", "/js/app.js.map",
	}
	for _, p := range private {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Body.String() != blockedBody {
			t.Errorf("subscriberSurface did not block %s (status %d, %d bytes) — the "+
				"public subscriber port must expose nothing but the portal routes",
				p, rec.Code, rec.Body.Len())
		}
	}
}

// TestPortalBrandLineIsTheOperatorsTitle pins the fix for the settings card that
// "did nothing": the portal heading used to be a translated constant, so
// changing Portal title changed the browser tab and nothing a subscriber saw.
func TestPortalBrandLineIsTheOperatorsTitle(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	client, err := ws.clients.CreateClient("Brand Check", 30, "")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	if !strings.Contains(portalPageHTML, `<h1 class="title">{{.Title}}</h1>`) {
		t.Fatal("the portal h1 does not render .Title — the operator's Portal title " +
			"reaches the browser tab and not the page")
	}

	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0")
	w := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `<h1 class="title">HyperDNS</h1>`) {
		t.Error("the default brand line is not rendered as the portal heading")
	}
}
