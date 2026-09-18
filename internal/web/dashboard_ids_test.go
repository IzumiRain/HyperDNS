package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// app.js does not create element ids. Grepping its template literals for `id="` and its
// code for `.id =` returns nothing: every id it touches is declared in index.html and
// nowhere else. That makes "every id app.js looks up exists in index.html" an exact,
// checkable property rather than a heuristic — and one worth checking, because both ways
// of getting it wrong are silent.
//
// document.getElementById returns null for an id that is not there, and app.js is written
// defensively throughout — `if (!el) return`, `el?.addEventListener`, and a setTxt helper
// that no-ops when the element is missing. So a renamed or deleted id does not throw and
// does not log: the button simply stops doing anything, or the tile keeps its placeholder
// dash forever. That is how a whole 37-line API-key regeneration handler sat in this file
// bound to `regen-api-key-btn` while index.html only ever declared
// `regenerate-api-key-btn` — dead code that looked live, found by hand-diffing the two
// lists, which is what this file replaces.

// dashGetByIDRe matches a getElementById call with a literal argument. The dynamic ones —
// `tab-${target}` and `snippet-${snip}` — do not match, and are covered instead by
// TestDashboardTabsAndPanelsAgree, which checks the values those templates can produce.
var dashGetByIDRe = regexp.MustCompile(`getElementById\('([a-zA-Z0-9_-]+)'\)`)

// dashSetTxtRe matches the stat-tile writes. setTxt takes the id as a parameter, so
// dashGetByIDRe cannot see these eighteen ids — its call site is one shared helper.
var dashSetTxtRe = regexp.MustCompile(`setTxt\('([a-zA-Z0-9_-]+)'`)

// dashHTMLIDRe matches an id attribute. The leading \s keeps it from matching
// `data-id="…"` or any other attribute ending in "id".
var dashHTMLIDRe = regexp.MustCompile(`\sid="([a-zA-Z0-9_-]+)"`)

// dashDataAttrRe matches data-tab and data-snippet, the two attributes app.js reads back
// through dataset and turns into an element id.
var dashDataAttrRe = regexp.MustCompile(`data-(tab|snippet)="([a-zA-Z0-9_-]+)"`)

// dashJSKeyRe and dashJSValRe pull the keys and values out of a quoted-string object
// literal such as tabRoutes.
var dashJSKeyRe = regexp.MustCompile(`'([^']+)'\s*:`)
var dashJSValRe = regexp.MustCompile(`:\s*'([^']+)'`)

// dashIDSet returns every id declared in index.html.
func dashIDSet(t *testing.T, html string) map[string]bool {
	t.Helper()

	set := map[string]bool{}
	for _, id := range values(dashHTMLIDRe, html) {
		set[id] = true
	}
	if len(set) < 150 {
		t.Fatalf("only %d ids found in web/index.html — the scan is broken, which would "+
			"make every check in this file vacuous", len(set))
	}
	return set
}

// dashJSObject returns the body of a top-level `const <name> = { … };` object literal.
func dashJSObject(t *testing.T, src, name string) string {
	t.Helper()

	decl := "\nconst " + name + " = {"
	start := strings.Index(src, decl)
	if start < 0 {
		t.Fatalf("js/app.js has no top-level object literal %s", name)
	}
	end := strings.Index(src[start:], "\n};")
	if end < 0 {
		t.Fatalf("could not find the end of %s in js/app.js", name)
	}
	return src[start : start+end]
}

// The whole point is that a missing id is not an error at runtime. Nothing in the browser
// console says so, and the only symptom is a control that does nothing when clicked.
func TestDashboardElementLookupsResolve(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")
	declared := dashIDSet(t, html)

	lookups := append(values(dashGetByIDRe, app), values(dashSetTxtRe, app)...)
	if len(lookups) < 150 {
		t.Fatalf("only %d literal element lookups found in js/app.js — the scan is broken, "+
			"which would make this test vacuously pass", len(lookups))
	}

	missing := map[string]bool{}
	for _, id := range lookups {
		if !declared[id] {
			missing[id] = true
		}
	}
	for _, id := range sortedKeys(missing) {
		t.Errorf("js/app.js looks up #%s, which web/index.html does not declare.\n"+
			"getElementById returns null and app.js guards every one of these, so this "+
			"does not throw — the control silently does nothing, or the tile keeps its "+
			"placeholder. Either add the id to index.html or delete the dead handler.", id)
	}
}

// A duplicated id is the other half of the same failure: getElementById returns the first
// one in document order, so the second copy is inert. index.html carries the dashboard and
// four modals in one document, and the modals repeat the vocabulary of the page behind
// them — client-name-input, edit-client-expiry, current-admin-pass — which is exactly the
// shape that produces a collision during a copy-paste of a form block.
func TestDashboardIDsAreUnique(t *testing.T) {
	html := readAsset(t, "index.html")

	count := map[string]int{}
	for _, id := range values(dashHTMLIDRe, html) {
		count[id]++
	}

	dupes := map[string]bool{}
	for id, n := range count {
		if n > 1 {
			dupes[id] = true
		}
	}
	for _, id := range sortedKeys(dupes) {
		t.Errorf("web/index.html declares id=%q %d times. getElementById returns the first "+
			"in document order, so every later copy is dead markup — and which one wins "+
			"depends on where in the file it sits.", id, count[id])
	}
}

// The two ids app.js builds rather than writes out: `tab-${target}` in switchTab and
// `snippet-${snip}` in the API tab. Neither can be seen by the scan above, and both fail
// the same quiet way — switchTab hides every .tab-content and then unhides `tab-<target>`
// only `if (targetEl)`, so a tab whose panel is missing leaves the operator on a blank
// page with the nav item highlighted.
//
// The set of values those templates can take is not open-ended: `target` comes from a
// data-tab attribute or from routeTabs, and `snip` from a data-snippet attribute. So the
// check is a closed one, in both directions.
func TestDashboardTabsAndPanelsAgree(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")
	declared := dashIDSet(t, html)

	// tabButtons counts a tab's nav items; tabSeen is the same key set, in the shape
	// sortedKeys takes, so the failures come out in a stable order.
	tabButtons := map[string]int{}
	tabSeen := map[string]bool{}
	snippetButtons := map[string]bool{}
	for _, m := range dashDataAttrRe.FindAllStringSubmatch(html, -1) {
		if m[1] == "tab" {
			tabButtons[m[2]]++
			tabSeen[m[2]] = true
		} else {
			snippetButtons[m[2]] = true
		}
	}
	if len(tabButtons) == 0 || len(snippetButtons) == 0 {
		t.Fatalf("found %d data-tab and %d data-snippet values in web/index.html — the "+
			"scan is broken", len(tabButtons), len(snippetButtons))
	}

	routes := dashJSObject(t, app, "tabRoutes")
	tabs := map[string]bool{}
	for _, k := range values(dashJSKeyRe, routes) {
		tabs[k] = true
	}

	for _, tab := range sortedKeys(tabs) {
		if !declared["tab-"+tab] {
			t.Errorf("tabRoutes has %q but web/index.html has no #tab-%s panel. switchTab "+
				"hides every .tab-content and only unhides the target if it exists, so "+
				"selecting this tab blanks the page.", tab, tab)
		}
		// Two: the sidebar on desktop and the bottom bar on mobile. A tab reachable
		// from only one of them is invisible on the other form factor.
		if tabButtons[tab] < 2 {
			t.Errorf("tab %q has %d data-tab button(s) in web/index.html, want at least 2 "+
				"— the sidebar item and the mobile bottom-bar item.", tab, tabButtons[tab])
		}
	}

	// The other direction. A nav item whose value is not a tabRoutes key still switches
	// the panel, but `if (updateUrl && tabRoutes[target])` then skips the pushState, so
	// the address bar keeps pointing at the previous tab — and a reload lands the operator
	// somewhere other than where they were.
	for _, tab := range sortedKeys(tabSeen) {
		if !declared["tab-"+tab] {
			t.Errorf("web/index.html has a data-tab=%q button but no #tab-%s panel to show.", tab, tab)
		}
		if !tabs[tab] {
			t.Errorf("web/index.html has a data-tab=%q button but tabRoutes in js/app.js has "+
				"no entry for it, so selecting it does not update the URL and a reload "+
				"returns to whichever tab the address bar still names.", tab)
		}
	}

	// routeTabs is the inverse map, consulted on load and on popstate. A value that is not
	// a tabRoutes key sends switchTab an id that has no panel.
	for _, tab := range values(dashJSValRe, dashJSObject(t, app, "routeTabs")) {
		if !tabs[tab] {
			t.Errorf("routeTabs maps a path to tab %q, which tabRoutes does not define.", tab)
		}
	}

	for _, snip := range sortedKeys(snippetButtons) {
		if !declared["snippet-"+snip] {
			t.Errorf("web/index.html has a data-snippet=%q button but no #snippet-%s panel, "+
				"so that language's example never appears.", snip, snip)
		}
	}
}

// switchTab pushes a clean path with history.pushState, and handleRouteFromURL reads
// window.location back on load and on popstate. Between the two, every key of routeTabs is
// a URL a browser can be pointed at directly — from a bookmark, from a reload, from the
// operator typing it — and the server has to answer index.html for all of them or the SPA
// never gets a chance to route.
//
// Three of them used to 404: /policy, /stream and /connect, the aliases routeTabs accepts
// alongside the /rules, /logs and /guide paths that switchTab actually pushes. Nothing in
// the panel links to them, so no amount of clicking through the UI finds it; the bug only
// shows up for someone who typed a URL that the front-end router plainly claims to know.
//
// Derived from app.js rather than listed here, so the two sides cannot drift apart again:
// adding a route to routeTabs and forgetting spaRoutes in server.go fails this test.
func TestDashboardCleanURLsAreServed(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	handler := ws.buildAdminHandler()
	app := readAsset(t, "js/app.js")

	paths := values(dashJSKeyRe, dashJSObject(t, app, "routeTabs"))
	if len(paths) < 8 {
		t.Fatalf("only %d routeTabs entries parsed out of js/app.js — the scan is broken", len(paths))
	}

	// "/" is in the SPA route table of the admin mux — after the outer router
	// strips <admin-path>/dash, "/" is the dashboard document itself. It is
	// checked by the admin-namespace tests (landing_test.go), not here, and the
	// public root is the Matrix landing page.
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200. js/app.js routes this path, so a browser can be "+
				"pointed straight at it — add it to spaRoutes in server.go.", path, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), `id="tab-dashboard"`) {
			t.Errorf("GET %s returned 200 but not the dashboard document, so the SPA router "+
				"never runs on it.", path)
		}
	}
}

// dashInteractiveRe matches an interactive element that carries an id. [^>]* cannot cross the
// tag's own ">", so an element without an id simply does not match — and the attribute order
// in index.html varies, which is why the id is not anchored to a fixed position.
var dashInteractiveRe = regexp.MustCompile(`<(button|input|select|textarea)[^>]*\sid="([a-zA-Z0-9_-]+)"`)

// The mirror of TestDashboardElementLookupsResolve. That one walks JS → HTML and catches a
// handler bound to an id nobody declares; this one walks HTML → JS and catches the opposite:
// a control sitting in the panel that no line of JavaScript ever names. There is no form
// submission behind any of these — the four <form>s bind their own submit handlers, and every
// other control is wired by id — so an unnamed id is a button that does nothing when clicked,
// or an input whose value is never read.
//
// This is a weaker property than "the control works": stream-filter and stream-search were
// both read by name for months while doing nothing observable, because they were read at the
// wrong moment (TestStreamFilterControlsRerenderExistingRows is what pins that). But it is an
// exact property, it costs one scan, and it is the check that would have flagged a control
// added to the markup during a design pass and never connected to anything.
func TestDashboardInteractiveElementsAreWired(t *testing.T) {
	app := readAsset(t, "js/app.js")
	// The v2.1 panels live in ES modules; their ids are wired there. Every JS
	// file the dashboard ships is part of the wiring surface, so the scan
	// covers them all.
	v21 := readAsset(t, "js/modules/twofa.js")
	html := readAsset(t, "index.html")

	ids := map[string]bool{}
	for _, m := range dashInteractiveRe.FindAllStringSubmatch(html, -1) {
		ids[m[2]] = true
	}
	if len(ids) < 90 {
		t.Fatalf("only %d interactive ids found in web/index.html — the scan is broken, which "+
			"would make this test vacuously pass", len(ids))
	}

	for _, id := range sortedKeys(ids) {
		wired := false
		for _, js := range []string{app, v21} {
			if strings.Contains(js, "'"+id+"'") || strings.Contains(js, `"`+id+`"`) {
				wired = true
				break
			}
		}
		if wired {
			continue
		}
		t.Errorf("web/index.html declares the control #%s, which js/app.js never names.\n"+
			"Nothing submits a form here, so an id the script does not mention is a button "+
			"that does nothing when clicked or a field whose value is never read — and neither "+
			"reports anything to the console. Wire it, or take it out of the markup.", id)
	}
}

// routeTabs, so /Clients and /clients/ have always been the clients tab as far as the
// front end is concerned. The server used to match the raw path, so both 404'd — and a
// trailing slash is one keystroke, or one proxy that normalises directory-looking URLs.
//
// The second half of this test is the more important half: the normalisation has to stay
// exactly as wide as the front end's and no wider, or the panel starts answering 200 on
// paths that should be a plain 404.
func TestDashboardCleanURLsToleratePathVariants(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	handler := ws.buildAdminHandler()

	for _, path := range []string{"/clients/", "/Clients", "/CLIENTS/", "/policy/", "/home/", "/Settings"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 — app.js routes this exact string to a tab.", path, w.Code)
		}
	}

	for _, path := range []string{"/clientsx", "/clients/extra", "/clients/1", "/rulesss"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404. Only the paths app.js actually routes may serve "+
				"the panel; everything else is a missing asset.", path, w.Code)
		}
	}
}
