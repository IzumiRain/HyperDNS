package web

import (
	"regexp"
	"strings"
	"testing"
)

// Every list on the dashboard is filled by JavaScript after a fetch, and every one of them used
// to start life as an empty container holding nothing but `<!-- Dynamically populated -->`. That
// is not a neutral state to render. An empty list does not say "not loaded yet" to whoever is
// reading it; it says "there is nothing in here", and for these particular lists that sentence is
// a claim about the operator's own server:
//
//   - #clients-list empty reads as "your subscribers are gone". On a reseller install that is the
//     single most alarming thing the panel can say, and it was said by a 500 or a dropped
//     connection on the first load — loadClients answered a failure with `return` and a console
//     line, so the grid stayed blank with nothing to indicate a request had failed at all.
//   - #custom-blocked-list empty reads as "nothing is blocked".
//   - #upstreams-list empty reads as "no upstreams configured" — renderUpstreams prints exactly
//     that sentence for an empty array, and the blank container before the first stats poll is
//     indistinguishable from it.
//
// The fix is in two halves and this file pins both: the markup ships a loading notice instead of
// an empty container, and the loaders report a failure in the panel rather than leaving the last
// state — or no state — on screen.

// loadingBody returns the start of a container's body: everything between its opening tag's ">"
// and the FIRST "</div>". For a container holding a nested placeholder that is a truncated body,
// not the whole one — which is fine, because the only question asked of it is whether anything at
// all renders there. Truncation can only make a non-empty body look shorter, never make an empty
// one look filled, so the direction of any inaccuracy is a missed failure and not a false alarm.
func loadingBody(t *testing.T, html, id string) string {
	t.Helper()

	re := regexp.MustCompile(`(?s)<div\s[^>]*id="` + regexp.QuoteMeta(id) + `"[^>]*>(.*?)</div>`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("web/index.html has no <div id=%q>, so this test cannot check what it shows "+
			"before its fetch lands", id)
	}
	return m[1]
}

// loadingCommentRe matches an HTML comment, which is what these containers used to hold in place
// of content. A comment renders as nothing, so a body that is only comments is an empty body.
var loadingCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)

// jsFilledLists are the containers app.js populates from a fetch, each with what an empty one
// would be telling the operator. They are listed rather than derived because the point of each
// entry is the sentence next to it: someone has to have read the panel and decided what its
// blank state claims. The two assertions below keep the list honest — an id that index.html no
// longer declares, or that app.js no longer writes to, fails instead of silently guarding
// nothing.
var jsFilledLists = map[string]string{
	"clients-list":        `an empty subscriber grid reads as "your clients are gone"`,
	"upstreams-list":      `an empty upstream list is indistinguishable from renderUpstreams' own "No upstreams configured"`,
	"custom-proxied-list": `an empty proxy list reads as "nothing is being routed through the proxy"`,
	"custom-blocked-list": `an empty blocklist reads as "nothing is blocked"`,
	"custom-records-list": `an empty record list reads as "no static overrides are set"`,
	"tokens-list":         `an empty token list reads as "no DoH tokens exist", i.e. that the endpoint is open`,
}

func TestJSFilledListsShipALoadingStateRatherThanAnEmptyContainer(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")

	for id, claim := range jsFilledLists {
		body := loadingBody(t, html, id)
		if strings.TrimSpace(loadingCommentRe.ReplaceAllString(body, "")) == "" {
			t.Errorf("#%s ships empty in web/index.html. Until its fetch lands — and forever if "+
				"that fetch fails — the panel is blank, and %s.\nPut a loading notice in the "+
				"container; every renderer here overwrites innerHTML outright, so it costs one "+
				"paint.", id, claim)
		}

		// And app.js has to still be the thing that fills it, or the entry above is guarding a
		// container nobody writes to any more.
		if !strings.Contains(app, "'"+id+"'") {
			t.Errorf("js/app.js no longer mentions '%s'. If the panel was removed, drop it from "+
				"jsFilledLists; if it was renamed, rename it here too.", id)
		}
	}
}

// loadConfig fetched /api/auth/me and /api/config, checked each one for 401, and then called
// res.json() whatever the status was. On a 500 the JSON error body parsed fine, so currentConfig
// became {error: "…"} — truthy, which is the whole of saveRules' guard — and renderConfig read
// cfg.rules?.enable_riot off it, got undefined for every preset, and painted the entire policy
// grid as OFF.
//
// That is the failure mode worth a test of its own, because it is not a display bug. The screen
// is plausible: every game switch off, as though the operator had turned them off. One press of
// Save then reads those switches with getSwitch and writes the false values back. A transient 500
// on a status probe, plus one ordinary click, disables every game preset on the server.
func TestConfigLoadRefusesToRenderAResponseItDidNotCheck(t *testing.T) {
	body := functionBody(t, readAsset(t, "js/app.js"), "loadConfig")

	for _, want := range []struct{ src, why string }{
		{"if (!res.ok) {", "a non-401 failure on /api/auth/me has to stop the load. " +
			"meData.password_weak is undefined in an error body, so the forced credential-change " +
			"modal was skipped whenever its own probe broke — a gate opening because the check " +
			"for it failed"},
		{"if (!cfgRes.ok) {", "a non-401 failure on /api/config has to stop the load before the " +
			"body is parsed"},
	} {
		if !strings.Contains(body, want.src) {
			t.Errorf("loadConfig does not contain %q — %s.", want.src, want.why)
		}
	}

	// Order is the property, not presence: a guard after the render is not a guard.
	guard := strings.Index(body, "if (!cfgRes.ok) {")
	render := strings.Index(body, "renderConfig(currentConfig);")
	if guard < 0 || render < 0 {
		t.Fatal("loadConfig no longer has both the ok guard and the renderConfig call — the scan " +
			"is broken, which would make the ordering check below vacuous")
	}
	if guard > render {
		t.Error("loadConfig checks cfgRes.ok after it has already rendered. The point of the " +
			"guard is that a config which did not arrive is never painted over a config that did.")
	}
}

// A failed read and an empty list have to look different. loadClients answered both with a blank
// grid, which is the wrong one of the two to show by default.
func TestClientLoadReportsFailureInThePanel(t *testing.T) {
	app := readAsset(t, "js/app.js")
	body := functionBody(t, app, "loadClients")

	for _, want := range []struct{ src, why string }{
		{"if (res.status === 401) {", "an expired session is not a failure of this endpoint, and " +
			"the answer to it is the login gate rather than an error drawn inside a panel that " +
			"sits behind it"},
		{"clientsPanelMessage('alert-triangle'", "a refused read has to say so in the grid, not " +
			"leave it blank"},
		{"clientsPanelMessage('wifi-off'", "a dropped connection has to say so too — the catch " +
			"branch used to be console.error and nothing else"},
		{"escapeHTML(msg)", "the message is the server's own error text and clientsPanelMessage " +
			"assigns innerHTML"},
		{".clients-placeholder", "the loading state may only be painted when the grid is not " +
			"already showing subscriber cards, or every mutation would flash the whole list away"},
	} {
		if !strings.Contains(body, want.src) {
			t.Errorf("loadClients does not contain %q — %s.", want.src, want.why)
		}
	}

	// The class is load-bearing in three places — the helper and the two empty states — plus the
	// static notice in the markup. If a notice is added without it, loadClients will read that
	// notice as a populated grid and stop showing its loading state.
	if n := strings.Count(app, `class="clients-placeholder`); n < 3 {
		t.Errorf("js/app.js builds only %d element(s) carrying clients-placeholder; expected the "+
			"helper and both empty states. A notice that omits the class is counted as a "+
			"subscriber card.", n)
	}
	if n := strings.Count(readAsset(t, "index.html"), `class="clients-placeholder`); n != 1 {
		t.Errorf("web/index.html builds %d element(s) carrying clients-placeholder, want exactly "+
			"1 — the static notice inside #clients-list.", n)
	}
}
