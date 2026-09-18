package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	webAssets "hyperdns/web"
)

// The dashboard's Content-Security-Policy carries two relaxations — 'unsafe-inline'
// and 'unsafe-eval' — and both exist for specific, removable reasons. The failure
// mode this file guards against is not a wrong policy; it is a policy that stays
// loose after the thing it was loosened for is gone, or markup that quietly adds a
// new dependency on the looseness. Neither shows up as a broken page, which is
// exactly why it needs a test rather than a note.
//
// These read the embedded assets, so they assert what a browser is actually served
// rather than what is sitting in the working tree.

func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(webAssets.StaticFS, name)
	if err != nil {
		t.Fatalf("reading embedded %s: %v", name, err)
	}
	return string(b)
}

func assetExists(name string) bool {
	_, err := fs.ReadFile(webAssets.StaticFS, name)
	return err == nil
}

// cssCommentRe strips /* … */ so the checks below read what a browser parses rather
// than what the file documents. style.css explains at length why its Google Fonts
// @import was removed, and a naive substring search would report that explanation as
// the very thing it warns about.
var cssCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)

func readCSSRules(t *testing.T, name string) string {
	t.Helper()
	return cssCommentRe.ReplaceAllString(readAsset(t, name), "")
}

// inlineHandlerRe matches an HTML event-handler attribute: a word boundary, "on",
// letters, then "=". The leading [\s"'] is what keeps it from matching inside a word
// like "button" or a JS property such as elem.onclick, since only an attribute is
// preceded by whitespace or a quote in markup.
var inlineHandlerRe = regexp.MustCompile(`[\s"']on[a-z]+\s*=`)

// index.html's four inline copy handlers became one delegated listener in app.js.
// That was not tidying: an inline handler is the reason 'unsafe-inline' has to stay in
// script-src, and a policy that permits inline script permits whatever inline script
// an injection manages to place — which is most of what the CSP is for. Adding one
// back is a silent regression of that work, so it fails here.
//
// app.js is checked too, and for the same reason: it renders most of the dashboard's
// dynamic markup, so a handler attribute written into one of its template strings
// blocks the policy exactly as much as one in the static document.
func TestDashboardCarriesNoInlineEventHandlers(t *testing.T) {
	html := readAsset(t, "index.html")
	app := readAsset(t, "js/app.js")

	for _, f := range []struct{ name, body string }{
		{"index.html", html},
		{"js/app.js", app},
		// i18n.js writes attributes onto live elements — title, aria-label, data-feather —
		// so it is exactly the kind of file where an on* would arrive by accident.
		{"js/i18n.js", readAsset(t, "js/i18n.js")},
	} {
		if found := inlineHandlerRe.FindAllString(f.body, -1); len(found) != 0 {
			t.Errorf("%s has %d inline event handler(s): %v\n"+
				"Use a delegated listener with a data- attribute instead — inline "+
				"handlers are what keep 'unsafe-inline' in the CSP.",
				f.name, len(found), found)
		}
	}

	// And the replacement has to actually be wired, or removing the attributes would
	// have silently broken the copy buttons in the setup guide.
	for _, id := range []string{
		"guide-win-ip", "guide-console-ip", "guide-dot-hostname", "guide-doh-url",
	} {
		if !strings.Contains(html, `data-copy-target="`+id+`"`) {
			t.Errorf("no data-copy-target for %q — the copy box lost its handler", id)
		}
	}
	if !strings.Contains(app, `closest('[data-copy-target]')`) {
		t.Error("app.js has no delegated [data-copy-target] listener, so the guide's copy boxes do nothing")
	}
	// A focusable control with no visible focus state is a control a keyboard user
	// cannot find, and these boxes became focusable when they stopped being onclick
	// attributes.
	if !strings.Contains(readCSSRules(t, "css/style.css"), ".code-box:focus-visible") {
		t.Error("no .code-box:focus-visible rule — the copy boxes are tabbable with no visible focus ring")
	}
}

// 'unsafe-eval' is in the policy for exactly one file. js/tailwind.js is the Tailwind
// Play CDN's JIT engine: it compiles utility classes in the browser at runtime and
// cannot run without eval. When it is replaced by a purged, committed stylesheet, the
// relaxation has to go with it — and the way that gets forgotten is that removing the
// file breaks nothing visible, so nobody revisits the CSP. This ties the two
// together in both directions.
func TestUnsafeEvalIsTiedToTheJITEngine(t *testing.T) {
	jit := assetExists("js/tailwind.js")
	eval := strings.Contains(contentSecurityPolicy, "'unsafe-eval'")

	switch {
	case jit && !eval:
		t.Error("js/tailwind.js is embedded but the CSP has no 'unsafe-eval' — " +
			"the Play CDN engine cannot run, so the dashboard will render unstyled")
	case !jit && eval:
		t.Error("js/tailwind.js is no longer embedded, so 'unsafe-eval' has nothing " +
			"left to permit — remove it from contentSecurityPolicy")
	}

	// The engine is the single largest asset in the binary and the reason the page is
	// unstyled until JavaScript runs. Recording the size keeps that visible: a purge
	// is worth it, and this number is what it saves.
	if jit {
		size := len(readAsset(t, "js/tailwind.js"))
		if size < 300*1024 {
			t.Logf("js/tailwind.js is %d bytes — smaller than the Play CDN build; "+
				"if this is now a purged stylesheet, drop 'unsafe-eval'", size)
		}
	}
}

// scriptOpenRe captures a <script> start tag's attributes so a block with a src can be
// told from an inline one. </script> does not match: the "/" comes before "script".
var scriptOpenRe = regexp.MustCompile(`<script(\s[^>]*)?>`)

// Exactly one inline <script> block remains in index.html, and it is inline for a
// reason an external file cannot satisfy: the theme/language restore in <head>,
// which has to run before the first paint. Moving it to a file makes it a second
// round trip, and the flash of the wrong theme that would open every page load is
// the whole thing it exists to prevent.
//
// The second block that used to be here — the tailwind.config the JIT engine
// read out of the document — died with the JIT engine itself (v2.1): the utility
// set is the committed purged stylesheet now. Pinning the count means a new
// inline block cannot arrive unnoticed, which is what keeps 'unsafe-inline' from
// quietly regaining residents.
func TestInlineScriptBlocksAreAccountedFor(t *testing.T) {
	html := readAsset(t, "index.html")

	inline := 0
	for _, m := range scriptOpenRe.FindAllStringSubmatch(html, -1) {
		if !strings.Contains(m[1], "src=") {
			inline++
		}
	}

	if inline != 1 {
		t.Errorf("index.html has %d inline <script> block(s), want 1 (the pre-paint theme "+

			"restore).\nEvery inline block is a reason 'unsafe-inline' cannot be dropped; if a new "+

			"one is truly necessary, account for it here by name.", inline)
	}
	if !strings.Contains(html, "hyperdns_theme") {
		t.Errorf("no inline script contains %q — the pre-paint restore is gone or changed "+

			"shape; update this test to say what is there now.", "hyperdns_theme")
	}

	// The restore has to run before any external script: behind them it still sets
	// the attribute, but a paint can already have happened by then, which is the
	// flash it exists to prevent. The comparison is against the first <script src=>
	// tag — the restore's own opening tag necessarily precedes the string inside it.
	if restore, firstExternal := strings.Index(html, "hyperdns_theme"), strings.Index(html, `<script src=`); restore > firstExternal {
		t.Error("the pre-paint theme restore is no longer the first script in the document, so the panel can " +

			"paint in the wrong theme before the restore runs — put it back at the top of <head>.")
	}

	// The purged stylesheet must be linked: it is what replaced both the JIT
	// engine and its config block.
	if !strings.Contains(html, "/css/tailwind.purged.css") {
		t.Error("index.html does not link /css/tailwind.purged.css — the dashboard will render unstyled")
	}
}

// offOriginRe finds a resource URL that would be fetched from another host: an
// absolute http(s) URL or a protocol-relative one, inside a src or href attribute.
// Attribute-scoped on purpose — index.html's favicon is a data: URI containing the
// SVG namespace http://www.w3.org/2000/svg, which is an XML identifier and never
// fetched, and a bare search for "http" would report it forever.
var offOriginRe = regexp.MustCompile(`(?:src|href)\s*=\s*["'](?:https?:)?//[^"']+`)

// "100% offline, zero external CDN" is a claim the project makes, and it is the
// operational requirement behind it that matters: this panel is served from a VPS in
// Iran to a browser at home, and any third-party host in the critical path is a host
// that is frequently unreachable from one end or the other. It is also a privacy
// claim — a CDN in the page tells that CDN who administers this resolver and when.
func TestDashboardLoadsNothingOffOrigin(t *testing.T) {
	for _, name := range []string{"index.html", "css/style.css", "js/app.js", "js/i18n.js"} {
		body := readAsset(t, name)
		if found := offOriginRe.FindAllString(body, -1); len(found) != 0 {
			t.Errorf("%s references %d off-origin resource(s): %v", name, len(found), found)
		}
	}
}

// style.css opened with an @import of three Google Fonts families for the whole life
// of the project, and it had never once loaded: style-src is 'self' 'unsafe-inline'
// and font-src is 'self' data:, so the project's own policy refused the request on
// every single page load and logged a violation for it. The panel had always been
// drawing with the fallback stacks. Re-adding it would not look broken — it would
// look exactly like this — which is why the guard is a test and not a comment.
func TestStylesheetFetchesNoWebfontsTheCSPWouldRefuse(t *testing.T) {
	css := readCSSRules(t, "css/style.css")

	if strings.Contains(css, "@import") {
		t.Error("css/style.css has an @import. Nothing off-origin can load under this " +
			"CSP, and an @import of a local file should just be part of the file.")
	}
	for _, host := range []string{"fonts.googleapis.com", "fonts.gstatic.com", "cdn.jsdelivr.net", "unpkg.com"} {
		if strings.Contains(css, host) {
			t.Errorf("css/style.css references %s — blocked by font-src/style-src 'self'", host)
		}
	}

	// The three families are still named first in the stacks so that self-hosting
	// them later is purely additive: a @font-face block plus .woff2 files under css/,
	// which font-src 'self' already permits, and no policy change.
	for _, prop := range []string{"--font-body:", "--font-heading:", "--font-mono:"} {
		if !strings.Contains(css, prop) {
			t.Errorf("css/style.css no longer defines %s — the font stacks are the "+
				"replacement for the blocked @import and are what actually renders", prop)
		}
	}
}
