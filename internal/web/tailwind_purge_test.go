package web

import (
	"regexp"
	"strings"
	"testing"
)

// The class-inventory test (rework Phase 4).
//
// The dashboard's utility classes were compiled ahead of time into
// css/tailwind.purged.css by tools/tailwind.config.js. Unlike the Play CDN JIT
// engine it replaced, that stylesheet cannot see markup that arrives later: a
// class added to index.html, or built inside one of app.js's template strings,
// simply does not exist — and the failure is silent, because an unknown class
// is not an error to a browser, it is an unstyled control.
//
// So the inventory is checked here, against the bytes the browser is served.
// Every candidate token in the markup and the JS is matched against the
// selectors the purged stylesheet actually defines; custom classes
// (.glass-panel, .badge, the state classes style.css owns) are exempt, because
// their definitions live in style.css and are covered by the rest of this
// suite. A token Tailwind could generate but the purge missed fails with the
// regeneration command in the message.

// twTokenRe extracts class attribute values from HTML/JS text. It runs over
// class= and className= forms and splits on whitespace; template-literal
// interpolations inside the attributes are skipped (the dynamic values are
// safelisted in tools/tailwind.config.js and therefore present in the output).
var twTokenRe = regexp.MustCompile(`class(?:Name)?\s*=\s*("[^"]*"|'[^']*'|\x60[^\x60]*\x60)`)

// TestEveryUtilityClassSurvivedThePurge walks the served markup and the served
// JS, extracts every class token, and requires each Tailwind-shaped token to
// appear as a selector (or an @media-wrapped selector) in the purged
// stylesheet.
//
// What counts as "Tailwind-shaped": a token that is not already defined by
// style.css. The custom classes (.glass-panel, .badge, .pulse-dot, the JS
// delegation hooks like .edit-client-btn) all live in style.css, so they are
// read out of that stylesheet itself rather than listed here — the allowlist
// cannot drift from the definitions.
func TestEveryUtilityClassSurvivedThePurge(t *testing.T) {
	html := readAsset(t, "index.html")
	app := readAsset(t, "js/app.js")
	i18n := readAsset(t, "js/i18n.js")
	css := readCSSRules(t, "css/tailwind.purged.css")
	baseCSS := readCSSRules(t, "css/style.css")
	// The document's own <style> blocks are a third definition source, and
	// ignoring them made this test report a false miss for every class defined
	// there. .skip-link is deliberately inline: it must be styled before the
	// external sheets load, or the first Tab press on a cold cache reveals a
	// "Skip to main content" link sitting on top of the page.
	inlineCSS := inlineStyleCSS(html)

	if css == "" {
		t.Fatal("css/tailwind.purged.css is empty — the purge output was not embedded")
	}

	// Custom classes = every class selector style.css defines, plus the ones the
	// document defines inline.
	custom := map[string]bool{}
	for _, m := range styleClassRe.FindAllStringSubmatch(baseCSS+inlineCSS, -1) {
		custom[m[1]] = true
	}
	// Structural hooks that are neither in style.css nor Tailwind utilities.
	custom["dark"] = true  // darkMode:'class' hook the theme restore toggles
	custom["group"] = true // Tailwind group markers are styling containers
	custom["peer"] = true
	// Panels the JS shows/hides by class rather than styles by it.
	custom["tab-content"] = true
	custom["api-snippet-content"] = true
	custom["api-snippet-tab"] = true
	// JS delegation hooks: ids-as-classes app.js binds listeners through
	// (classList or querySelector). Their "styling" is the listener; the
	// conventional suffixes make them recognisable without a hand-kept list.
	for _, m := range twTokenRe.FindAllStringSubmatch(app, -1) {
		for _, tok := range strings.Fields(strings.Trim(m[1], "\"'`")) {
			if jsHookSuffixRe.MatchString(tok) {
				custom[tok] = true
			}
		}
	}

	missing := map[string]bool{}
	seen := 0
	for _, src := range []struct{ name, body string }{
		{"index.html", html}, {"js/app.js", app}, {"js/i18n.js", i18n}, {"js/modules/twofa.js", readAsset(t, "js/modules/twofa.js")},
	} {
		for _, m := range twTokenRe.FindAllStringSubmatch(src.body, -1) {
			raw := strings.Trim(m[1], "\"'`")
			for _, tok := range strings.Fields(raw) {
				// Fragments: template-literal boundaries (${…}), closing braces
				// and quotes from interpolated class strings, stray punctuation
				// from the scanner crossing a quote. None of them is a class.
				if tok == "" || strings.ContainsAny(tok, "${}'\"`?:") {
					continue
				}
				seen++
				if custom[tok] {
					continue
				}
				if classDefinedIn(css, tok) || classDefinedIn(baseCSS, tok) {
					continue
				}
				missing[tok] = true
			}
		}
	}

	if len(missing) != 0 {
		names := make([]string, 0, len(missing))
		for tok := range missing {
			names = append(names, tok)
		}
		t.Errorf("%d utility class(es) used by the dashboard are missing from the purged "+
			"stylesheet: %v\nRe-run the purge and commit the output:\n"+
			"  npx tailwindcss@3.4.17 -c tools/tailwind.config.js -i tools/tailwind.input.css "+
			"-o web/css/tailwind.purged.css --minify\n"+
			"(and add any new variable-built state class to the safelist first).",
			len(names), names)
	}
	if seen < 400 {
		t.Errorf("only %d class tokens extracted — the scanner is broken and this test "+
			"is passing in silence", seen)
	}
}

// styleClassRe extracts a class name from a CSS selector like ".glass-panel" or
// "code, pre, .font-mono". Only the definition side matters.
var styleClassRe = regexp.MustCompile(`\.([a-zA-Z][a-zA-Z0-9_-]*)`)

// inlineStyleBlockRe captures the body of each <style> element in a document.
var inlineStyleBlockRe = regexp.MustCompile(`(?is)<style[^>]*>(.*?)</style>`)

// inlineStyleCSS concatenates every inline <style> body in the document, so a
// class defined there counts as defined. A document's own stylesheet is as real
// as an external one; treating it as absent turned a deliberate pre-paint rule
// into a phantom purge failure.
func inlineStyleCSS(html string) string {
	var out strings.Builder
	for _, m := range inlineStyleBlockRe.FindAllStringSubmatch(html, -1) {
		out.WriteString(m[1])
		out.WriteByte('\n')
	}
	return out.String()
}

// jsHookSuffixRe recognises the class names app.js uses as listener hooks —
// element classes that exist to be queried, not styled. Their styling comes
// from the surrounding utility classes in the same attribute.
var jsHookSuffixRe = regexp.MustCompile(`-(btn|placeholder|item|tab|content|filter|tag|prompt|record|upstream|token|proxied|blocked)$`)

// classDefinedIn reports whether the class has a selector in the given CSS.
// Tailwind escapes ':' as '\:' and '/' as '\/' in its selectors, and variant
// selectors wrap the class in pseudo-classes, so the check is a containment
// search for the escaped class name — precise enough to be meaningful (a class
// that is not in the stylesheet cannot be a substring of it) and loose enough
// not to break on variant prefixes or media wrapping.
func classDefinedIn(css, tok string) bool {
	escaped := escapeClassForCSS(tok)
	return strings.Contains(css, "."+escaped)
}

// escapeClassForCSS applies the escapes Tailwind uses in selectors.
func escapeClassForCSS(tok string) string {
	r := strings.NewReplacer(":", `\:`, "/", `\/`, ".", `\.`, "[", `\[`, "]", `\]`, "%", `\%`, "(", `\(`, ")", `\)`, "#", `\#`, ",", `\,`, "'", `\'`)
	return r.Replace(tok)
}

// TestPurgedStylesheetIsNotTheWholeFramework guards the reason the purge
// exists: the stylesheet must be a fraction of the JIT engine it replaced. If
// this grows past a tenth of the old engine's size, the content list or the
// safelist has rotted.
func TestPurgedStylesheetIsNotTheWholeFramework(t *testing.T) {
	size := len(readAsset(t, "css/tailwind.purged.css"))
	// The Play CDN build this replaced measured ~397 KB. A healthy purge of
	// this dashboard lands near 40 KB minified (with preflight); 100 KB is
	// already suspicious.
	if size > 100*1024 {
		t.Errorf("css/tailwind.purged.css is %d bytes — the purge has rotted (the JIT "+
			"engine it replaced was ~397 KB). Re-check tools/tailwind.config.js's content "+
			"and safelist.", size)
	}
}
