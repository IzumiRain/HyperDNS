package web

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The subscriber portal is a template constant in portal.go, a stylesheet in
// web/css/portal.css, and a script in web/js/portal.js — three files that the Go
// toolchain has no way of checking against each other. A class renamed in one and not
// the other compiles, embeds, serves, and 200s; the page just loses a card's styling
// for whoever opens it next. This file is the check that does not exist otherwise.
//
// It matters more here than on the dashboard for two reasons. The portal has no
// framework to fall back on — there is no JIT engine to invent a missing utility, so
// an undefined class is simply unstyled — and it is the one page served to a
// stranger: a subscription link is public by construction, and the person opening it
// is a reseller's customer on a phone, not an operator who can read a console.
//
// A framework also cannot be half removed. The Tailwind Play CDN engine, the blocked
// Google Fonts <link>, the inline <style>, the inline <script> and fifteen onclick
// attributes all left the portal in one change; what keeps them from drifting back in
// one at a time is that each of those things fails a test below rather than looking
// fine in a browser.
var portalTemplateSources = []struct {
	name string
	body string
}{
	{"portalPageHTML", portalPageHTML},
	{"portalErrorHTML", portalErrorHTML},
}

// classAttrRe captures the value of a class attribute. Double quotes only, which is
// the one form the templates use — a single-quoted variant appearing later would slip
// past the inventory, so TestPortalClassesAreDefinedAndUsed also rejects class='…'.
var classAttrRe = regexp.MustCompile(`class="([^"]*)"`)

// cssRuleHeadRe captures everything up to a "{": the selector list of a rule, or the
// prelude of an at-rule. Neither "{" nor "}" can appear in the capture, so a
// declaration block cannot be mistaken for a selector.
var cssRuleHeadRe = regexp.MustCompile(`([^{}]*)\{`)

// cssClassRe matches one class name inside a selector. It finds "panel" and
// "is-hidden" in ".panel.is-hidden", "btn" in ".btn[aria-busy='true']", and "steps"
// in ".steps > li + li".
var cssClassRe = regexp.MustCompile(`\.(-?[A-Za-z_][A-Za-z0-9_-]*)`)

var (
	idAttrRe     = regexp.MustCompile(`\sid="([^"]*)"`)
	ariaRefRe    = regexp.MustCompile(`\saria-(?:controls|labelledby)="([^"]*)"`)
	styleOpenRe  = regexp.MustCompile(`<style(\s[^>]*)?>`)
	dataTabRe    = regexp.MustCompile(`\sdata-tab="([^"]*)"`)
	dataPanelRe  = regexp.MustCompile(`\sdata-panel="([^"]*)"`)
	tailwindRefs = []string{"tailwind", "fonts.googleapis.com", "fonts.gstatic.com", "cdn.jsdelivr.net", "unpkg.com"}
)

// classesUsed collects the class names written in body's class attributes.
func classesUsed(body string) map[string]bool {
	out := map[string]bool{}
	for _, m := range classAttrRe.FindAllStringSubmatch(body, -1) {
		for c := range strings.FieldsSeq(m[1]) {
			out[c] = true
		}
	}
	return out
}

// classesDefined collects the class names portal.css writes a rule for. At-rule
// preludes are skipped rather than parsed: the rules nested inside a @media or
// @supports block are captured on their own, because the regex resumes after each
// brace.
func classesDefined(css string) map[string]bool {
	out := map[string]bool{}
	for _, m := range cssRuleHeadRe.FindAllStringSubmatch(css, -1) {
		head := strings.TrimSpace(m[1])
		if head == "" || strings.HasPrefix(head, "@") {
			continue
		}
		for _, c := range cssClassRe.FindAllStringSubmatch(head, -1) {
			out[c[1]] = true
		}
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// values returns each capture-group-1 match of re in body, in order.
func values(re *regexp.Regexp, body string) []string {
	ms := re.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m[1])
	}
	return out
}

// The portal is served with the same Content-Security-Policy as the dashboard, and it
// is now the part of the app that needs none of that policy's relaxations. Every
// reason it used to need them was removed at once: the inline <script>, the inline
// <style>, the fifteen onclick attributes, the Play CDN engine, and the Google Fonts
// <link> the policy had always refused anyway. Re-adding any single one of them looks
// harmless and works in a browser, which is why each is a failure here instead.
//
// The regexes are csp_test.go's, deliberately: the dashboard and the portal are held
// to one definition of "inline handler" and "off-origin resource" rather than two that
// can drift.
func TestPortalTemplatesNeedNoCSPRelaxation(t *testing.T) {
	for _, tpl := range portalTemplateSources {
		if found := inlineHandlerRe.FindAllString(tpl.body, -1); len(found) != 0 {
			t.Errorf("%s has %d inline event handler(s): %v\n"+
				"Add a data- attribute and handle it in web/js/portal.js — the delegated "+
				"listener there is what let 'unsafe-inline' stop being load-bearing.",
				tpl.name, len(found), found)
		}
		if found := styleOpenRe.FindAllString(tpl.body, -1); len(found) != 0 {
			t.Errorf("%s has an inline <style> block: %v\nPut the rules in web/css/portal.css.",
				tpl.name, found)
		}
		for _, m := range scriptOpenRe.FindAllStringSubmatch(tpl.body, -1) {
			if !strings.Contains(m[1], "src=") {
				t.Errorf("%s has an inline <script%s> — every script the portal runs must "+
					"be a file under web/js/ so it is 'self', cacheable and gzipped", tpl.name, m[1])
			}
		}
		if found := offOriginRe.FindAllString(tpl.body, -1); len(found) != 0 {
			t.Errorf("%s loads %d off-origin resource(s): %v\nThis page is opened from "+
				"Iranian mobile networks; a third-party host in its critical path is a host "+
				"that is regularly unreachable, and default-src 'self' refuses it anyway.",
				tpl.name, len(found), found)
		}
		for _, ref := range tailwindRefs {
			if strings.Contains(tpl.body, ref) {
				t.Errorf("%s references %q again — the portal is styled by web/css/portal.css alone",
					tpl.name, ref)
			}
		}
		if !strings.Contains(tpl.body, `<link rel="stylesheet" href="/css/portal.css">`) {
			t.Errorf("%s does not link /css/portal.css, so it renders unstyled", tpl.name)
		}
	}

	// The error page needs no behaviour at all: it shows a reason and an IP. Shipping a
	// script tag on it would only widen what a page served to an unauthenticated
	// stranger can be made to do.
	if strings.Contains(portalErrorHTML, "<script") {
		t.Error("portalErrorHTML carries a <script> tag; the error page needs no JavaScript")
	}
	if !strings.Contains(portalPageHTML, `<script src="/js/portal.js"></script>`) {
		t.Error("portalPageHTML does not load /js/portal.js — the copy buttons, the tabs, " +
			"the countdown and the sync button are all inert without it")
	}
}

// The templates reference two files by URL, and a URL that names nothing is not an
// error a browser reports: the page still answers 200, unstyled and inert. web/embed
// is where that goes wrong quietly, because assets.go lists every file by name.
func TestPortalAssetsAreEmbeddedAndWired(t *testing.T) {
	for _, name := range []string{"css/portal.css", "js/portal.js"} {
		if !assetExists(name) {
			t.Fatalf("%s is not in the binary — add a //go:embed line to web/assets.go. "+
				"Nothing fails loudly without it: the portal keeps serving, with no styling "+
				"and no working buttons.", name)
		}
	}

	js := readAsset(t, "js/portal.js")
	for _, hook := range []string{"[data-copy]", "[data-tab]", "[data-reg]", "[data-expires]"} {
		if !strings.Contains(js, hook) {
			t.Errorf("js/portal.js handles no %s, so the markup that declares it does nothing", hook)
		}
	}

	// The bug the old inline script had, which no browser and no test would report: it
	// called navigator.clipboard.writeText on a page served over plain http — where the
	// API does not exist — and then showed "کپی شد!" unconditionally. The subscriber was
	// told the copy worked and their clipboard was untouched. Both paths have to stay.
	if !strings.Contains(js, "isSecureContext") || !strings.Contains(js, "execCommand") {
		t.Error("js/portal.js no longer carries both clipboard paths. This page is normally " +
			"served over plain http on a VPS address, so navigator.clipboard is absent for " +
			"most subscribers and the execCommand fallback is the one that runs.")
	}

	css := readCSSRules(t, "css/portal.css")
	if strings.Contains(css, "@import") {
		t.Error("css/portal.css has an @import. Nothing off-origin can load under this CSP, " +
			"and an @import of a local file should just be part of the file.")
	}
	// The font stacks are the replacement for the webfont link that never loaded. Naming
	// Vazirmatn first keeps self-hosting it additive — a @font-face plus a .woff2 under
	// css/, which font-src 'self' already permits.
	for _, prop := range []string{"--font-fa:", "--font-mono:"} {
		if !strings.Contains(css, prop) {
			t.Errorf("css/portal.css no longer defines %s — that stack is what actually "+
				"renders this all-Persian page", prop)
		}
	}
}

// The inventory, in both directions. A framework cannot be half removed, and this is
// what makes that checkable without a browser or a build step:
//
//   - every class the markup uses has a rule in portal.css, so a typo or a rename is a
//     failure rather than one card that quietly loses its border and padding;
//   - every rule in portal.css is used by the markup or applied by portal.js, so the
//     stylesheet cannot silently accumulate what the old Tailwind classes did — dead
//     rules that nobody can tell from live ones by reading either file.
//
// The second direction is the one a purge tool normally provides. Here the markup and
// the stylesheet are written by the same hand, so a test does it exactly and with no
// Node in the build.
func TestPortalClassesAreDefinedAndUsed(t *testing.T) {
	defined := classesDefined(readCSSRules(t, "css/portal.css"))
	if len(defined) == 0 {
		t.Fatal("no class rules found in css/portal.css — the selector scan is broken, " +
			"which would make every check below vacuously pass")
	}

	used := map[string]bool{}
	for _, tpl := range portalTemplateSources {
		if strings.Contains(tpl.body, "class='") {
			t.Errorf("%s writes class='…'; this inventory reads class=\"…\" only, so those "+
				"classes would go unchecked", tpl.name)
		}
		for _, v := range values(classAttrRe, tpl.body) {
			// A class name assembled from data cannot be checked here — and cannot be
			// greped for, purged, or reasoned about from the stylesheet either.
			if strings.Contains(v, "{{") {
				t.Errorf("%s builds a class attribute from a template action: %q", tpl.name, v)
			}
		}
		for c := range classesUsed(tpl.body) {
			used[c] = true
		}
	}

	js := readAsset(t, "js/portal.js")

	for _, c := range sortedKeys(used) {
		if !defined[c] {
			t.Errorf("class %q is used by the portal markup but has no rule in css/portal.css", c)
		}
	}
	for _, c := range sortedKeys(defined) {
		if used[c] {
			continue
		}
		// Some classes are only ever applied at runtime: .is-shown is added to the toast
		// by the script and never appears in the markup.
		if strings.Contains(js, "'"+c+"'") || strings.Contains(js, `"`+c+`"`) {
			continue
		}
		t.Errorf("class %q is defined in css/portal.css but used by neither the portal "+
			"markup nor js/portal.js — delete the rule or wire it up", c)
	}
}

// The script addresses the markup by id and by data- attribute, and every one of those
// names is a contract that no compiler sees. The three failures this pins down all
// existed in the shipped portal: ids the script wrote to that the markup had renamed
// (so a value simply stopped updating), a countdown whose numbers were server-rendered
// once and never moved, and a sync button that refreshed the IP while leaving the quota
// bar showing whatever the page was first drawn with.
func TestPortalMarkupWiringMatchesTheScript(t *testing.T) {
	page := portalPageHTML

	for _, id := range []string{
		"toast", "detected-ip", "traffic-display", "traffic-fill", "traffic-remaining",
		"quota-pill", "cd-days", "cd-hours", "cd-mins",
	} {
		if !strings.Contains(page, `id="`+id+`"`) {
			t.Errorf(`portalPageHTML has no id=%q — js/portal.js writes to it, so that `+
				`value would silently stop updating`, id)
		}
	}

	// The countdown's source of truth. Without it the three cells keep their first paint
	// forever, which is how "0 روز 4 ساعت" stayed at four hours past midnight.
	if !strings.Contains(page, `data-expires="{{.ExpiresUnix}}"`) {
		t.Error(`no data-expires="{{.ExpiresUnix}}" — the countdown cannot count`)
	}
	if !strings.Contains(page, `data-reg="{{.RegisterAPIPath}}"`) {
		t.Error(`no data-reg="{{.RegisterAPIPath}}" — the register button has no endpoint`)
	}
	if !strings.Contains(page, `id="register-secret"`) {
		t.Error(`no id="register-secret" — the register card has no secret field`)
	}

	// Two lists that have to name the same keys in the same order: the order is what the
	// arrow keys walk, and a tab whose key names no panel switches to nothing.
	tabs, panels := values(dataTabRe, page), values(dataPanelRe, page)
	if !slices.Equal(tabs, panels) {
		t.Errorf("data-tab keys %v do not match data-panel keys %v in order", tabs, panels)
	}
	if len(tabs) == 0 {
		t.Error("no data-tab keys at all — the device guide has no tabs")
	}

	// aria-controls and aria-labelledby are what pair a tab with its panel for a screen
	// reader. A dangling reference is announced as nothing at all.
	ids := map[string]bool{}
	for _, id := range values(idAttrRe, page) {
		ids[id] = true
	}
	for _, ref := range values(ariaRefRe, page) {
		if !ids[ref] {
			t.Errorf("aria reference to id %q, which no element in portalPageHTML has", ref)
		}
	}

	// First paint, before any script runs: one tab selected, one panel visible, one tab
	// in the tab order. Two visible panels is not a subtle bug — the guide shows two
	// devices' instructions stacked — but it only appears if someone opens the page.
	activeTabs, visiblePanels := 0, 0
	for _, v := range values(classAttrRe, page) {
		tokens := strings.Fields(v)
		if slices.Contains(tokens, "tab") && slices.Contains(tokens, "is-active") {
			activeTabs++
		}
		if slices.Contains(tokens, "panel") && !slices.Contains(tokens, "is-hidden") {
			visiblePanels++
		}
	}
	if activeTabs != 1 {
		t.Errorf("%d tabs carry .is-active, want exactly 1", activeTabs)
	}
	if visiblePanels != 1 {
		t.Errorf("%d panels are visible on first paint, want exactly 1", visiblePanels)
	}
	if got := strings.Count(page, `aria-selected="true"`); got != 1 {
		t.Errorf(`%d elements have aria-selected="true", want exactly 1`, got)
	}
	if got := strings.Count(page, `tabindex="0"`); got != 1 {
		t.Errorf(`%d elements have tabindex="0", want exactly 1 — the rest of the tablist `+
			`is reached with the arrow keys, not with Tab`, got)
	}
}
