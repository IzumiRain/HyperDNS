package web

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The dashboard renders almost all of its dynamic markup by assigning template
// literals to innerHTML, and most of the values it interpolates are free text an
// operator — or anything holding the API key, such as the Telegram provisioner — can
// set: a client's name, note and UUID, a blocklist entry, a static record's domain, an
// upstream address. A name of `<img src=x onerror=…>` used to execute inside the
// authenticated panel, with the operator's own session cookie, on the page that also
// holds the API key and the admin password form.
//
// There is no JavaScript test runner in this project and no Node in the build, so these
// tests read the embedded script and assert the property statically. That is weaker than
// executing the renderer, but it catches the regression that actually happens: someone
// adds a field to a card template and writes ${c.whatever} because every line around it
// looks like that. The check runs in the same `go test ./...` as everything else, which
// is the whole reason it is written this way rather than not at all.

// attrRe matches an HTML attribute with a double-quoted value. app.js writes its JS
// strings with single quotes and its markup with double quotes, so a match containing
// "${" is always an attribute inside a template literal.
//
// The value excludes newlines as well as quotes, which keeps the match line-local: a
// stray unclosed `="` somewhere in the file cannot otherwise swallow half a template and
// report a text-position interpolation as an attribute. An interpolated expression that
// itself contained a double quote would cut the value short — none does today, and that
// direction is under-detection rather than a false alarm.
var attrRe = regexp.MustCompile(`([a-zA-Z-]+)="([^"\n]*)"`)

// interpRe matches one ${…} interpolation. Nested braces would break it; the templates
// here interpolate expressions, not object literals.
var interpRe = regexp.MustCompile(`\$\{([^}]*)\}`)

// safeAttrInterp lists every attribute interpolation that is deliberately not escaped,
// with the reason it cannot carry stored data. The list is exact and short on purpose:
// a new entry means someone had to look at the value and decide, which is the point.
var safeAttrInterp = map[string]string{
	"removeClass": "a CSS class name chosen by renderList's caller, not data",
	"badgeClass":  "a CSS class name computed from a latency number",
	"dotClass":    "a CSS class name computed from a latency number, in renderUpstreams",
	"latTitle":    "one of two literals in renderUpstreams, chosen by whether the latency was measured",
	"usedClass":   "a CSS class name computed from a traffic percentage, in the client card",
	"actionCls":   "a CSS class name from renderCustomGroups' fixed proxy/direct/block colour map",
	"tone.icon":   "a Feather icon name, a literal in showDialog's tone table",
	"icon":        "a Feather icon name, a literal at each of clientsPanelMessage's call sites",
	"titleClass":  "a CSS class name, a literal at each of clientsPanelMessage's call sites",
	"!c.enabled":  "a boolean",
	"i":           "a loop index in the hour/minute pickers",
	"d":           "a day number in the datepicker grid",
	"c.enabled ? 'Disable Client' : 'Enable Client'": "two literals",
	"c.enabled ? 'pause' : 'play'":                   "two literals",
	"r.success ? 'bg-emerald-400' : 'bg-red-400'":    "two literals",
	"isSelected ? 'bg-cyan-400' : 'bg-slate-600'":    "two literals, in the policy multi-select's kind dot",
}

// A quoted attribute is the easier half of this to get wrong, because breaking out of
// one does not need a "<" — closing the quote is enough to add an event handler, and
// data-* attributes read back through dataset are unaffected by escaping, since the HTML
// parser decodes the entities before dataset ever sees them. So there is no cost to
// escaping and no reason for an exception that is not in the table above.
func TestDashboardAttributeInterpolationsAreEscaped(t *testing.T) {
	app := readAsset(t, "js/app.js")

	checked := 0
	for _, attr := range attrRe.FindAllStringSubmatch(app, -1) {
		name, value := attr[1], attr[2]
		if !strings.Contains(value, "${") {
			continue
		}
		for _, m := range interpRe.FindAllStringSubmatch(value, -1) {
			expr := strings.TrimSpace(m[1])
			checked++
			if strings.HasPrefix(expr, "escapeHTML(") {
				continue
			}
			if _, ok := safeAttrInterp[expr]; ok {
				continue
			}
			t.Errorf("%s=\"${%s}\" interpolates an unescaped value into a quoted attribute.\n"+
				"Wrap it in escapeHTML(), or — if it genuinely cannot carry stored data — add it "+
				"to safeAttrInterp with the reason. Closing the quote is enough to add an event "+
				"handler here; a \"<\" is not needed.", name, expr)
		}
	}

	// If the scan finds nothing it proves nothing, and a renamed helper or a switch to
	// single-quoted attributes would do exactly that.
	if checked < 30 {
		t.Errorf("only %d attribute interpolations found in js/app.js — the scan is broken, "+
			"which would make this test vacuously pass", checked)
	}
}

// storedValueExprs are the expressions that carry stored or remote data into the
// dashboard's markup. Each must never appear as a bare ${expr}: not in an attribute,
// which the sweep above covers, and not in a text position, which it does not.
//
// clientIP and protoStr are here because the live query log is the one place a value can
// originate off-box — on DoH the client address can come from a forwarding header — and
// they were the last two unescaped fields in that row.
//
// Three absences are deliberate. c.note reaches the DOM only as an input's .value, which
// is a property assignment and not a parse, so there is no escaped form to look for.
// c.token appears bare once on purpose, building the registration URL, where it is a path
// segment rather than markup. And a whitelisted address, the `ip` loop variable, is
// escaped in all three places it becomes markup but appears bare twice more — in a toast
// message and in a confirm dialog's body, both of which reach the DOM through
// textContent, which the last test in this file is what pins down.
var storedValueExprs = []string{
	"c.name", "c.uuid", "c.id", // client record, operator free text
	"currentIP", "dnsPrimaryIP", // addresses, including pre-validation records
	"expText", "remainingText", // formatted from a stored expiry
	"item",               // a blocklist / whitelist entry
	"dom",                // a static record's domain
	"u.address",          // an upstream address
	"r.name", "r.target", // a diagnostics result
	"label",             // a policy label, raw key when the map does not know it
	"domain", "ruleStr", // query log
	"clientIP", "protoStr", // query log, the two that can come off-box
	"accountName", // query log, resolved from the client record
}

// The regression this pins is not subtle to read and impossible to see in a browser
// unless you happen to name a client with a tag in it. Every one of these fields is
// rendered by a template assigned to innerHTML.
func TestStoredValuesAreNeverInterpolatedRaw(t *testing.T) {
	app := readAsset(t, "js/app.js")

	for _, expr := range storedValueExprs {
		bare := "${" + expr + "}"
		if n := strings.Count(app, bare); n != 0 {
			t.Errorf("js/app.js interpolates %s raw, %d time(s). This value comes from a client "+
				"record, the settings API or a resolved query, and the templates around it are "+
				"assigned to innerHTML — write ${escapeHTML(%s)}.", bare, n, expr)
		}
		// And the escaped form has to actually be there, or a field that was quietly
		// dropped from a template would pass the check above by not existing.
		if !strings.Contains(app, "${escapeHTML("+expr+")}") {
			t.Errorf("js/app.js no longer renders escapeHTML(%s) anywhere. If the field was "+
				"removed, drop it from storedValueExprs; if it was renamed, rename it here too, "+
				"or this list stops guarding anything.", expr)
		}
	}
}

// functionBody returns the source of a top-level function declaration, from its name to
// the first line that closes a brace in column 0. app.js indents everything nested, so
// that line is the function's own closing brace.
//
// `async function` is tried second rather than folded into one search because the plain form
// is the common case and an `async` prefix on a name that also exists unprefixed would be a
// different function. Only runFullDiagnostics is declared async today.
func functionBody(t *testing.T, src, name string) string {
	t.Helper()

	start := strings.Index(src, "\nfunction "+name+"(")
	if start < 0 {
		start = strings.Index(src, "\nasync function "+name+"(")
	}
	if start < 0 {
		t.Fatalf("js/app.js has no top-level function %s", name)
	}
	end := strings.Index(src[start+1:], "\n}")
	if end < 0 {
		t.Fatalf("could not find the end of %s's body in js/app.js", name)
	}
	return src[start : start+1+end]
}

// escapeHTML is one small function that everything above depends on, and it is wrong in
// a way that is easy to miss if & is not replaced first: escaping "<" to "&lt;" and only
// then escaping "&" yields "&amp;lt;", so the panel displays the literal text "&lt;"
// instead of "<" — and a value that round-trips through the dashboard grows an extra
// "amp;" every time it is saved.
func TestEscapeHTMLCoversEveryMarkupCharacter(t *testing.T) {
	app := readAsset(t, "js/app.js")

	// A top-level declaration, so it is hoisted and reachable from the nested scopes
	// that call it — renderList inside its own function, the policy tag renderer inside
	// the DOMContentLoaded handler. Moved inside a block, those calls become a
	// ReferenceError at render time and the list simply never appears.
	body := functionBody(t, app, "escapeHTML")

	replacements := []struct{ char, entity string }{
		{"&", "&amp;"},
		{"<", "&lt;"},
		{">", "&gt;"},
		{`"`, "&quot;"},
		{"'", "&#039;"},
	}
	for _, r := range replacements {
		if !strings.Contains(body, r.entity) {
			t.Errorf("escapeHTML does not produce %s, so %q survives into the markup",
				r.entity, r.char)
		}
	}

	// Order, not just presence.
	amp := strings.Index(body, "&amp;")
	for _, r := range replacements[1:] {
		if i := strings.Index(body, r.entity); i >= 0 && i < amp {
			t.Errorf("escapeHTML replaces %s before &amp;, which double-escapes the "+
				"ampersand it just introduced", r.entity)
		}
	}
}

// innerHTMLAssignRe matches an assignment to a node's innerHTML. The "\w+\." prefix is
// what keeps it from matching the two comments in app.js that discuss innerHTML by name.
var innerHTMLAssignRe = regexp.MustCompile(`(\w+)\.innerHTML\s*=`)

// The dialogs and the toast are the other half of the same surface, and they take the
// opposite approach: they build nodes and set textContent rather than escaping into a
// template. That is why the delete confirmation can name a client without escaping it.
//
// Both used to be innerHTML. The toast is the worse of the two, because its text is
// usually not a literal — errorMessage() returns whatever string the response carried,
// so any handler that echoes part of a request back in its error body could put live
// markup into the panel.
func TestDialogsAndToastsSetTextRatherThanMarkup(t *testing.T) {
	app := readAsset(t, "js/app.js")

	for _, assign := range []string{
		"label.textContent =",   // showToast
		"message.textContent =", // showDialog: the line that names the client
		"title.textContent =",
		"hint.textContent =",
	} {
		if !strings.Contains(app, assign) {
			t.Errorf("js/app.js no longer contains %q. These strings name a client, and a "+
				"client name is free text — if this became innerHTML, the delete "+
				"confirmation would run whatever the name contains.", assign)
		}
	}

	// And nothing in either function may build markup from a string. showDialog has one
	// permitted exception: the Feather icon in the header badge, whose name comes from
	// its own tone table.
	for _, fn := range []struct {
		name    string
		allowed []string
	}{
		{"showToast", nil},
		{"showDialog", []string{"badge"}},
	} {
		body := functionBody(t, app, fn.name)
		for _, m := range innerHTMLAssignRe.FindAllStringSubmatch(body, -1) {
			if slices.Contains(fn.allowed, m[1]) {
				continue
			}
			t.Errorf("%s assigns %s.innerHTML. Every string these two render is either a "+
				"client name or a server-supplied error message; build a node and set "+
				"textContent instead.", fn.name, m[1])
		}
	}
}
