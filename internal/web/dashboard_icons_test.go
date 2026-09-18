package web

import (
	"regexp"
	"strings"
	"testing"
)

// Feather draws by scanning the DOM for [data-feather] and swapping each element for the matching
// SVG, and its replaceElement guards that lookup — `if (void 0 !== icons[name])`. A name the bundle
// does not have is therefore not an error: the <i> is left exactly as it was, empty, nothing is
// logged, and the page around it works. A mistyped icon is invisible in every sense of the word.
//
// Which is the whole reason this file exists. Three of these names arrived with clientsPanelMessage's
// failure notices — loader, alert-triangle, wifi-off — and a typo in one of them would have produced
// an error panel with a hole where its icon belongs, on the screen an operator only reads when
// something has already gone wrong.
//
// The bundle's own contents are the reference. Nothing here hardcodes what Feather ships, so
// replacing feather.min.js with a hand-built subset of the icons actually used — the size win this
// dashboard is heading for — fails these tests with the precise list of names the subset is missing,
// instead of quietly shipping a panel of blanks.

// featherNameRe reads the keys of the icon-contents map out of the minified bundle.
//
// Two shapes, because the minifier quotes a key only when it has to: hyphen-free names appear as
// `{activity:'<polyline…` and hyphenated ones as `,"alert-triangle":'<path…`. The `:'<` tail is what
// makes the match exact — it is the opening of an SVG body, and the bundle's only other map keyed by
// icon name is the tag/alias list, whose values are arrays (`:[`) and so cannot match.
var featherNameRe = regexp.MustCompile(`[{,]"?([a-z0-9-]+)"?:'<`)

// featherIconSet returns every icon name web/js/feather.min.js can actually render.
func featherIconSet(t *testing.T) map[string]bool {
	t.Helper()

	set := map[string]bool{}
	for _, name := range values(featherNameRe, readAsset(t, "js/feather.min.js")) {
		set[name] = true
	}
	// Feather 4.x ships a few hundred. A bundle whose internals no longer match either shape above
	// would parse to a near-empty set and turn every check below into a pass.
	if len(set) < 200 {
		t.Fatalf("only %d icon names parsed out of js/feather.min.js — the scan is broken, which "+
			"would make every assertion in this file vacuous", len(set))
	}
	return set
}

var (
	// A literal attribute value. The value class excludes "$" as well as the quote, so an
	// interpolated value cannot match this even partially — the two sweeps are disjoint.
	featherLiteralRe = regexp.MustCompile(`data-feather="([^"$]*)"`)

	// A value that is exactly one interpolation: data-feather="${expr}".
	featherInterpRe = regexp.MustCompile(`data-feather="\$\{([^}"]*)\}"`)

	// setAttribute('data-feather', <expr>) — the one icon on the dashboard that is chosen at
	// runtime on an element that already exists rather than written into a template. Neither
	// sweep above can see it, so it gets its own.
	featherSetAttrRe = regexp.MustCompile(`setAttribute\('data-feather',\s*([^)]*)\)`)

	// A single-quoted JS string, for digging the names out of whatever the two above captured.
	featherJSLiteralRe = regexp.MustCompile(`'([a-z0-9-]*)'`)
)

// featherInterpSources maps each interpolated data-feather expression to the names that can reach
// it, and records why that is the whole list. An interpolation absent from this map fails the sweep:
// the point is that adding one costs somebody a look at where its values come from.
//
// This is the same discipline as safeAttrInterp in dashboard_escaping_test.go, for the same reason —
// an expression is only as safe, or as spelled-correctly, as its call sites.
var featherInterpSources = map[string]struct {
	names func(t *testing.T, app, expr string) []string
	why   string
}{
	"icon": {
		names: func(_ *testing.T, app, _ string) []string {
			return values(regexp.MustCompile(`clientsPanelMessage\('([a-z0-9-]*)'`), app)
		},
		why: "clientsPanelMessage's first argument is a literal at every call site",
	},
	"tone.icon": {
		names: func(t *testing.T, app, _ string) []string {
			return values(regexp.MustCompile(`icon: '([a-z0-9-]*)'`), functionBody(t, app, "showDialog"))
		},
		why: "showDialog picks between two tone tables, each naming its icon literally",
	},
	"c.enabled ? 'pause' : 'play'": {
		names: func(_ *testing.T, _, expr string) []string {
			return values(featherJSLiteralRe, expr)
		},
		why: "both names are literals inside the expression itself",
	},
}

// TestEveryFeatherIconNameIsOneTheBundleCanRender sweeps both assets and resolves every name,
// literal or interpolated, against the shipped bundle. The t.Logf at the end is the inventory a
// hand-built subset needs: how many distinct icons this dashboard asks for, out of how many it
// currently downloads to get them.
func TestEveryFeatherIconNameIsOneTheBundleCanRender(t *testing.T) {
	icons := featherIconSet(t)
	app := readAsset(t, "js/app.js")
	used := map[string]bool{}

	check := func(asset, name, where string) {
		if name == "" {
			t.Errorf("%s has an empty icon name %s, which draws nothing.", asset, where)
			return
		}
		used[name] = true
		if !icons[name] {
			t.Errorf("%s asks for the Feather icon %q %s, and js/feather.min.js has no icon by that "+
				"name. Feather skips a name it does not know without logging anything, so this is "+
				"blank space where a symbol should be and nothing anywhere reports it.",
				asset, name, where)
		}
	}

	for _, asset := range []string{"index.html", "js/app.js"} {
		src := readAsset(t, asset)
		literals := values(featherLiteralRe, src)
		interps := values(featherInterpRe, src)

		if got, want := len(literals)+len(interps), strings.Count(src, `data-feather="`); got != want {
			t.Fatalf("%s: the two sweeps matched %d of the file's %d data-feather attributes. A value "+
				"that is neither a plain literal nor a single ${…} — a mixed one such as "+
				"data-feather=\"icon-${x}\" — would be read by neither sweep and go unchecked.",
				asset, got, want)
		}

		for _, name := range literals {
			check(asset, name, "in its markup")
		}
		for _, expr := range interps {
			source, ok := featherInterpSources[expr]
			if !ok {
				t.Errorf("%s renders data-feather=\"${%s}\", and featherInterpSources does not say "+
					"where that expression's names come from — so none of them are checked. Add an "+
					"entry that collects them.", asset, expr)
				continue
			}
			names := source.names(t, app, expr)
			if len(names) == 0 {
				t.Errorf("featherInterpSources found no names for ${%s} (%s). Either the extractor "+
					"is broken or what it reads was renamed; the icon is unchecked either way.",
					expr, source.why)
				continue
			}
			for _, name := range names {
				check(asset, name, "through ${"+expr+"}")
			}
		}
	}

	t.Logf("dashboard uses %d distinct Feather icons; js/feather.min.js ships %d: %s",
		len(used), len(icons), strings.Join(sortedKeys(used), " "))
}

// Two icons on the dashboard are chosen at runtime and written onto elements that are already in
// the document: the badge in the credential modal, which is alert-triangle when the password change
// is forced and user-check when the operator opened it themselves, and the theme switch, which shows
// moon while the panel is dark and sun while it is light. Setting the attribute draws nothing by
// itself — Feather only reads [data-feather] when replace() runs — so the swap and the redraw are
// one fact in two lines, and separating them leaves the previous icon on screen. In forced mode that
// means a security warning wearing the "you chose to be here" icon; on the switch it means a button
// that says "switch to light" under a sun.
func TestTheRuntimeIconSwapNamesRealIconsAndIsRedrawn(t *testing.T) {
	icons := featherIconSet(t)
	app := readAsset(t, "js/app.js")
	i18n := readAsset(t, "js/i18n.js")

	for _, f := range []struct{ name, body string }{{"js/app.js", app}, {"js/i18n.js", i18n}} {
		exprs := values(featherSetAttrRe, f.body)
		if len(exprs) == 0 {
			t.Errorf("nothing in %s sets data-feather through setAttribute any more. If that "+
				"mechanism is genuinely gone there, delete this half of the test rather than "+
				"leaving it passing on nothing.", f.name)
			continue
		}
		for _, expr := range exprs {
			names := values(featherJSLiteralRe, expr)
			if len(names) == 0 {
				t.Errorf("%s: setAttribute('data-feather', %s) passes no literal name, so which "+
					"icon it draws cannot be checked here. Keep the names literal at this call.",
					f.name, expr)
				continue
			}
			for _, name := range names {
				if name == "" || !icons[name] {
					t.Errorf("%s: setAttribute('data-feather', %s) can set %q, which "+
						"js/feather.min.js cannot render — the element would keep whatever icon "+
						"it had.", f.name, expr, name)
				}
			}
		}
	}

	// i18n.js swaps the switch's icon inside syncSwitchLabels and cannot redraw there — that
	// function also runs during init(), before app.js's helper is guaranteed to have been
	// evaluated. The redraw belongs to the click handler that caused the swap, so what is
	// checked here is that the file draws at all: a swap with no draw anywhere leaves the
	// button showing the icon for the theme it just left.
	if !strings.Contains(i18n, "safeFeatherReplace()") {
		t.Error("js/i18n.js swaps the theme switch's icon but never calls safeFeatherReplace, " +
			"so the moon stays on screen in light mode and the sun stays on in dark.")
	}

	// The swap and the redraw, in that order, in the one function in app.js that does this.
	body := functionBody(t, app, "showChangePwdModal")
	swap := strings.Index(body, "setAttribute('data-feather'")
	draw := strings.Index(body, "safeFeatherReplace();")
	switch {
	case swap < 0:
		t.Error("showChangePwdModal no longer swaps the badge icon — the scan is broken.")
	case draw < 0:
		t.Error("showChangePwdModal sets data-feather but never redraws, so the badge keeps the " +
			"icon from the last time the modal was opened: the forced-change warning shown with " +
			"the voluntary-rotation icon, or the reverse.")
	case draw < swap:
		t.Error("showChangePwdModal redraws before it swaps the badge icon, so the new name is " +
			"written one paint too late and takes effect only the next time the modal opens.")
	}
}

// Every place that draws icons goes through safeFeatherReplace, which is the version with the
// typeof guard and the try/catch. Two sites used to open-code a weaker one, and the worse of them
// was inside showDialog: it ran with the backdrop already in the document and none of the buttons
// wired, so a throw there would have left a dialog on screen that could not be answered or closed.
func TestIconsAreOnlyEverDrawnThroughTheGuardedHelper(t *testing.T) {
	app := readAsset(t, "js/app.js")

	if n := strings.Count(app, "feather.replace()"); n != 1 {
		t.Errorf("js/app.js calls feather.replace() %d times, want exactly one — the call inside "+
			"safeFeatherReplace. A bare call skips the typeof guard and the try/catch, and every "+
			"other draw site already goes through the helper.", n)
	}
	if !strings.Contains(functionBody(t, app, "safeFeatherReplace"), "feather.replace()") {
		t.Error("the one feather.replace() call in js/app.js is no longer the one inside " +
			"safeFeatherReplace, so the count above is guarding the wrong line.")
	}
}
