package web

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The portal's two languages are two literals of the same struct, and that shape has
// exactly one failure mode: a field added to portalText and filled in on only one of
// them. Go does not complain — a missing key in a struct literal is the zero value —
// so the English reader gets a heading that renders as nothing at all, and the page
// still returns 200 with a valid document. Nobody sees it until an English-speaking
// subscriber does.
//
// The reverse leak matters too. A field nobody reads is a translation someone wrote
// and a maintainer will keep updating for a page that does not show it, and a
// {{.T.Whatever}} that names no field renders "<no value>" into the markup rather
// than failing, because these templates are executed with a concrete struct.
//
// Reflection is what makes this hold for fields that do not exist yet. A list of
// names checked by hand is a list that goes stale the first time someone adds a
// string, which is the moment it was supposed to help.

// tFieldRe matches a bundle field being read: {{.T.Name}} in a template, or t.Name in
// the handler. The two templates are Go constants in the same file as the handler, so
// one scan over the source covers both. `\b` at the end keeps LabelRemaining from
// counting as a use of Label.
var tFieldRe = regexp.MustCompile(`(?:\.T\.|\bt\.)([A-Za-z][A-Za-z0-9_]*)\b`)

// portalBundles is what every check below iterates. Named rather than positional so a
// failure says which language is short a string.
func portalBundles() map[string]portalText {
	return map[string]portalText{
		portalLangFa: portalFa,
		portalLangEn: portalEn,
	}
}

// TestPortalTextBundlesAreComplete asserts every field of every bundle carries text.
//
// It walks the struct by reflection rather than by name, so a field added tomorrow is
// covered the moment it exists — which is the only version of this test that keeps
// working.
func TestPortalTextBundlesAreComplete(t *testing.T) {
	typ := reflect.TypeFor[portalText]()

	for lang, bundle := range portalBundles() {
		v := reflect.ValueOf(bundle)

		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			f := v.Field(i)

			switch f.Kind() {
			case reflect.String:
				if strings.TrimSpace(f.String()) == "" {
					t.Errorf("portal bundle %q has no %s — a subscriber reading that "+
						"language sees an empty element where this string belongs", lang, name)
				}
			case reflect.Slice:
				if f.Len() == 0 {
					t.Errorf("portal bundle %q has no %s steps — the device panel renders "+
						"a heading with nothing under it", lang, name)
					continue
				}
				for j := 0; j < f.Len(); j++ {
					if strings.TrimSpace(f.Index(j).String()) == "" {
						t.Errorf("portal bundle %q has an empty step %s[%d] — the guide "+
							"renders a numbered bullet with no instruction in it", lang, name, j)
					}
				}
			default:
				// A field of some other kind means the struct grew a shape this test does
				// not know how to check, and silently skipping it is how the guarantee
				// erodes.
				t.Errorf("portalText.%s is a %s — extend this test to check that kind, "+
					"or it is unverified in both languages", name, f.Kind())
			}
		}
	}
}

// TestPortalTextSlicesAgreeAcrossLanguages pins the step counts together.
//
// The steps are a numbered procedure for a specific settings screen, so the two
// languages are not free to differ in length: a Persian list with five steps and an
// English one with four means one of the two is missing an instruction, and the one
// most likely to be missing it is the one nobody on this project reads back.
func TestPortalTextSlicesAgreeAcrossLanguages(t *testing.T) {
	typ := reflect.TypeFor[portalText]()
	fa := reflect.ValueOf(portalFa)
	en := reflect.ValueOf(portalEn)

	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() != reflect.Slice {
			continue
		}
		name := typ.Field(i).Name
		if a, b := fa.Field(i).Len(), en.Field(i).Len(); a != b {
			t.Errorf("%s has %d step(s) in Persian and %d in English — one language is "+
				"walking the subscriber through a different procedure", name, a, b)
		}
	}
}

// TestPortalTemplatesNameOnlyRealBundleFields is the other direction: a {{.T.X}} that
// names nothing.
//
// html/template resolves a missing field on a struct at execute time and writes
// "<no value>" where the string should be, so the page renders, returns 200, and shows
// that literal to the subscriber. A typo in a field name is therefore not a build
// error, not a parse error and not a runtime error — it is a word on the page.
func TestPortalTemplatesNameOnlyRealBundleFields(t *testing.T) {
	typ := reflect.TypeFor[portalText]()

	for _, tpl := range []struct{ name, body string }{
		{"portalPageHTML", portalPageHTML},
		{"portalErrorHTML", portalErrorHTML},
	} {
		for _, m := range regexp.MustCompile(`\.T\.([A-Za-z][A-Za-z0-9_]*)`).FindAllStringSubmatch(tpl.body, -1) {
			if _, ok := typ.FieldByName(m[1]); !ok {
				t.Errorf("%s reads .T.%s, which portalText does not have — that renders "+
					"as the literal \"<no value>\" on the page", tpl.name, m[1])
			}
		}
	}
}

// TestPortalTextFieldsAreAllRead catches the opposite waste: a translated string that
// reaches no reader.
//
// Some fields are read by the handler rather than by a template — WordRemaining and the
// cycle names are glued to a number in Go, and the status lines are chosen by a switch —
// so both templates and the Go source are scanned, and both files are read as text
// because a field name used in a Go string constant cannot be found any other way.
func TestPortalTextFieldsAreAllRead(t *testing.T) {
	read := map[string]bool{}
	for _, file := range []string{"portal.go", "portal_i18n.go"} {
		for _, m := range tFieldRe.FindAllStringSubmatch(readGoSource(t, file), -1) {
			read[m[1]] = true
		}
	}

	typ := reflect.TypeFor[portalText]()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !read[name] {
			t.Errorf("portalText.%s is translated in both languages and read by nothing — "+
				"either wire it into the markup or delete it, because right now it is a "+
				"string two people have to keep in sync for no reader", name)
		}
	}
}

// TestPortalScriptMessagesReachTheScript ties the four script-facing fields to the
// attributes js/portal.js actually reads.
//
// This pair is easy to half-finish: the field exists, the translation is written, the
// template renders the attribute — and the script still asks for a differently spelled
// one, at which point showToast is handed ” and stays silent. A copy that failed then
// looks exactly like a copy that worked.
func TestPortalScriptMessagesReachTheScript(t *testing.T) {
	js := readAsset(t, "js/portal.js")

	for field, attr := range map[string]string{
		"MsgCopied":         "copied",
		"MsgCopyFail":       "copy-fail",
		"MsgRegisterOK":     "register-ok",
		"MsgRegisterFail":   "register-fail",
		"MsgRegisterDenied": "register-denied",
		// The per-reason lines. The API answers with a machine-readable `reason`
		// and the script renders `msg('reason-'+reason)`; a rename on either side
		// would leave the subscriber reading the generic fallback for a refusal
		// that has a specific, actionable line written for it.
		"MsgRegisterSuspended": "reason-suspended",
		"MsgRegisterExpired":   "reason-expired",
		"MsgRegisterQuota":     "reason-quota",
		"MsgRegisterConflict":  "reason-conflict",
	} {
		if _, ok := reflect.TypeFor[portalText]().FieldByName(field); !ok {
			t.Errorf("portalText has no %s — the script asks for data-msg-%s", field, attr)
			continue
		}
		if want := `data-msg-` + attr + `="{{.T.` + field + `}}"`; !strings.Contains(portalPageHTML, want) {
			t.Errorf("portalPageHTML does not render %s, so the script reads an absent "+
				"attribute and the toast stays empty", want)
		}
		if want := `msg('` + attr + `')`; !strings.Contains(js, want) {
			t.Errorf("js/portal.js never calls %s, so %s is rendered into the page and "+
				"never shown", want, field)
		}
	}

	// The two fragments renderQuota needs after a sync. Reusing the bundle fields Go
	// formatted the first paint with is the whole reason the numbers do not appear to
	// change wording when the subscriber presses the button.
	for _, want := range []string{
		`data-word="{{.T.WordRemaining}}"`,
		`data-unlimited="{{.T.Unlimited}}"`,
	} {
		if !strings.Contains(portalPageHTML, want) {
			t.Errorf("portalPageHTML does not render %s — renderQuota rebuilds the "+
				"remaining line after a sync and would write a bare number", want)
		}
	}
	for _, want := range []string{`getAttribute('data-word')`, `getAttribute('data-unlimited')`} {
		if !strings.Contains(js, want) {
			t.Errorf("js/portal.js does not read %s", want)
		}
	}

	// And no message may go back to being a literal in the script, which is the shape
	// this whole mechanism replaced: one file, served to both audiences, cannot hold a
	// sentence in either language. Every call has to pass a variable — msg(), or the
	// element's own data-copied — never a quoted string.
	if lit := regexp.MustCompile(`showToast\(\s*['"]`).FindAllString(js, -1); len(lit) != 0 {
		t.Errorf("js/portal.js calls showToast with a quoted literal %d time(s) — that "+
			"string is shown to the Persian and the English reader alike", len(lit))
	}
	// The emoji prefixes are now a masked ::before driven by the tone class, so a glyph
	// reappearing in a shown string means someone put the old shape back.
	for _, glyph := range []string{"✅", "⚠️", "❌"} {
		if strings.Contains(js, glyph) {
			t.Errorf("js/portal.js contains %q — the toast draws its icon from "+
				".toast.is-ok/.is-warn/.is-bad, and a glyph in the text would need "+
				"innerHTML on a page whose URL is a bearer token", glyph)
		}
	}
	// The three tone classes have to be spelled here as well: portal.css defines them,
	// the markup never carries them, and TestPortalClassesAreDefinedAndUsed accepts a
	// runtime-only class exactly because it is quoted in this file.
	for _, tone := range []string{"'is-ok'", "'is-warn'", "'is-bad'"} {
		if !strings.Contains(js, tone) {
			t.Errorf("js/portal.js never names %s, so the toast has no tone and the rule "+
				"in portal.css is dead", tone)
		}
	}
}
