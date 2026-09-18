package web

import (
	"regexp"
	"strings"
	"testing"
)

// Two properties of js/app.js that only a text scan can hold, both learned by breaking
// them.
//
// The first is a parse hazard peculiar to this file's style. Most of the dashboard's
// markup is built inside template literals, and the convention here is to explain a
// layout decision in an HTML comment sitting next to the element it governs. A backtick
// inside one of those comments does not comment anything out — it *ends the template
// literal*, and the rest of the markup becomes JavaScript. The failure is total (the
// whole file fails to parse, so the panel never boots) and it is invisible to every
// tool in this repo's build: Go does not read the asset, `go vet` does not read the
// asset, and the embed step copies bytes. Only running the page finds it. Writing
// `p-0.5` in prose is the natural thing to do in a file where that is what the class is
// called, which is exactly why this needs a guard rather than care.
//
// The second is the WCAG 2.2 SC 2.5.8 floor. Six controls in this file were built as an
// icon or a glyph with a padding class around it — `p-0.5` on a 12px icon is 16x16, a
// bare `×` sized by its own font metrics measured 6.6x16.5 — and every one of them is on
// the mobile panel, the surface where a control is only ever touched. Padding-derived
// sizes are the trap: they read as generous in source and land under 24px in the layout,
// because the number that matters is padding plus the glyph, and the glyph is small.
// Fixed `w-6 h-6` (or an explicit min-height) is the shape that cannot drift, so the
// test pins the shape rather than trying to compute pixels from class names.

// tplCommentRe matches an HTML comment. `(?s)` lets it span lines, which these do — the
// arithmetic comments in this file run to a dozen lines. Non-greedy so two comments in
// one template are two matches rather than one that swallows the markup between them.
var tplCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)

// TestDashboardHTMLCommentsCarryNoBacktick keeps the panel parseable.
//
// The scan is deliberately blunt: it checks every HTML comment in the file rather than
// only those inside a template literal, because deciding which is which needs a real JS
// parser and the cost of the false positive is having to write "p-0.5" without quoting
// it. A comment in the static index.html would be allowed to hold one, but this file is
// not that file.
func TestDashboardHTMLCommentsCarryNoBacktick(t *testing.T) {
	app := readAsset(t, "js/app.js")

	comments := tplCommentRe.FindAllString(app, -1)
	if len(comments) < 5 {
		t.Fatalf("only %d HTML comments found in js/app.js — the scan is broken, which would "+
			"make this test vacuously pass", len(comments))
	}

	for _, c := range comments {
		if !strings.Contains(c, "`") {
			continue
		}
		// Report the first line, which is what someone needs to find it. The whole comment
		// can be a dozen lines of layout arithmetic.
		head := c
		if i := strings.IndexByte(head, '\n'); i >= 0 {
			head = head[:i]
		}
		t.Errorf("an HTML comment in js/app.js contains a backtick:\n  %s\n"+
			"Inside a template literal that ends the string and the markup after it is parsed "+
			"as JavaScript — the file fails to parse and the panel does not boot. Nothing in "+
			"`go build` reads this asset, so the first sign is a blank page. Write the class "+
			"name unquoted.", strings.TrimSpace(head))
	}
}

// touchTargetOffenders are the class fragments that produced a sub-24px control, each
// paired with the control it broke. A match is not proof of a new failure — some other
// element could legitimately carry the fragment — but every one of these was a real
// measured violation on the 360px panel, so a reappearance is worth stopping to look at.
//
// The Set IP Manually button is not listed. Its broken and fixed forms share the same
// opening run of classes, so no fragment tells them apart; it is pinned positively by the
// min-height assertion at the bottom of the test instead, which is the more exact check
// anyway.
var touchTargetOffenders = map[string]string{
	`copy-uuid-btn text-slate-400`:   "the UUID copy button measured 16x16 with p-0.5 around a 12px icon",
	`remove-client-ip-btn hover:`:    "the whitelist × measured 6.6x16.5, sized by the glyph's own metrics",
	`remove-upstream text-slate-500`: "the upstream delete measured 16x16, and deleted on a single tap",
	`remove-record text-slate-500`:   "the static-record delete measured 22x22 with p-1 around a 14px icon",
}

// TestDashboardTouchTargetsKeepTheirFloor pins the six controls raised to 24px.
//
// It asserts the shape, not the size: a fixed w-6/h-6 box or an explicit min-height,
// rather than padding that happens to add up today. The distinction is the whole lesson —
// `p-1.5` reaches 24px around a 12px icon and drops to 21px the moment someone swaps in a
// 9px one, and nothing about the class name says so.
func TestDashboardTouchTargetsKeepTheirFloor(t *testing.T) {
	app := readAsset(t, "js/app.js")

	for frag, why := range touchTargetOffenders {
		if strings.Contains(app, frag) {
			t.Errorf("js/app.js contains %q again — %s.\nThat is under the 24x24 CSS px floor "+
				"WCAG 2.2 SC 2.5.8 sets for a touch target, on controls that only exist to be "+
				"touched. Use a fixed w-6 h-6 inline-flex box, or min-h-[24px] where the label "+
				"supplies the width.", frag, why)
		}
	}

	// The raised shape, per control. Spelled out rather than counted, so a failure names
	// the one that regressed.
	for _, want := range []struct{ sel, what string }{
		{`copy-uuid-btn inline-flex items-center justify-center w-6 h-6 shrink-0`, "UUID copy"},
		{`remove-client-ip-btn inline-flex items-center justify-center w-6 h-6`, "whitelist remove"},
		{`remove-upstream inline-flex items-center justify-center w-6 h-6 shrink-0`, "upstream remove"},
		{`remove-record inline-flex items-center justify-center w-6 h-6 shrink-0`, "static-record remove"},
	} {
		if !strings.Contains(app, want.sel) {
			t.Errorf("the %s control no longer carries %q — it was raised to the 24px floor and "+
				"something has reshaped it.", want.what, want.sel)
		}
	}
	// The one that reaches the floor by min-height rather than a fixed box, because its
	// width comes from a text label.
	if !strings.Contains(app, `min-h-[24px] px-1.5 -me-1.5`) {
		t.Error("the Set IP Manually button no longer carries min-h-[24px] px-1.5 -me-1.5. The " +
			"min-height is what lifts a 15px-tall 10px label to the WCAG floor, and the negative " +
			"inline-end margin is what keeps the widened hit area from shifting the row.")
	}
}

// TestUpstreamRemovalIsConfirmed ties the enlarged target to the dialog that has to come
// with it.
//
// Raising a one-tap destructive control from 16px to 24px makes it reachable and also
// makes it easier to hit by accident — and this list re-sorts itself by measured latency
// on every stats tick, so the row under a thumb is not guaranteed to be the row that was
// there when the reach began. Every other destructive control on this panel already
// asked; this one did not.
func TestUpstreamRemovalIsConfirmed(t *testing.T) {
	app := readAsset(t, "js/app.js")

	body := app[strings.Index(app, `if (btn.classList.contains('remove-upstream'))`):]
	if i := strings.Index(body, `else if (btn.classList.contains('remove-proxied')`); i > 0 {
		body = body[:i]
	}
	if len(body) < 100 {
		t.Fatal("could not slice the remove-upstream branch out of js/app.js — the scan is broken")
	}

	for _, want := range []struct{ src, why string }{
		{"confirmAction({", "the branch has to ask before it deletes"},
		{"destructive: true", "the dialog has to render in its destructive tone, not as a neutral question"},
		{"if (!ok) return;", "a cancelled dialog has to stop the request, not fall through to it"},
	} {
		if !strings.Contains(body, want.src) {
			t.Errorf("the remove-upstream branch does not contain %q — %s.", want.src, want.why)
		}
	}
	// Order matters: the fetch has to be downstream of the guard.
	if ci, fi := strings.Index(body, "if (!ok) return;"), strings.Index(body, "/api/upstreams/delete"); ci < 0 || fi < 0 || ci > fi {
		t.Error("the remove-upstream branch calls /api/upstreams/delete before the confirmation " +
			"guard returns, so pressing Cancel deletes the upstream anyway.")
	}
}

// TestClientCardHeaderKeepsItsActionsOnScreen pins the mobile layout of the client
// card's action row.
//
// The card header is a flex row: the subscriber's name and their Code/Slug line on
// one side, the edit/pause/delete buttons on the other. The Slug is a single
// unbreakable 64-character token, so its min-content width (~345px at 10px mono)
// is wider than the whole header on a 375px phone — and a flex item's minimum
// width defaults to its min-content unless the item says min-w-0. Without that
// one class the text block refused to shrink, the row overflowed the card, and
// the three action buttons sat at x=385-476: fully off the right edge of the
// screen, invisible and unreachable. The buttons looked "not displayed
// properly" because they were not displayed at all.
//
// The fix is the same shape the UUID row below the header already used: the text
// block may shrink (min-w-0 flex-1), its one unbreakable line truncates with the
// full value kept on the title, and the button group may never be compressed
// (shrink-0). All three have to hold together — any one missing and the row
// overflows again.
func TestClientCardHeaderKeepsItsActionsOnScreen(t *testing.T) {
	app := readAsset(t, "js/app.js")

	start := strings.Index(app, "<!-- Card Header -->")
	end := strings.Index(app, "<!-- UUID Row -->")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("could not slice the client card header out of js/app.js — the scan is broken")
	}
	header := app[start:end]

	for _, want := range []struct{ src, why string }{
		{`class="min-w-0 flex-1"`, "the name/slug block must be allowed to shrink below its " +
			"min-content width — the 64-character Slug token alone is wider than the header on " +
			"a 375px screen"},
		{`font-mono mt-0.5 truncate`, "the Code/Slug line must truncate rather than set the " +
			"row's minimum width to the unbreakable slug"},
		{`flex items-center gap-1 shrink-0`, "the edit/pause/delete group must never be the " +
			"thing the layout compresses — without shrink-0 it is pushed off-screen by the " +
			"refusing-to-shrink text block"},
	} {
		if !strings.Contains(header, want.src) {
			t.Errorf("the client card header does not carry %q — %s. That is how the three "+
				"action buttons ended up at x=385-476 on a 375px screen: unreachable, and "+
				"reported as icons that do not display.", want.src, want.why)
		}
	}
}
