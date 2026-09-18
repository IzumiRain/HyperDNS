package web

import (
	"regexp"
	"strings"
	"testing"
)

// index.html carries five modals as static markup; showDialog builds a sixth kind at runtime.
// The runtime one has always been accessible — role="dialog", aria-modal, a labelled heading, a
// focus trap, Escape, focus return — and the five static ones had none of it. That is the kind of
// gap a click-through never finds: the panels look right and the mouse works, and only a keyboard
// or a screen reader discovers they are ordinary <div>s.
//
// Two of the failures were more than an inconvenience. Without a trap, Tab out of the login
// overlay reaches the dashboard's own controls behind the backdrop while nobody is authenticated.
// And with no Escape and no backdrop click, the only way out of the diagnostics panel was the
// 20-pixel × in its corner.
//
// The list of modals is read out of app.js rather than written here, so a sixth static modal
// added to MODAL_IDS and not given the attributes fails this file instead of shipping.

// modalIDsRe pulls the quoted entries out of the one-line MODAL_IDS literal.
var modalIDsRe = regexp.MustCompile(`'([a-z0-9-]+)'`)

// modalIDList returns MODAL_IDS as declared in js/app.js.
func modalIDList(t *testing.T, app string) []string {
	t.Helper()

	const decl = "const MODAL_IDS = ["
	start := strings.Index(app, decl)
	if start < 0 {
		t.Fatal("js/app.js no longer declares MODAL_IDS. The Escape handler, the backdrop handler " +
			"and the focus manager all read it, so nothing below is being checked.")
	}
	end := strings.Index(app[start:], "]")
	if end < 0 {
		t.Fatal("could not find the end of the MODAL_IDS literal in js/app.js")
	}
	ids := values(modalIDsRe, app[start:start+end])
	if len(ids) < 5 {
		t.Fatalf("MODAL_IDS parsed to %d entries, want the five static modals — the scan is broken, "+
			"which would make every check in this file vacuous", len(ids))
	}
	return ids
}

// modalTag returns the opening <div> tag of the modal container carrying this id. [^>]* cannot
// cross the tag's own ">", and the id is unique (TestDashboardIDsAreUnique), so the match is
// exactly one tag however its attributes are ordered or wrapped across lines.
func modalTag(t *testing.T, html, id string) string {
	t.Helper()

	re := regexp.MustCompile(`<div\s[^>]*id="` + regexp.QuoteMeta(id) + `"[^>]*>`)
	tag := re.FindString(html)
	if tag == "" {
		t.Fatalf("web/index.html has no <div> carrying id=%q, but js/app.js lists it in MODAL_IDS", id)
	}
	return tag
}

// modalAttrRe reads one attribute out of an opening tag.
var modalAttrRe = regexp.MustCompile(`([a-zA-Z-]+)="([^"]*)"`)

func modalAttrs(tag string) map[string]string {
	attrs := map[string]string{}
	for _, m := range modalAttrRe.FindAllStringSubmatch(tag, -1) {
		attrs[m[1]] = m[2]
	}
	return attrs
}

// Every static modal has to say what it is and what it is called. aria-labelledby is the one that
// carries real information: without it a screen reader announces "dialog" and nothing else, and
// four of the five headings had no id to point at.
func TestStaticModalsDeclareTheirRoleAndLabel(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")
	declared := dashIDSet(t, html)

	for _, id := range modalIDList(t, app) {
		attrs := modalAttrs(modalTag(t, html, id))

		if attrs["role"] != "dialog" {
			t.Errorf("#%s has role=%q, want \"dialog\". Without it the overlay is announced as an "+
				"ordinary div, and nothing tells assistive technology the page behind it is inert.",
				id, attrs["role"])
		}
		if attrs["aria-modal"] != "true" {
			t.Errorf("#%s has aria-modal=%q, want \"true\".", id, attrs["aria-modal"])
		}

		label := attrs["aria-labelledby"]
		if label == "" {
			t.Errorf("#%s has no aria-labelledby, so it is announced as an unnamed dialog.", id)
			continue
		}
		if !declared[label] {
			t.Errorf("#%s points aria-labelledby at #%s, which web/index.html does not declare. A "+
				"dangling reference is announced exactly like a missing one — as nothing.", id, label)
		}
	}
}

// Escape and a backdrop click go through the modal's own close button, so the button has to be
// there: the handlers call .click() on whatever data-modal-close names, and a name that resolves
// to nothing makes them silently do nothing — the same failure mode as every other id mismatch in
// this dashboard.
func TestDismissibleModalsNameACloseControlThatExists(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")

	// Every id that belongs to a <button>. A close control that is not a button would not answer
	// .click() the way the handlers assume.
	buttons := map[string]bool{}
	for _, m := range dashInteractiveRe.FindAllStringSubmatch(html, -1) {
		if m[1] == "button" {
			buttons[m[2]] = true
		}
	}
	if len(buttons) < 30 {
		t.Fatalf("only %d button ids found in web/index.html — the scan is broken", len(buttons))
	}

	dismissible := 0
	for _, id := range modalIDList(t, app) {
		closeID := modalAttrs(modalTag(t, html, id))["data-modal-close"]
		if closeID == "" {
			continue
		}
		dismissible++
		if !buttons[closeID] {
			t.Errorf("#%s declares data-modal-close=%q, which is not a <button> in web/index.html. "+
				"The Escape and backdrop handlers call .click() on it; if it is missing they do "+
				"nothing at all and the modal quietly stops being dismissible.", id, closeID)
		}
	}
	if dismissible < 4 {
		t.Errorf("only %d modal(s) declare data-modal-close. The diagnostics, edit-client and "+
			"add-client panels each have a close button, and change-pwd-modal has CANCEL in its "+
			"voluntary mode — all four should be dismissible.", dismissible)
	}
}

// login-modal is the authentication gate. Escape must not dismiss it, and that is expressed by
// declaring no close control: there is no close button in its markup to name, and adding one would
// be the actual bug.
func TestTheLoginGateIsNotDismissible(t *testing.T) {
	if strings.Contains(modalTag(t, readAsset(t, "index.html"), "login-modal"), "data-modal-close") {
		t.Error("#login-modal declares data-modal-close. Escape would then dismiss the " +
			"authentication overlay, leaving the dashboard shell on screen with no session behind " +
			"it — every tile empty and every action answering 401.")
	}
}

// change-pwd-modal is the one whose dismissibility is not a property of the markup. Forced by a
// weak password it must not be escapable; opened from Settings to rotate a compliant password it
// must be. Rather than two rules there is one: it names the CANCEL button, showChangePwdModal hides
// that button in forced mode, and modalCloseControl refuses a hidden control. The two cannot drift
// apart because they are the same fact read twice — which is the only reason a single
// data-modal-close attribute is safe on a modal that is sometimes a gate.
func TestForcedPasswordChangeIsNotEscapable(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")

	if got := modalAttrs(modalTag(t, html, "change-pwd-modal"))["data-modal-close"]; got != "change-pwd-cancel" {
		t.Errorf("#change-pwd-modal declares data-modal-close=%q, want \"change-pwd-cancel\" — the "+
			"button showChangePwdModal hides in forced mode.", got)
	}

	if !strings.Contains(functionBody(t, app, "showChangePwdModal"), "cancel?.classList.add('hidden')") {
		t.Error("showChangePwdModal no longer hides #change-pwd-cancel in forced mode. That hidden " +
			"class is the only thing that makes the weak-password gate un-escapable.")
	}

	if !strings.Contains(functionBody(t, app, "modalCloseControl"), "isShown(btn) ? btn : null") {
		t.Error("modalCloseControl no longer refuses a hidden close control. Escape would then " +
			"click #change-pwd-cancel while it is hidden, dismissing the forced password change the " +
			"operator is not allowed to skip.")
	}
}

// The handlers themselves. Statically checked, like every other JS property in this package —
// there is no JS runner here — so these assert the lines that carry the behaviour rather than the
// behaviour itself.
func TestModalDismissalAndFocusAreWired(t *testing.T) {
	app := readAsset(t, "js/app.js")

	for _, want := range []struct{ src, why string }{
		{"if (e.defaultPrevented) return;", "showDialog's own trap runs on the capture phase and " +
			"calls preventDefault; without this check, Escape on a confirm dialog opened over the " +
			"edit-client modal closes both the dialog and the modal that asked the question"},
		{"if (activeDialog) return;", "showDialog only calls preventDefault on the two Tab wrap " +
			"cases, so mid-list presses reach this handler unmarked and the static modal underneath " +
			"would drag focus out of the dialog in front of it"},
		{"e.key !== 'Escape' && e.key !== 'Tab'", "Tab is half of this handler — aria-modal claims " +
			"the rest of the page is inert, and the trap is what makes that true for the keyboard"},
		{"closeBtn.click();", "the handlers reuse the modal's own close button rather than hiding it " +
			"themselves, so whatever else that button does still happens"},
		{"attributeFilter: ['class']", "the observer watches the class attribute, which is how all " +
			"five modals are shown and hidden"},
		{"modalReturnFocus.set(modal, document.activeElement)", "focus has to be recorded on open " +
			"or there is nowhere to return it to when the modal closes"},
	} {
		if !strings.Contains(app, want.src) {
			t.Errorf("js/app.js no longer contains %q — %s.", want.src, want.why)
		}
	}

	// The autofocus must not override the show functions' own choice. showChangePwdModal focuses
	// #current-admin-pass and runs synchronously; the observer callback is a microtask, so it sees
	// that focus and this guard is what makes it leave it alone.
	if !strings.Contains(app, "if (!panel.contains(document.activeElement)) {") {
		t.Error("the modal focus manager no longer checks whether focus is already inside the panel " +
			"before moving it, so it overrides the field each show function deliberately picked.")
	}
}

// initModalA11y attaches the observers, and it has to run before the first modal is shown.
// checkAuthAndBoot calls showLoginModal synchronously when there is no token, so an observer
// attached after it never sees the class change that opened the overlay — and the login modal is
// precisely the one that most needs the trap.
func TestModalFocusManagerIsInstalledBeforeTheFirstModalOpens(t *testing.T) {
	app := readAsset(t, "js/app.js")

	init := strings.Index(app, "initModalA11y();")
	boot := strings.Index(app, "checkAuthAndBoot();")
	if init < 0 {
		t.Fatal("js/app.js never calls initModalA11y(), so no static modal manages focus at all.")
	}
	if boot < 0 {
		t.Fatal("js/app.js never calls checkAuthAndBoot() — the scan is broken.")
	}
	if init > boot {
		t.Error("initModalA11y() is called after checkAuthAndBoot(). checkAuthAndBoot unhides the " +
			"login overlay synchronously, so the observer misses it, and the login gate — the one " +
			"modal that must not leak Tab into the dashboard — is the one left unmanaged.")
	}

	// And it cannot move into bootDashboard, which runs only once a token is in hand.
	if strings.Contains(functionBody(t, app, "bootDashboard"), "initModalA11y") {
		t.Error("initModalA11y() is called from bootDashboard, which runs only after authentication " +
			"succeeds. The login modal would never be managed.")
	}
}

// modalPopoverRe matches an element marked as a popover nested inside a modal.
var modalPopoverRe = regexp.MustCompile(`<div\s[^>]*id="([a-zA-Z0-9_-]+)"[^>]*\sdata-modal-popover`)

// A modal can contain its own popover, and Escape inside one has to mean "close the popover" —
// closing the whole modal would discard a half-filled client edit because the operator dismissed a
// calendar. The expiry datepicker is the only such popover today, and it is marked in the markup so
// the next one participates by carrying an attribute rather than by someone remembering this
// handler exists.
func TestEscapeClosesANestedPopoverBeforeTheModal(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")

	found := values(modalPopoverRe, html)
	if len(found) == 0 {
		t.Fatal("no element in web/index.html carries data-modal-popover. #datepicker-popup lives " +
			"inside edit-client-modal, so without the marker Escape in the calendar closes the " +
			"client edit form instead of the calendar.")
	}
	for _, id := range found {
		// A popover that is not hidden at rest is permanently open, and isShown would read it as
		// the thing Escape should close on every press.
		if !strings.Contains(modalTag(t, html, id), `class="hidden `) {
			t.Errorf("#%s carries data-modal-popover but does not start hidden, so Escape would "+
				"swallow every press in the modal that contains it.", id)
		}
	}

	nested := strings.Index(app, "if (closeNestedPopover(modal)) {")
	closeBtn := strings.Index(app, "const closeBtn = modalCloseControl(modal);")
	if nested < 0 {
		t.Fatal("the Escape handler no longer calls closeNestedPopover, so a press meant for the " +
			"datepicker closes edit-client-modal and loses whatever was typed into it.")
	}
	if closeBtn < 0 {
		t.Fatal("the Escape handler no longer resolves the modal's close control — the scan is broken.")
	}
	if nested > closeBtn {
		t.Error("closeNestedPopover runs after the modal's own close control in the Escape handler, " +
			"so the modal closes first and the popover check never gets the press.")
	}
}

// modalPanelTag returns the opening tag of the panel inside a modal: the first <div> that follows
// the container's own opening tag. All five are built the same way — one backdrop container, one
// panel child — which is the assumption modalPanel() makes in app.js too.
func modalPanelTag(t *testing.T, html, id string) string {
	t.Helper()

	tag := modalTag(t, html, id)
	rest := html[strings.Index(html, tag)+len(tag):]
	panel := regexp.MustCompile(`<div\s[^>]*>`).FindString(rest)
	if panel == "" {
		t.Fatalf("#%s has no panel <div> after its container tag", id)
	}
	return panel
}

// modalScrollExempt lists the modals whose panel deliberately does not scroll itself, with where
// the scrolling happens instead.
var modalScrollExempt = map[string]string{
	"diagnostics-modal": "the panel is flex flex-col and the scroll lives on #diag-items-list, so " +
		"the header and the Run Test button stay put while the results move",
}

// Every modal panel is centred by its backdrop with flex items-center, and a centred box that is
// taller than the viewport overflows off BOTH ends — the top goes above the screen and the bottom
// below it, and neither is reachable, because the overflow belongs to a box the page cannot scroll.
//
// Three of these five panels had no height cap. The credential modal is the one that mattered: it
// is five fields, two hint blocks and two buttons, it is where an operator with a weak password is
// sent on first login, and it cannot be dismissed in that mode. On a phone that is a dashboard
// with no way in and no way out — the SAVE button below the fold of an un-closable dialog.
func TestModalPanelsCannotOverflowAShortViewport(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")

	for _, id := range modalIDList(t, app) {
		panel := modalPanelTag(t, html, id)

		if !strings.Contains(panel, "max-h-[") {
			t.Errorf("the panel inside #%s has no max-h. Its backdrop centres it, so on a viewport "+
				"shorter than the panel it overflows past both edges of the screen and neither end "+
				"can be scrolled to.", id)
		}

		if why, ok := modalScrollExempt[id]; ok {
			if strings.Contains(panel, "overflow-y-auto") {
				t.Errorf("#%s's panel now scrolls itself, which modalScrollExempt says it does not "+
					"(%s). Drop the entry.", id, why)
			}
			continue
		}
		if !strings.Contains(panel, "overflow-y-auto") {
			t.Errorf("the panel inside #%s caps its height but has no overflow-y-auto, so the part "+
				"of the form past the cap is clipped instead of scrollable — which is worse than "+
				"overflowing, because nothing on screen suggests there is more.\nEither add it, or "+
				"move the scroll to an inner container and record that in modalScrollExempt.", id)
		}
	}
}
