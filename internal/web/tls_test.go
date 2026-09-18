package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"hyperdns/internal/database"
)

// The subject here is the argument handling in tls.go, which exists because this is
// the one place the daemon runs another program — with the daemon's own privileges,
// root on a normal install, since the resolver binds port 53.
//
// No test in this file runs certbot. The two handler tests hold ws.acmeRunning before
// they send anything, so startACMEIssuance refuses at the single-flight gate whatever
// the machine running the suite happens to have installed. What is pinned instead is
// the pair of things that decide what certbot would have received: the validators, and
// certbotArgs.

func TestValidACMEDomainRefusesHostileAndMalformedNames(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", "cannot be empty"},
		{"whitespace only", "   ", "cannot be empty"},
		{"reads as an option", "-example.com", "cannot start with '-'"},
		{"certbot hook", "--deploy-hook=/bin/sh", "cannot start with '-'"},
		{"wildcard", "*.example.com", "DNS-01"},
		{"trailing dot", "example.com.", "cannot end with '.'"},
		{"ipv4 literal", "192.0.2.1", "IP address"},
		{"ipv6 literal", "2001:db8::1", "IP address"},
		{"no dot", "localhost", "fully qualified"},
		{"empty label", "dns..example.com", "empty part"},
		{"leading dot", ".example.com", "empty part"},
		{"space in a label", "dns example.com", "only letters"},
		{"underscore", "dns_1.example.com", "only letters"},
		{"non-ascii", "exämple.com", "punycode"},
		{"label ends in a hyphen", "dns-.example.com", "start or end with '-'"},
		{"over 253 bytes", strings.Repeat("a.", 127) + "com", "longer than 253"},
		{"label over 63 bytes", strings.Repeat("a", 64) + ".example.com", "63 characters or fewer"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validACMEDomain(tc.in)
			if err == nil {
				t.Fatalf("validACMEDomain(%q) = %q, want a refusal", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validACMEDomain(%q) said %q, want it to mention %q", tc.in, err, tc.want)
			}
		})
	}
}

// The accepted set is as much of the test as the refused set: a validator that turned
// away xn--80ak6aa92e.com, or a name with hyphens or digits in it, would be refusing
// certificates for domains an operator legitimately owns.
func TestValidACMEDomainNormalisesWhatItAccepts(t *testing.T) {
	cases := map[string]string{
		"  DNS.Example.COM  ": "dns.example.com",
		"a-b.c-d.example.com": "a-b.c-d.example.com",
		"xn--80ak6aa92e.com":  "xn--80ak6aa92e.com",
		"1.2.3.example.com":   "1.2.3.example.com",
		"x.io":                "x.io",
	}

	// The two limits, at the last byte each one allows: a 63-byte label and a 253-byte
	// name. Off-by-one here is a certificate the operator cannot request.
	longestLabel := strings.Repeat("a", 63) + ".example.com"
	longestName := strings.Repeat("ab.", 83) + "abcd"
	cases[longestLabel] = longestLabel
	cases[longestName] = longestName

	if len(longestName) != maxACMEDomainLength {
		t.Fatalf("the boundary case is %d bytes, not %d, so it is not testing the limit", len(longestName), maxACMEDomainLength)
	}

	for in, want := range cases {
		got, err := validACMEDomain(in)
		if err != nil {
			t.Errorf("validACMEDomain(%q) refused a legitimate name: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("validACMEDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidACMEEmailRefusesWhatCertbotWouldMisread(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"reads as an option", "-m@example.com", "cannot start with '-'"},
		{"two at signs", "a@b@example.com", "exactly one '@'"},
		{"no at sign", "operator.example.com", "exactly one '@'"},
		{"no local part", "@example.com", "needs a name and a domain"},
		{"no host", "operator@", "needs a name and a domain"},
		{"host is not qualified", "operator@localhost", "fully qualified"},
		{"embedded space", "oper ator@example.com", "spaces or control characters"},
		{"embedded newline", "oper\nator@example.com", "spaces or control characters"},
		{"over 254 bytes", strings.Repeat("a", 250) + "@example.com", "longer than 254"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validACMEEmail(tc.in)
			if err == nil {
				t.Fatalf("validACMEEmail(%q) = %q, want a refusal", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validACMEEmail(%q) said %q, want it to mention %q", tc.in, err, tc.want)
			}
		})
	}
}

// An empty contact is allowed — certbotArgs then registers the account without one —
// and an address that is given must survive as typed, because the part before '@' is
// case-sensitive, so lower-casing it can send the expiry warnings nowhere.
func TestValidACMEEmailAcceptsEmptyAndPreservesCase(t *testing.T) {
	if got, err := validACMEEmail("   "); err != nil || got != "" {
		t.Errorf(`validACMEEmail("   ") = %q, %v — want "", nil`, got, err)
	}
	if got, err := validACMEEmail(" Ali.R+dns@Example.com "); err != nil || got != "Ali.R+dns@Example.com" {
		t.Errorf("validACMEEmail altered a valid address: %q, %v", got, err)
	}
}

// v2.2.0: the certbot argv-builder is gone with certbot itself — issuance is
// the embedded ACME client now (internal/service/acme). The guarantees this
// test used to pin survive elsewhere: the contact email rides the manager
// (acme package tests), and the save path is still pinned by
// TestTLSIssueStoresTheDomainAndReportsIssuanceHonestly below.

func TestTLSIssueRefusesABadDomainWithoutStoringIt(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	w := postJSON(t, h, "/api/tls/issue",
		`{"domain":"--deploy-hook=curl example.com","email":"operator@example.com"}`, tok)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/tls/issue = %d, want 400 — %s", w.Code, w.Body.String())
	}
	if msg, _ := decodeBody(t, w)["error"].(string); msg == "" {
		t.Error("a refusal with no reason in it")
	}

	if got := ws.tlsSettings.GetDomain(); got != "" {
		t.Errorf("the refused domain was applied anyway: %q", got)
	}
	if ws.db.HasSetting("tls") {
		var stored database.TLSSettings
		if err := ws.db.GetSetting("tls", &stored); err != nil {
			t.Fatalf(`reading back the "tls" record: %v`, err)
		}
		t.Errorf(`the refused domain reached the "tls" record: %q`, stored.Domain)
	}
}

// The response contract, which exists because the old one had none: the save either
// happened or the request failed, and issuance is reported separately with a reason.
// "✓ SSL issuance triggered in background!" used to appear whether or not certbot was
// installed, whether or not port 80 was free, and whether or not the store succeeded.
func TestTLSIssueStoresTheDomainAndReportsIssuanceHonestly(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	// Hold the gate. Whatever this machine has installed, startACMEIssuance now
	// refuses before it can reach certbot — no test spawns a real issuance.
	ws.acmeRunning.Store(true)
	defer ws.acmeRunning.Store(false)

	w := postJSON(t, h, "/api/tls/issue",
		`{"domain":"  DNS.Example.COM  ","email":" Ali.R@Example.com "}`, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/tls/issue = %d, want 200 — %s", w.Code, w.Body.String())
	}

	body := decodeBody(t, w)
	if body["success"] != true {
		t.Errorf("success = %v, want true", body["success"])
	}
	if body["domain"] != "dns.example.com" {
		t.Errorf("domain = %v, want the normalised name", body["domain"])
	}
	if body["issuing"] != false {
		t.Errorf("issuing = %v while no run could start", body["issuing"])
	}
	if detail, _ := body["detail"].(string); detail == "" {
		t.Error("issuing was false and detail gave no reason, which is the old handler's failure")
	}

	// Both the live struct and the stored record, because the daemon reads one and a
	// restart reads the other. SetACME writes them under one lock so they cannot
	// disagree; if the persist step ever failed the handler answers 500 and rolls the
	// struct back, so a 200 means both.
	domain, email := ws.tlsSettings.ACMEContact()
	if domain != "dns.example.com" || email != "Ali.R@Example.com" {
		t.Errorf("in-memory contact = %q / %q, want dns.example.com / Ali.R@Example.com", domain, email)
	}

	if !ws.db.HasSetting("tls") {
		t.Fatal(`the "tls" record was never written, so a restart would forget the domain`)
	}
	var stored database.TLSSettings
	if err := ws.db.GetSetting("tls", &stored); err != nil {
		t.Fatalf(`reading back the "tls" record: %v`, err)
	}
	if stored.Domain != "dns.example.com" || stored.Email != "Ali.R@Example.com" {
		t.Errorf("stored contact = %q / %q, want the normalised pair", stored.Domain, stored.Email)
	}
}

// tlsUnusedKeys are the response fields the panel deliberately does not read, with the
// reason. "success" duplicates the status line: the handler sends it only on the path
// that already answered 200, and the panel has branched on res.ok before it parses
// anything.
var tlsUnusedKeys = map[string]string{
	"success": "it repeats the 200 the panel has already branched on",
	// v2.2.0: the echoed-back normalised domain is no longer read from the
	// response body — the shared bindLEButton refreshes the whole config
	// (loadConfig) after a run, and renderConfig is what puts the name in
	// the box, from the same source the rest of the page uses.
	"domain": "the button re-reads the name from /api/config instead of the echo",
}

// The response and the panel are two halves of one contract and only one half is Go, so
// nothing but a test like this connects them. The old panel read none of the four keys:
// it checked res.ok, and on anything else did nothing at all — a refused domain produced
// a "Requesting…" toast and then silence.
//
// The keys are derived from tls.go rather than listed here, so adding one to the response
// and forgetting the panel fails this test instead of going unnoticed.
func TestTLSPanelReadsEveryFieldTheHandlerAnswers(t *testing.T) {
	handler := goFuncBody(t, readGoSource(t, "tls.go"), "func (ws *WebServer) handleTLSSettings(")
	keys := values(diagJSONKeyRe, handler)
	if len(keys) < 4 {
		t.Fatalf("only %d response keys parsed out of handleTLSSettings — the scan is broken, "+
			"which would make this test vacuously pass", len(keys))
	}

	// Looked for inside the button-binding code, rather than anywhere in a
	// five-thousand-line file: a body.detail belonging to some other panel must
	// not stand in for this one. The handler moved from initEventListeners to
	// bindLEButton when the three Let's Encrypt buttons (panel, subscription,
	// DoH/DoT) began sharing it; both scopes are scanned so whichever holds
	// the binding tomorrow still satisfies the contract.
	appJS := readAsset(t, "js/app.js")
	panel := functionBody(t, appJS, "initEventListeners")
	bindStart := strings.Index(appJS, "window.bindLEButton = function")
	if bindStart >= 0 {
		bindEnd := strings.Index(appJS[bindStart:], "\n  window.bindLEButton(document")
		if bindEnd < 0 {
			bindEnd = strings.Index(appJS[bindStart:], "\n\n")
		}
		if bindEnd >= 0 {
			panel += "\n" + appJS[bindStart:bindStart+bindEnd]
		}
	}

	for _, key := range keys {
		if why, ok := tlsUnusedKeys[key]; ok {
			if strings.Contains(panel, "body."+key) {
				t.Errorf("the SSL panel now reads body.%s, which tlsUnusedKeys says it does not "+
					"(%s). Drop the entry.", key, why)
			}
			continue
		}
		if !strings.Contains(panel, "body."+key) {
			t.Errorf("handleTLSSettings answers %q and the SSL panel never reads body.%s.\n"+
				"issuing is the whole difference between a certificate having been requested and "+
				"a domain merely having been stored, and detail is the only place the reason for "+
				"the second appears. Without them the panel is back to announcing success for "+
				"both.", key, key)
		}
	}
}

// showToastToneRe matches the tone argument of a single-line showToast call. Calls split
// across lines are missed by construction, which is why the count is asserted below: a
// reformatting pass that wrapped every call would otherwise leave this test checking an
// empty set and still passing.
var showToastToneRe = regexp.MustCompile(`showToast\([^\n]*?,\s*'([a-z]+)'\s*\)`)

// A tone showToast does not recognise fails silently in the only way a toast can: it
// falls through to the else branch and is drawn as the cyan informational one. "The
// domain was saved and no certificate was requested" would then look exactly like
// "Copied!", which is the same defect this panel already had, one layer down.
//
// The set of tones is derived from the call sites, so a new one has to be given a branch
// rather than merely being passed.
func TestEveryToastToneHasABranchInShowToast(t *testing.T) {
	app := readAsset(t, "js/app.js")

	calls := values(showToastToneRe, app)
	if len(calls) < 40 {
		t.Fatalf("only %d showToast calls with a literal tone found in js/app.js — the scan is "+
			"broken", len(calls))
	}

	tones := map[string]bool{}
	for _, tone := range calls {
		tones[tone] = true
	}
	if len(tones) < 3 {
		t.Fatalf("only %d distinct tone(s) found — the scan is broken", len(tones))
	}

	body := functionBody(t, app, "showToast")
	for tone := range tones {
		// 'info' is the parameter's default and the else branch, so it is handled by
		// having no branch of its own.
		if tone == "info" {
			continue
		}
		// Matched as the comparison rather than as the bare literal, so a comment naming a
		// tone cannot stand in for the branch that handles it.
		if !strings.Contains(body, "=== '"+tone+"'") {
			t.Errorf("at least one call site passes the tone %q and showToast never compares against "+
				"it, so those toasts are drawn as the informational cyan one. Either give it a "+
				"branch or stop passing it.", tone)
		}
	}
}
