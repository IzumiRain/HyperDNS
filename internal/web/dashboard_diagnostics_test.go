package web

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Gaming Diagnostic Suite is the panel an operator opens to decide whether the VPS route
// is good enough to play on, and it had the same two defects the live query stream had: a
// control that can be pressed while it is already working, and a number left on screen after
// it stopped being true.
//
// handleDiagnosticsRun dials eight TCP endpoints with a 2.5 s timeout each. They run in
// parallel, so a healthy run answers in well under a second — but a route that black-holes
// SYNs takes the full 2.5 s, which is exactly the run an operator reruns. Nothing disabled
// the Run Test button for that window, and nothing serialised the requests: two runs were in
// flight, both writing #diag-items-list, and the list ended up showing whichever response
// *finished* last rather than whichever run started last. A slow first run landing after a
// fast second one replaced fresh numbers with stale ones, silently.
//
// The score banner was worse, because it failed in the direction of a false positive. It was
// only ever written on success, so a run that was refused — an expired session answers 401
// here — left the previous run's grade sitting directly above the error text. "88% /
// EXCELLENT (A+)" above "The diagnostic run was refused" is not an ambiguous display; it is a
// panel reporting a measurement it did not take.

// goFuncBody is the Go-side twin of functionBody: it slices a top-level declaration from its
// header to the first line that closes a brace in column 0. gofmt guarantees that line is the
// declaration's own closing brace, because everything nested is indented with tabs. `decl` is
// the whole header up to and including the opening paren or brace, so it works for a func and
// for a struct type alike.
func goFuncBody(t *testing.T, src, decl string) string {
	t.Helper()

	start := strings.Index(src, "\n"+decl)
	if start < 0 {
		t.Fatalf("could not find %q — the scan is broken", decl)
	}
	end := strings.Index(src[start+1:], "\n}")
	if end < 0 {
		t.Fatalf("could not find the end of %q", decl)
	}
	return src[start : start+1+end]
}

// readGoSource reads a file from this package's own directory. `go test` runs with the
// package directory as the working directory, so the plain name is enough. The property
// below is a contract between server.go and js/app.js and only one of the two is embedded;
// portal_i18n_test.go reads the bundle definitions the same way, for the same reason —
// a Go value cannot be inspected for which of its fields the *templates* mention.
func readGoSource(t *testing.T, name string) string {
	t.Helper()

	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// diagJSONKeyRe matches a quoted key in the response map literal. The colon has to be
// followed by whitespace, which is what keeps it off the ":443" inside every target address —
// there the colon is inside the string, not after its closing quote.
var diagJSONKeyRe = regexp.MustCompile(`"([a-z_]+)":\s`)

// diagTagRe matches a json struct tag.
var diagTagRe = regexp.MustCompile(`json:"([a-z_]+)"`)

// diagUnusedKeys are the response fields the panel deliberately does not show, each with the
// reason. The list is short on purpose: an entry means someone looked at the value and decided
// it has no place on screen — which is precisely what nobody did for avg_latency_ms, reachable
// and total, and why they went unshown for as long as they did.
var diagUnusedKeys = map[string]string{
	"timestamp": "the run is synchronous from the operator's side — spinner, then results — so a " +
		"clock on the banner would only ever say 'just now'",
}

// The panel used to read exactly two fields out of this response: overall_score and
// overall_quality. The server also computes and sends avg_latency_ms, reachable and total —
// average handshake time across the endpoints that answered, and how many of them did — and
// all three were dropped on the floor on every run. Average latency is the number this panel
// exists to report: a gamer opening it wants to know the route's ping, and the grade cannot
// say whether 75% means "six answered fast" or "six answered at 400 ms".
//
// Derived from server.go rather than listed here, so adding a field to the response and
// forgetting the panel fails this test instead of quietly measuring something nobody sees.
func TestDiagnosticsPanelShowsEveryFieldTheServerSends(t *testing.T) {
	app := readAsset(t, "js/app.js")
	server := readGoSource(t, "server.go")

	body := goFuncBody(t, server, "func (ws *WebServer) handleDiagnosticsRun(")
	keys := values(diagJSONKeyRe, body)
	if len(keys) < 6 {
		t.Fatalf("only %d response keys parsed out of handleDiagnosticsRun — the scan is broken, "+
			"which would make this test vacuously pass", len(keys))
	}

	for _, key := range keys {
		if why, ok := diagUnusedKeys[key]; ok {
			if strings.Contains(app, "report."+key) {
				t.Errorf("js/app.js now reads report.%s, which diagUnusedKeys says it does not "+
					"(%s). Drop the entry.", key, why)
			}
			continue
		}
		if !strings.Contains(app, "report."+key) {
			t.Errorf("handleDiagnosticsRun sends %q and js/app.js never reads report.%s.\n"+
				"The server measures it on every run and the panel throws it away — which is "+
				"how avg_latency_ms, reachable and total went unshown. Render it, or add it to "+
				"diagUnusedKeys with the reason it does not belong on screen.", key, key)
		}
	}

	// The per-result fields, from the struct rather than the map. r is the loop variable in
	// renderDiagnosticsReport, and r.name/r.target are also in storedValueExprs, so those two
	// are pinned twice over — here for presence and there for escaping.
	rowKeys := values(diagTagRe, goFuncBody(t, server, "type diagResult struct {"))
	if len(rowKeys) < 4 {
		t.Fatalf("only %d json tags parsed out of diagResult — the scan is broken", len(rowKeys))
	}
	for _, key := range rowKeys {
		if !strings.Contains(app, "r."+key) {
			t.Errorf("diagResult carries %q and js/app.js never reads r.%s, so that column of "+
				"the result is measured and dropped.", key, key)
		}
	}
}

// A second run started while the first is in flight is not a harmless duplicate: both write
// the same container, and the one that wins is the one that finishes last.
func TestDiagnosticsRunIsSerialised(t *testing.T) {
	app := readAsset(t, "js/app.js")

	if !strings.Contains(app, "let diagRunning = false;") {
		t.Fatal("js/app.js no longer declares diagRunning. Without it two runs can be in flight " +
			"at once, and the results list shows whichever response finished last rather than " +
			"whichever run the operator started last.")
	}

	body := functionBody(t, app, "runFullDiagnostics")
	for _, want := range []struct{ src, why string }{
		{"if (diagRunning) return;", "the second run has to be refused at the top, before the " +
			"spinner overwrites the first run's results"},
		{"diagRunning = true;", "the gate has to close for the whole of the request"},
		{"} finally {", "the gate has to reopen on the error paths too — a leaked flag makes " +
			"Run Test dead for the lifetime of the page, with no way back short of a reload"},
		{"diagRunning = false;", "the gate has to reopen"},
	} {
		if !strings.Contains(body, want.src) {
			t.Errorf("runFullDiagnostics does not contain %q — %s.", want.src, want.why)
		}
	}
}

// The button is the operator's only feedback that a press registered. The spinner replaces the
// results list, which on a rerun looks identical to the list already being replaced, so a
// press during a run produced no visible change whatsoever.
func TestDiagnosticsRerunButtonIsDisabledWhileRunning(t *testing.T) {
	body := functionBody(t, readAsset(t, "js/app.js"), "runFullDiagnostics")

	if !strings.Contains(body, "rerunBtn.disabled = true;") {
		t.Error("runFullDiagnostics never disables #rerun-diagnostics-btn. A run takes up to " +
			"2.5 s when a route black-holes SYNs, and that is precisely the run an operator " +
			"presses again.")
	}
	if !strings.Contains(body, "rerunBtn.disabled = false;") {
		t.Error("runFullDiagnostics never re-enables #rerun-diagnostics-btn, so one failed run " +
			"leaves the button dead for the life of the page.")
	}
	// Re-enabling only on the success path is the same leak with a narrower window.
	tail := body[strings.Index(body, "} finally {"):]
	if !strings.Contains(tail, "rerunBtn.disabled = false;") {
		t.Error("#rerun-diagnostics-btn is re-enabled outside the finally block, so a refused " +
			"run or a dropped connection leaves it disabled.")
	}
}

// The grade is the one number on this panel an operator acts on, and it used to outlive the
// run that produced it.
func TestDiagnosticsClearsTheScoreBeforeAndOnFailure(t *testing.T) {
	body := functionBody(t, readAsset(t, "js/app.js"), "runFullDiagnostics")

	if !strings.Contains(body, "scoreEl.innerText = '--%'") {
		t.Error("runFullDiagnostics does not reset #diag-score before it asks the server. The " +
			"previous run's grade stays on screen for the whole of the next run, and if that " +
			"run fails it stays for good — a score with no run behind it, which is worse than " +
			"no score.")
	}
	if !strings.Contains(body, "'Test failed'") {
		t.Error("runFullDiagnostics does not mark #diag-quality as failed when the run is " +
			"refused or unreachable. The error text lands in the results list while the banner " +
			"still reads like a completed measurement.")
	}

	// The failure copy has to reach the DOM escaped: errorMessage returns whatever string the
	// response body carried, and this one is assigned to innerHTML rather than textContent.
	if !strings.Contains(body, "${escapeHTML(msg)}") {
		t.Error("the diagnostics failure message is interpolated into innerHTML without " +
			"escapeHTML. errorMessage returns the server's own error text, so a handler that " +
			"echoes part of a request back would render it as markup here.")
	}
}
