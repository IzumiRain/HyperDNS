package web

import (
	"strings"
	"testing"
)

// The live query console had three variants of one bug: a control that reads its own value at
// the wrong moment does nothing observable, and nothing anywhere reports it.
//
// The filter dropdown and the search box had no event listeners at all. Both were read inside
// the function that appended an arriving row, so they applied to queries that had not happened
// yet and never to the eighty rows already on screen. Selecting BLOCK left every DIRECT row in
// place; typing a domain into the search box changed nothing until the next query came in,
// which on a resolver serving one household is minutes. The control looked broken because,
// from the operator's side, it was.
//
// The same append path cleared the "Listening for live DNS queries..." placeholder *before* it
// applied the filter, so a query that was then filtered out took the placeholder with it: the
// table went blank, with no row of any kind, and stayed blank.
//
// And Clear emptied the table's markup directly. The placeholder was recognised by matching
// the string "Listening" against the first row's text, so once the markup was gone it could
// never come back — a cleared stream and a dead daemon looked exactly alike.
//
// All three are fixed by holding the queries as data (streamBuffer) and rendering the table
// from it. These tests pin the parts of that arrangement which can be checked without a
// JavaScript runtime: that the two controls re-render, that Clear empties the buffer rather
// than the markup, that the placeholder is identified by a class both files agree on, and that
// the SSE handlers feed the buffer instead of writing to the table themselves.

// streamToolbarFilters are the two controls whose entire purpose is to change what is already
// on screen. A control like this is not wired merely by being read somewhere.
var streamToolbarFilters = []string{"stream-filter", "stream-search"}

func TestStreamFilterControlsRerenderExistingRows(t *testing.T) {
	body := functionBody(t, readAsset(t, "js/app.js"), "initEventListeners")

	for _, id := range streamToolbarFilters {
		wired := false
		for line := range strings.SplitSeq(body, "\n") {
			if !strings.Contains(line, "'"+id+"'") {
				continue
			}
			if strings.Contains(line, "addEventListener") && strings.Contains(line, "renderQueryStream") {
				wired = true
				break
			}
		}
		if !wired {
			t.Errorf("#%s has no listener in initEventListeners that calls renderQueryStream.\n"+
				"Without one it only affects rows that arrive after it changes: the queries "+
				"already in the table are never re-filtered, so on a quiet resolver the control "+
				"appears to do nothing at all.", id)
		}
	}
}

// Clear has to empty the buffer, not the markup. Emptying the markup removes the placeholder
// as well, and the render path is the only thing that puts one back.
func TestStreamClearEmptiesTheBuffer(t *testing.T) {
	body := functionBody(t, readAsset(t, "js/app.js"), "initEventListeners")

	if !strings.Contains(body, "'stream-clear-btn'") {
		t.Fatal("initEventListeners no longer binds #stream-clear-btn — the button does nothing")
	}
	if !strings.Contains(body, "streamBuffer = []") {
		t.Error("the #stream-clear-btn handler does not empty streamBuffer. Clearing the table's " +
			"markup instead leaves a blank panel that no longer matches the buffer, and the " +
			"placeholder only returns from renderQueryStream.")
	}
	if !strings.Contains(body, "renderQueryStream()") {
		t.Error("initEventListeners never calls renderQueryStream(), so nothing redraws the " +
			"table after the buffer is emptied — Clear would leave the old rows on screen.")
	}
}

// The placeholder used to be recognised by its wording. Both files now name a class instead,
// which is the only reason rewording the copy is safe.
func TestStreamPlaceholderIsIdentifiedByClass(t *testing.T) {
	app := readAsset(t, "js/app.js")
	html := readAsset(t, "index.html")

	if strings.Contains(app, "includes('Listening')") {
		t.Error("js/app.js still identifies the stream placeholder by matching the word " +
			"'Listening' in the row's text. Reword the copy in index.html and the placeholder " +
			"is never removed again — it stays pinned above the first real query, and nothing " +
			"throws or logs. Use the stream-placeholder class.")
	}
	for _, f := range []struct{ name, body string }{
		{"web/index.html", html},
		{"web/js/app.js", app},
	} {
		if !strings.Contains(f.body, "stream-placeholder") {
			t.Errorf("%s does not mention the stream-placeholder class. Both sides have to agree "+
				"on it: index.html ships the first one and app.js has to recognise it to replace "+
				"it with the first query that arrives.", f.name)
		}
	}
	if !strings.Contains(app, "querySelector('.stream-placeholder')") {
		t.Error("js/app.js no longer looks up .stream-placeholder, so nothing tells a table " +
			"holding a placeholder apart from one holding queries — the first arriving row " +
			"would be inserted above the placeholder rather than replacing it.")
	}
}

// The SSE handlers are the only writers into the stream, and there are four of them: the
// `query` event, the `history` batch, and an onmessage fallback that handles both shapes. Each
// used to write to the table itself — two of them by assigning innerHTML — which is what let
// the buffer and the view disagree. They must all go through the buffer now, or a filter change
// redraws from a record that never saw half the queries.
func TestLiveStreamHandlersFeedTheBuffer(t *testing.T) {
	body := functionBody(t, readAsset(t, "js/app.js"), "startLiveStream")

	for _, fn := range []string{"pushStreamQuery", "seedStreamQueries"} {
		if !strings.Contains(body, fn) {
			t.Errorf("startLiveStream does not call %s, so an arriving query does not reach "+
				"streamBuffer and the filter has nothing to re-filter.", fn)
		}
	}
	if strings.Contains(body, "innerHTML") {
		t.Error("startLiveStream writes innerHTML directly. That is how the history batch used " +
			"to land on screen without being recorded: the rows were visible, the buffer was " +
			"empty, and the first filter change wiped them. Hand the payload to " +
			"seedStreamQueries and let it render.")
	}
	if strings.Contains(body, "getElementById('stream-tbody')") {
		t.Error("startLiveStream looks up the table body. Nothing in the SSE path needs it — " +
			"the render path owns the table, and reaching past it is what lets the two diverge.")
	}
}
