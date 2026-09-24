package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// The dashboard is embedded, and until now it was served by http.FileServer. That
// combination has a failure mode that no test would have caught by asking for a
// page and checking the body: embed.FS reports a zero modification time,
// http.ServeContent omits Last-Modified when the time is zero, and FileServer never
// generates an ETag — so the response was always a complete, uncompressed copy of
// every asset, on every reload, forever. It worked. It was just expensive in
// exactly the place this project cannot afford it, which is the link between an
// Iranian VPS and the operator's browser.
//
// These tests pin the two halves of the fix (a validator and a pre-built gzip body)
// and, more importantly, the details of conditional-request handling that are easy
// to implement almost-correctly: a nearly-right ETag comparison silently answers
// 200 to every revalidation and undoes the whole feature while looking fine.

// bigJS is comfortably over the 1 KiB floor and highly compressible, standing in
// for the vendored libraries that dominate the real payload.
var bigJS = []byte(strings.Repeat("console.log('hyperdns');\n", 200))

func testAssets() *staticServer {
	return newStaticServer(fstest.MapFS{
		"index.html":       {Data: []byte("<!DOCTYPE html><title>HyperDNS</title>")},
		"js/app.js":        {Data: bigJS},
		"css/style.css":    {Data: []byte(strings.Repeat(".glass-panel{color:#00f0ff}\n", 100))},
		"js/tiny.js":       {Data: []byte("x=1")},
		"fonts/body.woff2": {Data: bytes.Repeat([]byte{0x77, 0x4f, 0x46, 0x32}, 600)},
	})
}

func get(t *testing.T, s *staticServer, path string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// A first request has to carry everything a browser needs to avoid the second one:
// the bytes, a validator to send back, and the instruction to revalidate rather
// than guess a lifetime. max-age or immutable would be wrong here — /js/app.js
// keeps its URL across builds, so an operator who upgrades the binary would keep
// being served the old panel out of their own cache with no way to know.
func TestStaticServesWithValidatorAndRevalidation(t *testing.T) {
	s := testAssets()

	w := get(t, s, "/js/app.js", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), bigJS) {
		t.Errorf("body = %d bytes, want the asset's %d", w.Body.Len(), len(bigJS))
	}
	if got := w.Header().Get("ETag"); got == "" || !strings.HasPrefix(got, `"`) {
		t.Errorf("ETag = %q, want a quoted strong validator", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	if got := w.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/javascript; charset=utf-8", got)
	}
	// Two representations share this URL, so a shared cache has to key on the
	// request's encoding or it will hand gzip bytes to a client that cannot read
	// them.
	if got := w.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Errorf("Vary = %q, want Accept-Encoding", got)
	}
	if got := w.Header().Get("Content-Length"); got != strconv.Itoa(len(bigJS)) {
		t.Errorf("Content-Length = %q, want %d", got, len(bigJS))
	}
}

// The point of the validator is the 304. Without this the feature is decorative.
func TestStaticAnswers304ForMatchingETag(t *testing.T) {
	s := testAssets()

	first := get(t, s, "/index.html", nil)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on first response")
	}

	// The three forms a real client or an intermediary can send. The weak prefix is
	// the one that bites: If-None-Match is compared weakly per RFC 9110 §13.1.2, so
	// a proxy that rewrites the tag to W/"…" must still get a 304. A server that
	// compares the raw strings answers 200 to every one of those revalidations and
	// quietly re-sends the whole payload.
	for _, header := range []string{etag, "W/" + etag, "*", `"stale", ` + etag} {
		w := get(t, s, "/index.html", http.Header{"If-None-Match": {header}})
		if w.Code != http.StatusNotModified {
			t.Errorf("If-None-Match: %s → %d, want 304", header, w.Code)
			continue
		}
		if w.Body.Len() != 0 {
			t.Errorf("If-None-Match: %s → %d body bytes, want none", header, w.Body.Len())
		}
		// A 304 that also declares a length or a type can contradict the entry the
		// client already holds.
		if got := w.Header().Get("Content-Length"); got != "" {
			t.Errorf("If-None-Match: %s → Content-Length %q on a 304, want none", header, got)
		}
		if got := w.Header().Get("Content-Type"); got != "" {
			t.Errorf("If-None-Match: %s → Content-Type %q on a 304, want none", header, got)
		}
		if got := w.Header().Get("ETag"); got != etag {
			t.Errorf("If-None-Match: %s → ETag %q on the 304, want %q", header, got, etag)
		}
	}

	// A tag that does not match must still produce the asset.
	if w := get(t, s, "/index.html", http.Header{"If-None-Match": {`"something-else"`}}); w.Code != http.StatusOK {
		t.Errorf("non-matching validator → %d, want 200", w.Code)
	}
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("response is not gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("reading gzip body: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("closing gzip reader: %v", err)
	}
	return out
}

// Compression is negotiated, not assumed. Two of these cases are the ones a
// substring check on Accept-Encoding would get wrong.
func TestStaticCompressesWhenAcceptedAndWorthwhile(t *testing.T) {
	s := testAssets()

	w := get(t, s, "/js/app.js", http.Header{"Accept-Encoding": {"gzip, deflate, br"}})
	if got := w.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if body := gunzip(t, w.Body.Bytes()); !bytes.Equal(body, bigJS) {
		t.Errorf("decompressed body is %d bytes, want the asset's %d", len(body), len(bigJS))
	}
	if w.Body.Len() >= len(bigJS) {
		t.Errorf("gzip body is %d bytes for a %d byte asset — it should not have been kept",
			w.Body.Len(), len(bigJS))
	}
	if got := w.Header().Get("Content-Length"); got != strconv.Itoa(w.Body.Len()) {
		t.Errorf("Content-Length = %q, want the compressed length %d", got, w.Body.Len())
	}

	// A client that says nothing gets the identity encoding.
	if got := get(t, s, "/js/app.js", nil).Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q with no Accept-Encoding, want none", got)
	}
}

// The three cases where compressing would be wrong even though the client asked.
func TestStaticSkipsCompressionWhenItWouldNotHelp(t *testing.T) {
	s := testAssets()

	cases := []struct {
		name, path, accept, why string
	}{
		{
			name: "explicitly refused",
			path: "/js/app.js",
			// "gzip;q=0" is how a client — or an operator debugging with curl — asks
			// for the identity encoding. Honouring it is the difference between a
			// diagnosable server and one that insists.
			accept: "gzip;q=0, identity",
			why:    "the client set q=0",
		},
		{
			name:   "below the size floor",
			path:   "/js/tiny.js",
			accept: "gzip",
			why:    "gzip's own header would dominate a 3-byte body",
		},
		{
			name:   "already-compressed format",
			path:   "/fonts/body.woff2",
			accept: "gzip",
			why:    "woff2 is compressed; a second pass costs CPU and adds bytes",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Accept-Encoding": {tc.accept}}
			w := get(t, s, tc.path, h)
			if got := w.Header().Get("Content-Encoding"); got != "" {
				t.Errorf("Content-Encoding = %q, want none — %s", got, tc.why)
			}
			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", w.Code)
			}
		})
	}
}

// The two encodings of one asset are two different representations, and each needs
// its own validator. This is the subtle one: if both were tagged identically, a
// shared cache holding the gzip body under that tag would answer a client that
// cannot decode gzip with compressed bytes — a blank panel with a console error, on
// some networks and not others, which is close to undiagnosable from a bug report.
func TestStaticValidatorsAreRepresentationSpecific(t *testing.T) {
	s := testAssets()

	identity := get(t, s, "/js/app.js", nil).Header().Get("ETag")
	compressed := get(t, s, "/js/app.js", http.Header{"Accept-Encoding": {"gzip"}}).Header().Get("ETag")

	if identity == "" || compressed == "" {
		t.Fatalf("missing validator: identity=%q gzip=%q", identity, compressed)
	}
	if identity == compressed {
		t.Fatalf("both encodings share the ETag %s", identity)
	}

	// The identity tag must not satisfy a request that will be answered with gzip.
	w := get(t, s, "/js/app.js", http.Header{
		"Accept-Encoding": {"gzip"},
		"If-None-Match":   {identity},
	})
	if w.Code != http.StatusOK {
		t.Errorf("identity validator + Accept-Encoding: gzip → %d, want 200", w.Code)
	}

	// And the pairing that does match still revalidates.
	w = get(t, s, "/js/app.js", http.Header{
		"Accept-Encoding": {"gzip"},
		"If-None-Match":   {compressed},
	})
	if w.Code != http.StatusNotModified {
		t.Errorf("gzip validator + Accept-Encoding: gzip → %d, want 304", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("304 carried %d body bytes", w.Body.Len())
	}
}

// HEAD is what a monitoring probe and a cache warmer use. It has to answer with the
// real headers, including the length the body would have had, and no body.
func TestStaticHeadSendsHeadersWithoutABody(t *testing.T) {
	s := testAssets()

	req := httptest.NewRequest(http.MethodHead, "/js/app.js", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD returned %d body bytes, want none", w.Body.Len())
	}
	if got := w.Header().Get("Content-Length"); got != strconv.Itoa(len(bigJS)) {
		t.Errorf("Content-Length = %q, want %d", got, len(bigJS))
	}
	if w.Header().Get("ETag") == "" {
		t.Error("HEAD carried no ETag")
	}
}

// Everything else is refused with an Allow header rather than being quietly treated
// as a GET. http.FileServer answered 405 for these too, so this pins existing
// behaviour rather than introducing it — but it also closes the door on a POST to
// /js/app.js being logged as a successful asset fetch.
func TestStaticRejectsWriteMethods(t *testing.T) {
	s := testAssets()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/js/app.js", strings.NewReader("x"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s → %d, want 405", method, w.Code)
		}
		if got := w.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s → Allow %q, want \"GET, HEAD\"", method, got)
		}
	}
}

// Path handling. There is no filesystem behind these bytes, so traversal has
// nothing to reach — but the request path is attacker-controlled and the map lookup
// must not be reachable with a key the walker never produced.
func TestStaticPathHandling(t *testing.T) {
	s := testAssets()

	cases := []struct {
		path string
		code int
	}{
		// "/" is the SPA entry point and resolves to index.html; the file's own name
		// works too. There are no directory listings and no /dir → /dir/ redirect,
		// which http.FileServer would have provided. Traversal collapses through
		// path.Clean and then simply misses the map. Keys are case-sensitive, because
		// embed keys are.
		{"/", http.StatusOK},
		{"/index.html", http.StatusOK},
		{"/js/app.js", http.StatusOK},
		{"/js/", http.StatusNotFound},
		{"/js", http.StatusNotFound},
		{"/nope.js", http.StatusNotFound},
		{"/../server.go", http.StatusNotFound},
		{"/js/../../internal/web/static.go", http.StatusNotFound},
		{"/JS/APP.JS", http.StatusNotFound},
	}

	for _, tc := range cases {
		if w := get(t, s, tc.path, nil); w.Code != tc.code {
			t.Errorf("GET %s → %d, want %d", tc.path, w.Code, tc.code)
		}
	}
}

// A daemon built without the dashboard — or with a broken embed — must answer 404
// rather than panic on a nil map. The resolver is the product; the panel going
// missing should not take DNS down with it.
func TestStaticSurvivesAnEmptyAssetTree(t *testing.T) {
	for name, s := range map[string]*staticServer{
		"nil fs":   newStaticServer(nil),
		"empty fs": newStaticServer(fstest.MapFS{}),
	} {
		if w := get(t, s, "/js/app.js", nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: GET asset → %d, want 404", name, w.Code)
		}
		if w := get(t, s, "/", nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: GET / → %d, want 404", name, w.Code)
		}

		w := httptest.NewRecorder()
		if s.serveIndex(w, httptest.NewRequest(http.MethodGet, "/dashboard", nil), "") {
			t.Errorf("%s: serveIndex reported success with no index.html", name)
		}
	}
}

// The SPA's own routes are the ones an operator actually reloads, and they were the
// worst case: each of the nine wrote index.html back out with a Content-Type and
// nothing else — no validator, no compression — because they bypassed the file
// server entirely. This runs against the real embedded dashboard rather than a
// synthetic tree, so it also proves the assets are present in the binary.
//
// v2.1 Phase 2 removed "/" from this list on purpose: the root serves the
// Matrix landing page now (landing_test.go), not the dashboard document.
func TestSPARoutesRevalidateThroughTheAssetServer(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()

	docCookie := &http.Cookie{Name: documentSessionCookie, Value: ws.sessions.Create()}
	for _, route := range []string{"/dashboard", "/panel", "/settings", "/clients"} {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		req.AddCookie(docCookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("GET %s → %d, want 200", route, w.Code)
		}
		etag := w.Header().Get("ETag")
		if etag == "" {
			t.Errorf("GET %s carried no ETag", route)
			continue
		}
		if got := w.Header().Get("Content-Encoding"); got != "gzip" {
			t.Errorf("GET %s → Content-Encoding %q, want gzip", route, got)
		}
		if body := gunzip(t, w.Body.Bytes()); !bytes.Contains(body, []byte("<!DOCTYPE html>")) {
			t.Errorf("GET %s did not return the dashboard document", route)
		}

		req = httptest.NewRequest(http.MethodGet, route, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("If-None-Match", etag)
		req.AddCookie(docCookie)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusNotModified {
			t.Errorf("reload of %s → %d, want 304", route, w.Code)
		}
	}
}

// web/css/tailwind.min.css was compiled into every binary by a css/* embed pattern
// and served to nobody: it is a Tailwind v2.2.19 build, and v2 has no slate palette
// at all, so it could not have styled this dashboard even if something had linked
// it. 2.9 MB of the shipped binary was that file, and in v2.1 the Play CDN JIT
// engine (js/tailwind.js) went the same way, replaced by the committed purged
// stylesheet. The embed list now names each asset explicitly, and this test is what
// keeps a future wildcard from quietly
// putting it back — a 404 here is the whole point.
func TestUnusableVendorStylesheetIsNotEmbedded(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()

	for _, gone := range []string{"/css/tailwind.min.css", "/js/tailwind.js"} {
		req := httptest.NewRequest(http.MethodGet, gone, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d (%d bytes), want 404 — an unpurged Tailwind build is back in the binary",
				gone, w.Code, w.Body.Len())
		}
	}

	// The assets that are supposed to be there, with the validator and the
	// compression that make a reload cheap. These are the real vendored files, so
	// the byte counts here are the ones the operator's browser actually downloads.
	for _, asset := range []string{
		"/index.html", "/css/style.css", "/css/tailwind.purged.css", "/js/app.js",
		"/js/feather.min.js", "/js/chart.umd.min.js",
	} {
		req := httptest.NewRequest(http.MethodGet, asset, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("GET %s → %d, want 200", asset, w.Code)
			continue
		}
		if w.Header().Get("ETag") == "" {
			t.Errorf("GET %s carried no ETag", asset)
		}
		if got := w.Header().Get("Content-Encoding"); got != "gzip" {
			t.Errorf("GET %s → Content-Encoding %q, want gzip", asset, got)
		}
	}
}
