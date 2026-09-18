package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Since v2.1 the SPA is served at /<admin-path>/dash/, but index.html was
// written when the panel lived at the host root: its stylesheet and script
// tags name /css/... and /js/... absolutely, and a browser landing on
// /<admin-path>/dash/ resolved them against the host root — where the
// dashboard's assets have not been mounted since v2.1. The operator's screen
// was an unstyled page whose every script 404'd, while curl to the asset
// paths below the prefix returned 200 — exactly what the field report showed.
//
// These tests pin the fix: the document the server actually emits carries its
// asset references below the live admin namespace, for both the plain and the
// gzip representation, and the emitted references are 200-fetchable below that
// same namespace through the real handler.

// TestSPADocumentRewritesAssetReferencesToTheAdminPrefix reads the embedded
// document through serveIndex and asserts every root-absolute asset reference
// in it was moved below the namespace.
func TestSPADocumentRewritesAssetReferencesToTheAdminPrefix(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	s := ws.staticHandler()
	w := httptest.NewRecorder()
	if !s.serveIndex(w, httptest.NewRequest(http.MethodGet, "/", nil), ws.AdminPath()) {
		t.Fatal("serveIndex reported no dashboard embedded")
	}
	doc := w.Body.String()

	// The root-absolute form must be gone from the served document entirely:
	// no attribute may name an asset at the host root any more.
	for _, p := range []string{`="/css/`, `="/js/`, `="/fonts/`, `="/swagger/`} {
		if strings.Contains(doc, p) {
			t.Errorf("served index.html still carries %q — a reference the browser resolves against the host root, where the dashboard is not mounted", p)
		}
	}

	// And the rewritten form must actually be there, for every tag the
	// document originally carried.
	prefix := "/" + ws.AdminPath()
	for _, want := range []string{
		prefix + `/css/tailwind.purged.css`,
		prefix + `/css/style.css`,
		prefix + `/js/feather.min.js`,
		prefix + `/js/chart.umd.min.js`,
		prefix + `/js/app.js`,
		prefix + `/js/i18n.js`,
		prefix + `/js/modules/twofa.js`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("served index.html is missing %q — the browser would request the asset at the host root and draw a 404", want)
		}
	}

	// Non-asset references must not have been rewritten. The dashboard's own
	// favicon is a data: URI and its language buttons are data attributes, not
	// hrefs — none of those shapes match the rewrite.
	if !strings.Contains(doc, `data-lang-btn="en"`) || !strings.Contains(doc, `data-lang-btn="fa"`) {
		t.Error("the language buttons were disturbed by the prefix rewrite")
	}
	if !strings.Contains(doc, `rel="icon" href="data:image/svg+xml`) {
		t.Error("the data: favicon was disturbed by the prefix rewrite")
	}

	// The docs anchor is rewritten too — it is the one absolute link that is
	// not an asset, and it must land in the same namespace.
	if strings.Contains(doc, `href="/api/v1/docs"`) {
		t.Error("the docs anchor was left at the host root")
	}
	if !strings.Contains(doc, `href="`+prefix+`/api/v1/docs"`) {
		t.Error("the docs anchor was not moved under the admin prefix")
	}
}

// TestSPADocumentWithoutPrefixIsUntouched pins the escape hatch: an empty
// admin path (a record that never migrated) serves the original document with
// root-absolute references, which is correct for a pre-v2.1 mount.
func TestSPADocumentWithoutPrefixIsUntouched(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	s := ws.staticHandler()
	w := httptest.NewRecorder()
	if !s.serveIndex(w, httptest.NewRequest(http.MethodGet, "/", nil), "") {
		t.Fatal("serveIndex reported no dashboard embedded")
	}
	doc := w.Body.String()

	if !strings.Contains(doc, `="/css/tailwind.purged.css"`) {
		t.Error("the unprefixed document lost its root-absolute stylesheet reference")
	}
}

// TestPrefixedDocumentHasItsOwnValidatorAndGzip: the rewritten document is a
// different representation of the same URL, so it needs its own validator, and
// the compressible rewrite must still compress — the browser sends
// Accept-Encoding on the document load exactly as on any asset.
func TestPrefixedDocumentHasItsOwnValidatorAndGzip(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	s := ws.staticHandler()
	plain := httptest.NewRecorder()
	s.serveIndex(plain, httptest.NewRequest(http.MethodGet, "/", nil), ws.AdminPath())

	plainETag := plain.Header().Get("ETag")
	if plainETag == "" {
		t.Fatal("the rewritten document carried no ETag")
	}

	// The original document's tag must not satisfy the rewritten body: a cache
	// that held the pre-rewrite bytes would keep serving asset URLs the server
	// no longer answers.
	s.prefixMu.Lock()
	originalETag := s.index.etag
	s.prefixMu.Unlock()
	if plainETag == originalETag {
		t.Fatal("the rewritten document reuses the original ETag — a cached pre-rewrite copy would keep its 404ing asset URLs")
	}

	gz := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	s.serveIndex(gz, req, ws.AdminPath())
	if got := gz.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("rewritten document → Content-Encoding %q, want gzip", got)
	}
	body := gunzip(t, gz.Body.Bytes())
	if !bytes.Contains(body, []byte(ws.AdminPath())) {
		t.Error("the gzip representation of the document lost the prefix rewrite")
	}

	// Its validator differs from the identity one and revalidates to 304.
	if gz.Header().Get("ETag") == plainETag {
		t.Error("the gzip representation of the rewritten document reuses the identity ETag")
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("If-None-Match", gz.Header().Get("ETag"))
	re := httptest.NewRecorder()
	s.serveIndex(re, req, ws.AdminPath())
	if re.Code != http.StatusNotModified {
		t.Errorf("revalidation of the rewritten gzip document → %d, want 304", re.Code)
	}
}

// TestRewrittenReferencesAreFetchableBelowThePrefix is the end-to-end half of
// the fix: every asset URL the served document names must actually answer 200
// when fetched from the same namespace the document was served from. This is
// the assertion the field failure would have caught — the document loads, the
// assets 404.
func TestRewrittenReferencesAreFetchableBelowThePrefix(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	// The harvest fetches every referenced URL, the keyless API routes among
	// them; make the harness's API public so the loop probes them the way an
	// external browser would (the bind gate itself is covered in the api
	// package's tests).
	ws.settings.APIBind = "0.0.0.0"
	h := ws.BuildHandler()

	// Serve the document the way the browser gets it.
	req := httptest.NewRequest(http.MethodGet, "/"+ws.AdminPath()+"/dash/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /%s/dash/ → %d, want 200", ws.AdminPath(), w.Code)
	}
	doc := w.Body.String()

	// Harvest every stylesheet and script URL it names and fetch each one.
	seen := 0
	for _, ref := range []string{`href="`, `src="`} {
		for _, rest := range strings.Split(doc, ref)[1:] {
			end := strings.Index(rest, `"`)
			if end < 0 {
				continue
			}
			url := rest[:end]
			if !strings.HasPrefix(url, "/"+ws.AdminPath()+"/") {
				continue
			}
			seen++
			areq := httptest.NewRequest(http.MethodGet, url, nil)
			aw := httptest.NewRecorder()
			h.ServeHTTP(aw, areq)
			if aw.Code != http.StatusOK {
				t.Errorf("the served document references %s, which answers %d — exactly the broken-panel failure this rewrite exists to prevent", url, aw.Code)
			}
		}
	}
	if seen < 7 {
		t.Fatalf("only %d asset references harvested from the served document — the harvest itself is broken", seen)
	}
}

// TestRegeneratedPathRewritesTheDocumentAgain: regenerating the admin path
// must move the served document's references with it, not keep serving the old
// namespace's URLs.
func TestRegeneratedPathRewritesTheDocumentAgain(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	s := ws.staticHandler()
	first := ws.AdminPath()

	w := httptest.NewRecorder()
	s.serveIndex(w, httptest.NewRequest(http.MethodGet, "/", nil), first)
	if !strings.Contains(w.Body.String(), "/"+first+"/js/app.js") {
		t.Fatalf("first document did not carry the %q prefix", first)
	}

	second := GenerateAdminPath()
	for second == first {
		second = GenerateAdminPath()
	}
	w = httptest.NewRecorder()
	s.serveIndex(w, httptest.NewRequest(http.MethodGet, "/", nil), second)
	if !strings.Contains(w.Body.String(), "/"+second+"/js/app.js") {
		t.Errorf("after regeneration the document still serves the old %q prefix", first)
	}
	if strings.Contains(w.Body.String(), "/"+first+"/js/app.js") {
		t.Error("the regenerated document leaked the retired namespace's asset URLs")
	}
}
