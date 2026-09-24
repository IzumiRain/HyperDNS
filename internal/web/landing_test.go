package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Phase 2/3 (v2.1): the bare root is a Matrix landing page and nothing else. It
// must carry the landing markers and must not carry anything that names the
// sign-in form, the panel, or the API — the whole point is that "/" stops
// advertising them.
func TestRootServesMatrixLandingPage(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.BuildHandler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("GET / Content-Type = %q, want text/html; charset=utf-8", got)
	}
	body := w.Body.String()

	for _, marker := range []string{
		`<title>HyperDNS</title>`,
		`data-landing="matrix"`,
		`<canvas id="matrix"`,
		`<h1>HyperDNS</h1>`,
		`prefers-reduced-motion`,
		`<noscript>`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("GET / body misses landing marker %q", marker)
		}
	}

	// No credential-adjacent word, no panel/API/bundle reference, no SPA hook.
	// Checked case-insensitively so a comment or an attribute cannot smuggle
	// one past a literal match.
	lowered := strings.ToLower(body)
	for _, forbidden := range []string{
		"login", "dashboard", "admin", "/api/", "app.js",
		"tab-dashboard", "data-tab", "password", "token",
	} {
		if strings.Contains(lowered, forbidden) {
			t.Errorf("GET / body contains %q — the root must not name it", forbidden)
		}
	}

	// The shared security headers still wrap the root: it is served through
	// the same middleware as everything else.
	if got := w.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src") {
		t.Errorf("GET / CSP = %q, want the shared policy", got)
	}
	if got := w.Header().Get("X-Robots-Tag"); got != "noindex, nofollow" {
		t.Errorf("GET / X-Robots-Tag = %q, want noindex, nofollow", got)
	}
}

// The root refuses everything but GET/HEAD with an explicit Allow, in the
// same shape as the SPA and asset handlers.
func TestRootLandingMethodGuard(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.BuildHandler()

	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
	} {
		req := httptest.NewRequest(method, "/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s / = %d, want 405", method, w.Code)
		}
		if got := w.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s / Allow = %q, want \"GET, HEAD\"", method, got)
		}
	}

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("HEAD / = %d, want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD / body = %d bytes, want empty", w.Body.Len())
	}
}

// Unknown public paths must not fall through to the admin SPA: the old root
// routes (/login, /home, /js/app.js, ...) now answer the same plain not-found a
// random path gets. No redirect — a redirect would publish the hidden namespace
// to whoever asked.
func TestUnknownPublicPathsDoNotFallThroughToSPA(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.BuildHandler()

	for _, path := range []string{
		"/ghost", "/login", "/admin", "/panel-secret", "/index",
		// The pre-v2.1 root routes, retired with the move.
		"/home", "/dashboard", "/panel", "/clients", "/settings",
		"/js/app.js", "/css/style.css", "/api/stats", "/api/auth/login",
		"/api/v1/status", "/events/stream", "/dns-query",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, w.Code)
		}
		lowered := strings.ToLower(w.Body.String())
		for _, forbidden := range []string{"login", "dashboard", "tab-dashboard"} {
			if strings.Contains(lowered, forbidden) {
				t.Errorf("GET %s 404 body contains %q — a miss must not serve the panel", path, forbidden)
			}
		}
	}
}

// Phase 3: the dashboard is reachable only below the generated admin path.
// The SPA mount, the APIs, and the assets must all work under it.
func TestAdminNamespaceServesDashboardUnderGeneratedPath(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.BuildHandler()
	ap := ws.AdminPath()
	if !IsValidAdminPath(ap) {
		t.Fatalf("AdminPath() = %q, not a valid 16-hex path", ap)
	}

	// /<p> redirects to /<p>/dash/ for an operator who typed the bare path.
	req := httptest.NewRequest(http.MethodGet, "/"+ap, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("GET /%s = %d, want 302", ap, w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/"+ap+"/dash/" {
		t.Errorf("GET /%s Location = %q, want /%s/dash/", ap, loc, ap)
	}

	// The dashboard document, every clean route under the mount, and the assets.
	docCookie := &http.Cookie{Name: documentSessionCookie, Value: ws.sessions.Create()}
	for _, path := range []string{
		"/" + ap + "/dash/",
		"/" + ap + "/dash/home",
		"/" + ap + "/dash/clients",
		"/" + ap + "/dash/settings",
		"/" + ap + "/js/app.js",
		"/" + ap + "/css/style.css",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(docCookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, w.Code)
			continue
		}
		if strings.HasSuffix(path, "/dash/") || strings.HasSuffix(path, "home") ||
			strings.HasSuffix(path, "clients") || strings.HasSuffix(path, "settings") {
			if !strings.Contains(w.Body.String(), `id="tab-dashboard"`) {
				t.Errorf("GET %s returned 200 but not the dashboard document", path)
			}
		}
	}

	// The login API answers under the admin namespace and nowhere else.
	req = httptest.NewRequest(http.MethodPost, "/"+ap+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5555"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("POST /%s/api/auth/login = %d, want 200 — body %s", ap, w.Code, w.Body.String())
	}

	// The versioned external API is mounted below the prefix as well. The
	// keyless routes are bind-gated, so the probe comes from loopback (the
	// test harness's APIBind is the localhost default).
	req = httptest.NewRequest(http.MethodGet, "/"+ap+"/api/v1/version", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /%s/api/v1/version = %d, want 200", ap, w.Code)
	}
}

// A wrong admin prefix must be indistinguishable from a random path: same
// status, same body, same headers. Anything that differs is an oracle for
// guessing the namespace.
func TestWrongAdminPrefixIsIndistinguishableFromNotFound(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.BuildHandler()

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	miss := get("/totally-random-path")
	for _, probe := range []string{
		"/ffffffffffffffff", "/aaaaaaaaaaaaaaaa", "/1234567890abcdef",
		"/" + ws.AdminPath() + "0",
		"/ffffffffffffffff/dash/", "/ffffffffffffffff/api/stats",
	} {
		w := get(probe)
		if w.Code != miss.Code {
			t.Errorf("GET %s = %d, want the plain miss status %d", probe, w.Code, miss.Code)
		}
		if w.Body.String() != miss.Body.String() {
			t.Errorf("GET %s body %q differs from the plain miss body %q — a wrong prefix must not be distinguishable", probe, w.Body.String(), miss.Body.String())
		}
	}
}

// Path traversal under the admin prefix must not escape the namespace: the
// outer router cleans the path before matching, so a dot segment cannot smuggle
// a request past the prefix check.
func TestAdminPrefixTraversalCannotEscape(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.BuildHandler()
	ap := ws.AdminPath()

	for _, raw := range []string{
		"/" + ap + "/../api/stats",
		"/" + ap + "/dash/../api/stats",
		"/" + ap + "%2f..%2fapi/stats",
	} {
		req := httptest.NewRequest(http.MethodGet, raw, nil)
		req.URL = &url.URL{Path: raw} // keep the raw form; httptest would escape it
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		// The traversal either 404s or is cleaned back into the namespace and
		// then hits requireAuth — it must never return the protected payload.
		if w.Code == http.StatusOK {
			t.Errorf("GET %q = 200 with body %.80q — traversal escaped the admin namespace", raw, w.Body.String())
		}
	}
}
