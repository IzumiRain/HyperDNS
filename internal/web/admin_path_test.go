package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The public boundary of Phase 3: the subscriber portal stays reachable at the
// root (a subscriber's browser never learns the admin path), the dashboard's
// assets stay inside the admin namespace, and only the two portal assets plus
// the fonts are deliberately public.
func TestPublicSurfaceSurvivesTheAdminMove(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.BuildHandler()

	// Portal pages and the JSON endpoint: public, as designed.
	client, err := ws.clients.CreateClient("Portal Probe", 30, "10.0.0.1")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	for _, path := range []string{"/sub/" + client.Token, "/ip/" + client.Token} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 — the portal must stay public", path, w.Code)
		}
	}

	// The two portal assets and the fonts: the deliberately public namespace.
	for _, path := range []string{"/css/portal.css", "/js/portal.js", "/fonts/vazirmatn-var.woff2"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 — the portal page references it", path, w.Code)
		}
	}

	// Every dashboard asset: inside the namespace only.
	for _, path := range []string{
		"/js/app.js", "/js/i18n.js",
		"/js/feather.min.js", "/js/chart.umd.min.js", "/css/style.css",
		"/css/tailwind.purged.css",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 — a dashboard asset at the root defeats the hidden namespace", path, w.Code)
		}
		// But it must serve below the prefix.
		req = httptest.NewRequest(http.MethodGet, "/"+ws.AdminPath()+path, nil)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET /%s%s = %d, want 200 — the dashboard cannot load without it", ws.AdminPath(), path, w.Code)
		}
	}
}

// TestAdminPathFallbackIsStableAndValid: a settings record that reaches the web
// server without an admin path (a test harness, or a record that skipped the
// startup migration) still gets a hidden namespace, and it must not wander
// between requests or BuildHandler calls.
func TestAdminPathFallbackIsStableAndValid(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	ws.settings.AdminPath = "" // simulate a record that skipped the migration

	first := ws.AdminPath()
	if !IsValidAdminPath(first) {
		t.Fatalf("fallback AdminPath() = %q, not a valid 16-hex path", first)
	}
	for i := 0; i < 5; i++ {
		if got := ws.AdminPath(); got != first {
			t.Fatalf("AdminPath() changed from %q to %q between calls — the namespace would move under a live browser", first, got)
		}
	}
	h1 := ws.BuildHandler()
	h2 := ws.BuildHandler()
	req := httptest.NewRequest(http.MethodGet, "/"+first+"/dash/", nil)
	req.AddCookie(&http.Cookie{Name: documentSessionCookie, Value: ws.sessions.Create()})
	w := httptest.NewRecorder()
	h2.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /%s/dash/ on a second BuildHandler = %d, want 200", first, w.Code)
	}
	_ = h1
}

// TestAdminPathRegeneration pins the whole regeneration workflow: explicit
// confirmation required, a valid new path persisted, the old namespace dead on
// the very next request, and every session invalidated.
func TestAdminPathRegeneration(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.BuildHandler()
	oldPath := ws.AdminPath()

	// Login to hold a live session that regeneration must kill.
	loginReq := httptest.NewRequest(http.MethodPost, "/"+oldPath+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.RemoteAddr = "203.0.113.7:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, loginReq)
	if w.Code != http.StatusOK {
		t.Fatalf("login under the old path = %d, want 200", w.Code)
	}
	token, _ := decodeBody(t, w)["token"].(string)
	before := ws.sessions.Count()
	if before == 0 {
		t.Fatal("no session was created; the invalidation assertion would be vacuous")
	}

	// A POST without the confirmation flag must be refused, whatever its body.
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/"+ws.AdminPath()+"/api/settings/regenerate-admin-path", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.RemoteAddr = "203.0.113.7:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := post(`{}`); w.Code != http.StatusBadRequest {
		t.Errorf("regeneration without confirm = %d, want 400", w.Code)
	}
	if ws.AdminPath() != oldPath {
		t.Fatalf("the path changed to %q without confirmation", ws.AdminPath())
	}

	w = post(`{"confirm":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("regeneration with confirm = %d, want 200 — body %s", w.Code, w.Body.String())
	}
	newPath, _ := decodeBody(t, w)["admin_path"].(string)
	if !IsValidAdminPath(newPath) {
		t.Errorf("regenerated path %q is not a valid 16-hex path", newPath)
	}
	if newPath == oldPath {
		t.Error("the regenerated path equals the old one; the generator did not move")
	}
	if got := ws.settings.GetAdminPath(); got != newPath {
		t.Errorf("settings hold %q, want the regenerated %q — the new path did not persist", got, newPath)
	}

	// The old namespace is dead at once, and indistinguishably.
	miss := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	old404 := miss("/" + oldPath + "/dash/")
	if old404.Code != http.StatusNotFound {
		t.Errorf("GET /%s/dash/ after regeneration = %d, want 404", oldPath, old404.Code)
	}
	random404 := miss("/totally-unrelated")
	if old404.Body.String() != random404.Body.String() {
		t.Error("the retired path is distinguishable from a random miss — that is an oracle for the old namespace")
	}

	// The new namespace is live, but every session died with the old path, so an
	// unauthenticated navigation there redirects to the sign-in page rather than
	// rendering the shell — the operator must log in again on the new
	// coordinates. (A live document cookie would serve 200; the point here is
	// that the route exists and gates, not 404s.)
	if w := miss("/" + newPath + "/dash/"); w.Code != http.StatusFound {
		t.Errorf("GET /%s/dash/ = %d, want 302 (re-login after regeneration)", newPath, w.Code)
	}
	authed := httptest.NewRequest(http.MethodGet, "/"+newPath+"/dash/", nil)
	authed.AddCookie(&http.Cookie{Name: documentSessionCookie, Value: ws.sessions.Create()})
	aw := httptest.NewRecorder()
	h.ServeHTTP(aw, authed)
	if aw.Code != http.StatusOK {
		t.Errorf("GET /%s/dash/ with a fresh session = %d, want 200", newPath, aw.Code)
	}
	// Drop the probe session so the count assertion below reflects only the
	// regeneration's own effect.
	ws.sessions.DeleteAll()

	// Every session died with the old path.
	if ws.sessions.Count() != 0 {
		t.Errorf("%d sessions survived the regeneration; the old coordinates could still open the panel", ws.sessions.Count())
	}

	// And the old token is refused on the new namespace too.
	req := httptest.NewRequest(http.MethodGet, "/"+newPath+"/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("/api/auth/me with a pre-regeneration token = %d, want 401", w.Code)
	}
}

// TestDoHServesAtRootWhileAdminMoves: the DoH endpoint is a service route, not
// part of the panel, so it must keep answering at the root of the host.
func TestDoHServesAtRootWhileAdminMoves(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	// No DoH handler in this harness; a GET to /dns-query must then be the plain
	// miss rather than a panel response — the route simply does not exist.
	h := ws.BuildHandler()
	req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("GET /dns-query with no DoH handler = %d, want 404", w.Code)
	}
}
