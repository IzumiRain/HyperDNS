package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdns/internal/database"
)

// Mantis PoC set for the v2.1.0 Hotfix 5 attack surface.
//
// This file is the red-team half of the subscriber-listener work: the listener
// is a NEW public port, bound on 0.0.0.0 on a real install, and every route it
// answers is reachable by anyone who can reach the box. Each test below asserts
// that a specific abuse is refused; they are written to FAIL if the guard is
// removed, which is what makes them regression tests as well as PoCs.
//
// Run in the isolated container:
//   bash build/race-in-docker.sh ./internal/web/ -run TestPoC

const pocNotFoundBody = "404 page not found\n"

func pocProbe(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// PoC-01: the public subscriber port must not become a second door into the
// admin namespace. A panel that hid its routes behind a 16-hex path would be
// pointless if the portal port answered them.
func TestPoC01SubscriberPortDoesNotExposeTheAdminNamespace(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.subscriberSurface()

	admin := ws.AdminPath()
	// Every shape an operator's browser or a scanner would try. The suffix
	// variants matter: /<admin>/dash/ is stripped by the panel router, so a
	// listener that reused that router would answer them.
	paths := []string{
		"/" + admin,
		"/" + admin + "/",
		"/" + admin + "/dash",
		"/" + admin + "/dash/",
		"/" + admin + "/dash/home",
		"/" + admin + "/dash/clients",
		"/" + admin + "/login",
		"/" + admin + "/api/config",
		"/" + admin + "/api/clients",
		"/" + admin + "/api/settings",
		"/" + admin + "/events/stream",
		"/dash/",
		"/dash/home",
		"/api/v1/status",
		"/dns-query",
		"/js/app.js",
		"/css/style.css",
		"//" + admin + "/dash/",
		"/." + admin + "/dash/",
		"/sub/../" + admin + "/dash/",
		"/SUB/../" + admin + "/dash/",
	}
	for _, p := range paths {
		rec := pocProbe(t, h, http.MethodGet, p)
		if rec.Body.String() != pocNotFoundBody {
			t.Errorf("PoC-01 CONFIRMED: %s on the public subscriber port answered %d "+
				"with %d bytes — the admin namespace is reachable without the panel path",
				p, rec.Code, rec.Body.Len())
		}
	}
}

// PoC-02: the same port must not leak the panel's unauthenticated endpoints.
// /api/auth/login is the one that matters most — it is reachable without a
// session by design on the panel, and the subscriber port must not become an
// unauthenticated password oracle.
func TestPoC02SubscriberPortDoesNotServeAuthEndpoints(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.subscriberSurface()

	for _, p := range []string{
		"/api/auth/login", "/api/auth/me", "/api/auth/2fa/status",
		"/api/auth/unlock", "/api/stats", "/api/stream/queries",
	} {
		rec := pocProbe(t, h, http.MethodPost, p)
		if rec.Body.String() != pocNotFoundBody {
			t.Errorf("PoC-02 CONFIRMED: POST %s answered %d on the public subscriber "+
				"port — an unauthenticated auth surface is exposed there", p, rec.Code)
		}
	}
}

// PoC-03: the registration endpoint must not become a token oracle. A wrong
// token and a wrong secret have to be the same answer, or the endpoint can be
// walked to enumerate live subscriptions.
func TestPoC03RegistrationIsNotATokenOracle(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	client, err := ws.clients.CreateClient("Oracle Target", 30, "")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	post := func(token, secret string) *httptest.ResponseRecorder {
		body := strings.NewReader(`{"secret":"` + secret + `","ip":"203.0.113.99"}`)
		req := httptest.NewRequest(http.MethodPost, "/ip/"+token, body)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		ws.buildAdminHandler().ServeHTTP(rec, req)
		return rec
	}

	realTokenWrongSecret := post(client.Token, "not-the-secret")
	fakeTokenWrongSecret := post("0000000000000000000000000000000000000000000000000000000000000000", "not-the-secret")

	if realTokenWrongSecret.Code != fakeTokenWrongSecret.Code {
		t.Errorf("PoC-03 CONFIRMED: a live token with a wrong secret answers %d while an "+
			"unknown token answers %d — the difference enumerates subscriptions",
			realTokenWrongSecret.Code, fakeTokenWrongSecret.Code)
	}
	if realTokenWrongSecret.Body.String() != fakeTokenWrongSecret.Body.String() {
		t.Errorf("PoC-03 CONFIRMED: the bodies differ between a live and an unknown token:\n"+
			"  live:  %s\n  fake:  %s", realTokenWrongSecret.Body.String(), fakeTokenWrongSecret.Body.String())
	}
}

// PoC-04: the reason codes added in this hotfix must not carry more than the
// guard they replace. `conflict` is the one to watch — it says an address is
// taken, and an attacker must not be able to use it to check whether a
// specific IP is registered to someone else without already holding a secret.
func TestPoC04ReasonCodesRequireASecretFirst(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	victim, err := ws.clients.CreateClient("Victim", 30, "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	_ = victim

	attacker, err := ws.clients.CreateClient("Attacker", 30, "")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	// A probe at the victim's address with a WRONG secret. The answer must be
	// the same "secret" refusal a free address gets — never "conflict". The
	// conflict is only meaningful to a caller who has already proved the secret.
	post := func(secret, ip string) *httptest.ResponseRecorder {
		body := strings.NewReader(`{"secret":"` + secret + `","ip":"` + ip + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/ip/"+attacker.Token, body)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		ws.buildAdminHandler().ServeHTTP(rec, req)
		return rec
	}

	taken := post("wrong-secret", "203.0.113.10")
	free := post("wrong-secret", "203.0.113.11")
	if taken.Code != free.Code || taken.Body.String() != free.Body.String() {
		t.Errorf("PoC-04 CONFIRMED: a wrong-secret probe distinguishes an address that is "+
			"taken from one that is free:\n  taken: %d %s\n  free:  %d %s",
			taken.Code, taken.Body.String(), free.Code, free.Body.String())
	}

	// With the right secret the conflict IS reported — that is the feature, and
	// the subscriber is the only one who can reach it.
	legit := post(attacker.RegisterSecret, "203.0.113.10")
	if legit.Code != http.StatusConflict {
		t.Errorf("with the correct secret a taken address should answer 409, got %d: %s",
			legit.Code, legit.Body.String())
	}
}

// PoC-05: the portal title is operator-controlled text that reaches a page with
// html/template, which escapes it. This asserts the escaping still holds — the
// field was newly wired into the h1 by this hotfix, and it must not be rendered
// as markup.
func TestPoC05PortalTitleIsEscapedNotExecuted(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	client, err := ws.clients.CreateClient("Escape Probe", 30, "")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	ws.SetSubscriptionSettings(&database.SubscriptionSettings{})
	if err := ws.subSettings.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", UsePanelCertificate: true,
		Title: `<img src=x onerror=alert(1)>"'>`,
	}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0")
	rec := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "<img src=x onerror") {
		t.Error("PoC-05 CONFIRMED: the operator's Portal title is rendered as live markup " +
			"on the subscriber page")
	}
	if !strings.Contains(body, "&lt;img") {
		t.Error("the escaped form of the title is absent — the title may not be rendered at all")
	}
}
