package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
	webAssets "hyperdns/web"
)

// testAdminPassword is the credential the web tests log in with. It has to
// satisfy the real strength policy, because the handlers enforce it.
const testAdminPassword = "Zx7-quiet-lantern-web"

// testAdminHash stores the password the way a running daemon does — hashed. A
// test that seeded plaintext would still authenticate through the legacy path
// and so would never exercise what production actually does.
//
// The cost is a testing shim, not the production work factor: this package logs
// in hundreds of times, and under the race detector a full
// DefaultPBKDF2Iterations derivation per login is slow enough to age a TOTP
// code out of its ±1-step window between the moment the test derives it and the
// moment the handler spends it — which made the 2FA suite flap for a reason
// unrelated to what it checks. See crypto.HashPasswordWithCost. The stored form
// for testAdminPassword is derived once per binary and shared; any other
// plaintext is hashed on the spot, since it is presumably being varied on
// purpose.
const testAdminPBKDF2Iterations = 1000

var testAdminHashOnce = sync.OnceValues(func() (string, error) {
	return crypto.HashPasswordWithCost(testAdminPassword, testAdminPBKDF2Iterations)
})

func testAdminHash(t *testing.T, plaintext string) string {
	t.Helper()
	hash := func() (string, error) { return crypto.HashPasswordWithCost(plaintext, testAdminPBKDF2Iterations) }
	if plaintext == testAdminPassword {
		hash = testAdminHashOnce
	}
	h, err := hash()
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return h
}

func setupTestWebServer(t *testing.T) (*WebServer, *database.DB, func()) {
	// A directory per test, not a fixed filename: bbolt takes an exclusive lock on
	// the file, so a test that stands up a second server while the first is still
	// open would otherwise block until the open timeout.
	dir := t.TempDir()
	tmpDB := filepath.Join(dir, "test_web.db")
	tmpKey := filepath.Join(dir, "test_web.key")

	cipher, err := crypto.LoadOrGenerateMasterKey(tmpKey)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	db, err := database.Open(tmpDB, cipher)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	c := cache.NewCache(1000, 60, 3600)
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"1.1.1.1:53"}, 2*time.Second, true, "")

	clients := service.NewClientService(db, true)
	stats := service.NewStatsService(db, nil, nil)

	settings := &database.ServerSettings{
		PublicIP:      "127.0.0.1",
		BindHost:      "127.0.0.1",
		WebPort:       8080,
		AdminUsername: "admin",
		AdminPassword: testAdminHash(t, testAdminPassword),
		APIKey:        "hdns_live_testkey123",
		APIBind:       "127.0.0.1",
	}
	tlsSettings := &database.TLSSettings{}

	sessions := service.NewSessionManager(time.Hour)
	ws := NewWebServer(db, clients, stats, c, m, u, nil, settings, tlsSettings, nil, sessions, webAssets.StaticFS)

	cleanup := func() {
		// Everything with a background goroutine gets stopped, not just the session
		// manager. cache.NewCache and service.NewStatsService each start a ticker
		// loop that outlives the test unless it is closed, and this helper runs once
		// per test in a package with more than fifty of them: the abandoned telemetry
		// loops alone tick once a second each and take a stop-the-world memory
		// reading every fifth tick, which is what pushed this package past the
		// per-package timeout under -race.
		sessions.Close()
		stats.Close()
		c.Close()
		_ = db.Close()
		_ = os.Remove(tmpDB)
		_ = os.Remove(tmpKey)
	}

	return ws, db, cleanup
}

func TestWebServer_SPARoutingAndAssets(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	handler := ws.buildAdminHandler()

	// 1. Verify Clean SPA Paths
	routes := []string{"/home", "/clients", "/logs", "/rules", "/api", "/guide", "/settings", "/dashboard", "/panel"}
	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK for SPA route %s, got %d", route, w.Code)
		}
	}

	// 2. Verify Local Embedded Assets
	assets := []string{"/js/feather.min.js", "/js/chart.umd.min.js", "/js/app.js", "/css/style.css", "/css/tailwind.purged.css"}
	for _, asset := range assets {
		req := httptest.NewRequest(http.MethodGet, asset, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK for asset %s, got %d", asset, w.Code)
		}
		if w.Body.Len() == 0 {
			t.Errorf("expected non-empty content for asset %s", asset)
		}
	}
}

func TestWebServer_AutoRegisterIP(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	handler := ws.buildAdminHandler()

	client, err := ws.clients.CreateClient("Sorena Pro", 30, "10.0.0.1")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// The read-only portal page at /sub/ shows the subscriber their account and
	// the detected address, and by Phase B binds nothing.
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
	req.RemoteAddr = "198.51.100.42:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /sub/%s, got %d", client.Token, w.Code)
	}
	bodyStr := w.Body.String()
	if !strings.Contains(bodyStr, "Sorena Pro") {
		t.Errorf("expected response to contain client name 'Sorena Pro'")
	}
	if !strings.Contains(bodyStr, "198.51.100.42") {
		t.Errorf("expected response to contain detected IP '198.51.100.42'")
	}
	stored, _ := ws.clients.GetClient(client.ID)
	if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "10.0.0.1" {
		t.Errorf("a page visit moved the binding: %v", stored.AllowedIPs)
	}

	// The secret-gated registration API is the one write: with the secret and no
	// explicit IP, the caller's own address is bound.
	postBody := `{"secret":"` + client.RegisterSecret + `"}`
	req2 := httptest.NewRequest(http.MethodPost, "/ip/"+client.Token, strings.NewReader(postBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "198.51.100.42:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 OK for the registration POST, got %d — %s", w2.Code, w2.Body.String())
	}
	stored, _ = ws.clients.GetClient(client.ID)
	if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "198.51.100.42" {
		t.Errorf("allowed IPs are %v, want [198.51.100.42]", stored.AllowedIPs)
	}
	c, _ := ws.clients.IsIPAllowed("198.51.100.42")
	if c == nil || c.Name != "Sorena Pro" {
		t.Errorf("expected IP to be registered to Sorena Pro")
	}

	// The page still displays the server address inferred from the Host header.
	req3 := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
	req3.Host = "95.179.140.241:8080"
	req3.RemoteAddr = "198.51.100.43:12345"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if !strings.Contains(w3.Body.String(), "95.179.140.241") {
		t.Errorf("expected sub page to display server public IP '95.179.140.241' instead of 127.0.0.1")
	}
}
