package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hyperdns/internal/config"
	"hyperdns/internal/dns"
	"hyperdns/internal/rules"
	"hyperdns/internal/sniproxy"
	webAssets "hyperdns/web"
)

func setupTestWebServer() (*WebServer, *config.Config) {
	cfg := config.DefaultConfig()
	cfg.Server.APIKey = "hdns_live_testkey1234567890"
	cfg.Server.PublicIP = "1.2.3.4"

	cache := dns.NewCache(100, 60, 3600)
	matcher := rules.NewMatcher(cfg)
	upstreams := dns.NewUpstreamPool([]string{"1.1.1.1:53"}, 1*time.Second, true, "")
	dnsHandler := dns.NewHandler(cfg, cache, matcher, upstreams)
	sniServer := sniproxy.NewServer(cfg)
	statsCollector := NewStatsCollector(dnsHandler, cache, sniServer)

	ws := NewWebServer(
		cfg,
		"config.test.json",
		matcher,
		cache,
		upstreams,
		dnsHandler,
		statsCollector,
		webAssets.StaticFS,
	)

	return ws, cfg
}

func TestAPIv1_AuthWithAPIKey(t *testing.T) {
	ws, _ := setupTestWebServer()
	handler := ws.BuildHandler()

	// 1. Unauthorized Request (no API key)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized without API key, got %d", w.Code)
	}

	// 2. Authorized Request with X-API-Key header
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req2.Header.Set("X-API-Key", "hdns_live_testkey1234567890")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 OK with X-API-Key, got %d", w2.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil || !resp.Success {
		t.Fatalf("expected valid JSON success response: %v", err)
	}
}

func TestAPIv1_ClientsCRUD(t *testing.T) {
	ws, _ := setupTestWebServer()
	handler := ws.BuildHandler()

	// 1. Create client via API POST
	createBody := map[string]interface{}{
		"name":         "API Tester",
		"expires_days": 30,
		"initial_ip":   "192.168.1.100",
	}
	bodyBytes, _ := json.Marshal(createBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", "hdns_live_testkey1234567890")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	var createResp struct {
		Success bool `json:"success"`
		Data    struct {
			Client config.Client `json:"client"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&createResp)
	clientID := createResp.Data.Client.ID
	if clientID == "" {
		t.Fatalf("expected created client ID, got empty")
	}

	// 2. Lookup client
	reqLookup := httptest.NewRequest(http.MethodGet, "/api/v1/clients/lookup?ip=192.168.1.100", nil)
	reqLookup.Header.Set("X-API-Key", "hdns_live_testkey1234567890")
	wLookup := httptest.NewRecorder()
	handler.ServeHTTP(wLookup, reqLookup)

	if wLookup.Code != http.StatusOK {
		t.Errorf("expected 200 OK looking up client by IP, got %d", wLookup.Code)
	}

	// 3. Update registered IP (Strict 1-IP limit)
	ipBody := map[string]string{"ip": "192.168.1.200"}
	ipBytes, _ := json.Marshal(ipBody)
	reqIP := httptest.NewRequest(http.MethodPost, "/api/v1/clients/"+clientID+"/ip", bytes.NewReader(ipBytes))
	reqIP.Header.Set("X-API-Key", "hdns_live_testkey1234567890")
	wIP := httptest.NewRecorder()
	handler.ServeHTTP(wIP, reqIP)

	if wIP.Code != http.StatusOK {
		t.Errorf("expected 200 OK updating client IP, got %d", wIP.Code)
	}

	// 4. Delete client
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/clients/"+clientID, nil)
	reqDel.Header.Set("X-API-Key", "hdns_live_testkey1234567890")
	wDel := httptest.NewRecorder()
	handler.ServeHTTP(wDel, reqDel)

	if wDel.Code != http.StatusOK {
		t.Errorf("expected 200 OK deleting client, got %d", wDel.Code)
	}
}

func TestAPIv1_DocsAccessible(t *testing.T) {
	ws, _ := setupTestWebServer()
	handler := ws.BuildHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/docs", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/v1/docs, got %d", w.Code)
	}
}
