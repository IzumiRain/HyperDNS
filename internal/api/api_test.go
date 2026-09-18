package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
	"hyperdns/internal/version"
)

func setupTestAPI(t *testing.T) (*API, *database.DB, *database.ServerSettings, func()) {
	// Per-test directory rather than fixed names in the package directory. Every test
	// in this package calls this helper, so shared filenames meant each run reused one
	// database file: a test that crashed before its cleanup left test_api.db next to the
	// source, and the next run opened that leftover instead of a fresh database. It is
	// also what a future t.Parallel() would deadlock on, since bbolt takes an exclusive
	// flock on the file. t.TempDir() removes the directory after the test's own cleanups
	// have run, so the handles below are closed first — which is what Windows requires.
	dir := t.TempDir()
	tmpDB := filepath.Join(dir, "api.db")
	tmpKey := filepath.Join(dir, "api.key")

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
		// The REST API authenticates with APIKey only; this field is here to make
		// the record realistic, never to be verified against.
		AdminPassword: "unused-by-the-rest-api",
		APIKey:        "hdns_live_testkey123",
		APIBind:       "127.0.0.1",
	}
	tlsSettings := &database.TLSSettings{}

	apiInst := NewAPI(db, clients, stats, c, m, u, settings, tlsSettings, nil)

	cleanup := func() {
		// Both of these run a ticker goroutine that outlives the test unless it is
		// stopped, and this helper is called once per test in the package. The files
		// themselves are t.TempDir()'s to remove.
		stats.Close()
		c.Close()
		_ = db.Close()
	}

	return apiInst, db, settings, cleanup
}

func TestAPI_AuthWithAPIKey(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	// 1. Unauthenticated Request -> 401 Unauthorized
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w.Code)
	}

	// 2. Authenticated Request with X-API-Key -> 200 OK
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	reqAuth.Header.Set("X-API-Key", "hdns_live_testkey123")
	reqAuth.RemoteAddr = "127.0.0.1:12345"
	wAuth := httptest.NewRecorder()
	mux.ServeHTTP(wAuth, reqAuth)

	if wAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK with valid API key, got %d", wAuth.Code)
	}
}

func TestAPI_Version(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	// The keyless routes are bind-gated like the rest of the surface: a
	// non-loopback caller on a localhost-bound API gets the same 403, and a
	// loopback caller (or a Public API install) gets the metadata.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("version from a non-loopback peer on a localhost bind = %d, want 403", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	req.RemoteAddr = "127.0.0.1:4444"
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var info version.Info
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatalf("failed to decode version info: %v", err)
	}
	// version.json is the single source of truth (2.2.0 as of this release);
	// the check is that the endpoint reports IT, not a stale literal, so read
	// the expected value from the same embedded source.
	if info.Version != version.Get().Version {
		t.Errorf("expected version %s (version.json), got %s", version.Get().Version, info.Version)
	}
}

func TestAPI_ClientsCRUD(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	// 1. Create Client with Advanced Settings
	body, _ := json.Marshal(map[string]any{
		"name":             "Alex VIP Pro",
		"days":             45,
		"ip":               "198.51.100.77",
		"traffic_limit_gb": 100.5,
		"custom_policies":  []string{"enable_riot", "enable_discord"},
		"note":             "VIP Annual Pass",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "hdns_live_testkey123")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	var created database.Client
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.Name != "Alex VIP Pro" {
		t.Errorf("expected name Alex VIP Pro, got %s", created.Name)
	}
	if created.TrafficLimitGB != 100.5 {
		t.Errorf("expected traffic limit 100.5, got %f", created.TrafficLimitGB)
	}
	if len(created.CustomPolicies) != 2 {
		t.Errorf("expected 2 custom policies, got %d", len(created.CustomPolicies))
	}

	// 2. Update Client Details via PUT
	newName := "Alex VIP Master"
	newLimit := 200.0
	newPolicies := []string{"enable_riot", "enable_discord", "enable_steam"}
	putBody, _ := json.Marshal(map[string]any{
		"name":             newName,
		"traffic_limit_gb": newLimit,
		"custom_policies":  newPolicies,
		"note":             "Upgraded to 200GB plan",
	})
	reqPut := httptest.NewRequest(http.MethodPut, "/api/v1/clients/"+created.ID, bytes.NewReader(putBody))
	reqPut.Header.Set("X-API-Key", "hdns_live_testkey123")
	reqPut.RemoteAddr = "127.0.0.1:12345"
	wPut := httptest.NewRecorder()
	mux.ServeHTTP(wPut, reqPut)

	if wPut.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on PUT, got %d: %s", wPut.Code, wPut.Body.String())
	}

	var updated database.Client
	_ = json.Unmarshal(wPut.Body.Bytes(), &updated)
	if updated.Name != "Alex VIP Master" || updated.TrafficLimitGB != 200.0 || len(updated.CustomPolicies) != 3 {
		t.Errorf("update mismatch: %+v", updated)
	}

	// 3. Test Reset Traffic via POST
	reqReset := httptest.NewRequest(http.MethodPost, "/api/v1/clients/"+created.ID+"/reset-traffic", nil)
	reqReset.Header.Set("X-API-Key", "hdns_live_testkey123")
	reqReset.RemoteAddr = "127.0.0.1:12345"
	wReset := httptest.NewRecorder()
	mux.ServeHTTP(wReset, reqReset)

	if wReset.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on reset-traffic, got %d: %s", wReset.Code, wReset.Body.String())
	}

	// 4. Test Regenerate UUID via POST
	reqUUID := httptest.NewRequest(http.MethodPost, "/api/v1/clients/"+created.ID+"/regenerate-uuid", nil)
	reqUUID.Header.Set("X-API-Key", "hdns_live_testkey123")
	reqUUID.RemoteAddr = "127.0.0.1:12345"
	wUUID := httptest.NewRecorder()
	mux.ServeHTTP(wUUID, reqUUID)

	if wUUID.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on regenerate-uuid, got %d: %s", wUUID.Code, wUUID.Body.String())
	}

	// 5. Delete Client via DELETE
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/clients/"+created.ID, nil)
	reqDel.Header.Set("X-API-Key", "hdns_live_testkey123")
	reqDel.RemoteAddr = "127.0.0.1:12345"
	wDel := httptest.NewRecorder()
	mux.ServeHTTP(wDel, reqDel)

	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on delete, got %d: %s", wDel.Code, wDel.Body.String())
	}
}

// The dashboard's policy picker is filled from this response, so `catalog` is part of
// the contract now rather than an extra field. Without it the picker is empty on a
// healthy install and the operator reads "No matching policies found".
func TestAPI_PoliciesServesTheCatalogueNotJustTheOverrides(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	req.Header.Set("X-API-Key", "hdns_live_testkey123")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		Policies []database.Policy            `json:"policies"`
		Catalog  []matcher.PolicyCatalogEntry `json:"catalog"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode the policies response: %v", err)
	}

	// A fresh install has no overrides at all, and that is the whole reason the
	// catalogue had to exist: this array being empty is correct, and the picker that
	// used to be fed from it had nothing to show.
	if len(body.Policies) != 0 {
		t.Errorf("a fresh install already reports %d policy overrides", len(body.Policies))
	}
	if len(body.Catalog) == 0 {
		t.Fatal("catalog is empty, so the dashboard picker would be too")
	}
	if len(body.Catalog) != len(matcher.PresetRuleKeys) {
		t.Errorf("catalog carries %d presets, the matcher knows %d",
			len(body.Catalog), len(matcher.PresetRuleKeys))
	}

	// Every row has to carry a label the panel can print and a key the resolver will
	// accept. A row with one and not the other is a policy an operator can attach and
	// the matcher then silently ignores.
	blocking := 0
	for _, e := range body.Catalog {
		want, known := matcher.PresetRuleKeys[e.Key]
		if !known {
			t.Errorf("catalog offers %q, which the matcher does not implement", e.Key)
			continue
		}
		if e.Label != want {
			t.Errorf("catalog labels %q as %q, the matcher calls it %q", e.Key, e.Label, want)
		}
		if e.Blocking {
			blocking++
		}
	}

	// The flag has to survive the encoding, not just exist in Go: it is the only thing
	// separating "add another game" from "take these domains away" in the picker.
	if blocking == 0 {
		t.Error("no catalog entry is marked blocking, so sinkholing categories look like games")
	}
}

// Every list field has to encode as [] and never as null.
//
// This is asserted on the raw bytes on purpose. The test above decodes into
// []database.Policy, and json.Unmarshal turns null into a nil slice whose len() is 0 —
// so it passed happily while the route was answering {"policies":null} on every fresh
// install. What that costs is on the consumer's side: data.policies.forEach in the
// dashboard and a plain for-loop in a Python integration both raise on null, and they
// raise on the one input that is not an error condition, an installation with no
// overrides yet.
//
// The create response is checked in the same test because it is built rather than read
// back: unpackClient normalises allowed_ips and custom_policies on the way out of the
// database, so GET was already correct while POST answered null for the same field.
func TestListFieldsEncodeAsArraysNotNull(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	call := func(method, path string, payload []byte) map[string]json.RawMessage {
		t.Helper()
		var rdr *bytes.Reader
		if payload != nil {
			rdr = bytes.NewReader(payload)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("X-API-Key", "hdns_live_testkey123")
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			t.Fatalf("%s %s: expected 200/201, got %d: %s", method, path, w.Code, w.Body.String())
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
			t.Fatalf("%s %s: response is not a JSON object: %v", method, path, err)
		}
		return fields
	}

	// A raw field is an array when it starts with '['. Comparing against the literal
	// "null" would miss a field the encoder dropped entirely, which is the same problem
	// for a caller that indexes it.
	wantArray := func(where, field string, fields map[string]json.RawMessage) {
		t.Helper()
		raw, ok := fields[field]
		if !ok {
			t.Errorf("%s: %s is missing from the response", where, field)
			return
		}
		if len(raw) == 0 || raw[0] != '[' {
			t.Errorf("%s: %s encoded as %s, want a JSON array", where, field, string(raw))
		}
	}

	// Nothing has been created yet, so these are the empty-list cases — the ones that
	// used to come back as null.
	fresh := call(http.MethodGet, "/api/v1/policies", nil)
	wantArray("GET /api/v1/policies", "policies", fresh)
	wantArray("GET /api/v1/policies", "catalog", fresh)

	freshClients := call(http.MethodGet, "/api/v1/clients", nil)
	wantArray("GET /api/v1/clients", "clients", freshClients)

	// No "ip" and no "custom_policies" in the request: both fields are then whatever the
	// service left them as, which is what this asserts.
	body, _ := json.Marshal(map[string]any{"name": "shape-probe", "days": 30})
	created := call(http.MethodPost, "/api/v1/clients", body)
	wantArray("POST /api/v1/clients", "allowed_ips", created)
	wantArray("POST /api/v1/clients", "custom_policies", created)

	// And the same record read back has to agree with the response that created it.
	var id struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created["id"], &id.ID); err != nil {
		t.Fatalf("the create response carries no usable id: %v", err)
	}
	readBack := call(http.MethodGet, "/api/v1/clients/"+id.ID, nil)
	wantArray("GET /api/v1/clients/{id}", "allowed_ips", readBack)
	wantArray("GET /api/v1/clients/{id}", "custom_policies", readBack)

	populated := call(http.MethodGet, "/api/v1/clients", nil)
	wantArray("GET /api/v1/clients (populated)", "clients", populated)
}
