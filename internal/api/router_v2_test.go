package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The v2 contract: symmetric DTOs, strict decoding, cursor pagination,
// RFC 9457 problems, deprecation headers on v1. Pinned here so v1 and v2
// cannot drift silently.

// v2TestKey is the fixed key the harness's ServerSettings carries.
const v2TestKey = "hdns_live_testkey123"

// v2Mux builds a fresh mux with both route versions registered.
func v2Mux(a *API) http.Handler {
	mux := http.NewServeMux()
	a.RegisterRoutes(mux)
	return mux
}

func v2Get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-API-Key", v2TestKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestV2ClientsListIsPaginatedEnvelope(t *testing.T) {
	a, _, _, cleanup := setupTestAPI(t)
	mux := v2Mux(a)
	defer cleanup()

	// Three clients so pagination has something to slice.
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if _, err := a.clients.CreateClient(name, 0, ""); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	w := v2Get(t, mux, "/api/v2/clients?limit=2")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/clients = %d: %s", w.Code, w.Body.String())
	}
	var page struct {
		Items      []v2ClientDTO `json:"items"`
		NextCursor string        `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("limit=2 returned %d items", len(page.Items))
	}
	if page.NextCursor == "" {
		t.Fatal("a truncated page carried no next_cursor")
	}

	// Follow the cursor; the last page has no cursor.
	w = v2Get(t, mux, "/api/v2/clients?limit=2&cursor="+page.NextCursor)
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("page 2 returned %d items, want the 1 remaining", len(page.Items))
	}
	if page.NextCursor != "" {
		t.Errorf("the final page carried next_cursor %q", page.NextCursor)
	}
	_ = a
}

func TestV2RejectsUnknownFields(t *testing.T) {
	a, _, _, cleanup := setupTestAPI(t)
	mux := v2Mux(a)
	_ = a
	defer cleanup()

	// The v1 failure shape: a typo'd key silently produced a lifetime
	// account. v2 must name the unknown field instead of dropping it.
	body := `{"display_name":"v2-client","expires_days":30}`
	req := httptest.NewRequest(http.MethodPost, "/api/v2/clients", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", v2TestKey)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d — %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		t.Errorf("error Content-Type = %q, want RFC 9457 problem+json", ct)
	}
}

func TestV2CreateAndPatchShareFieldNames(t *testing.T) {
	a, _, _, cleanup := setupTestAPI(t)
	mux := v2Mux(a)
	defer cleanup()

	body := `{"display_name":"Symmetry","validity_days":30,"allowed_ips":["198.51.100.7"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v2/clients", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", v2TestKey)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", w.Code, w.Body.String())
	}
	var created v2ClientDTO
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.DisplayName != "Symmetry" || len(created.AllowedIPs) != 1 {
		t.Fatalf("created DTO is wrong: %+v", created)
	}
	if created.ExpiresAt == "" {
		t.Error("a 30-day create answered with no expires_at")
	}
	if created.Token == "" {
		t.Error("create response carried no token — the register link cannot be built")
	}

	// PATCH speaks the SAME name the create did (v1 split ip/allowed_ip).
	patch := `{"allowed_ips":["203.0.113.9"]}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v2/clients/"+created.ID, strings.NewReader(patch))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", v2TestKey)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("patch = %d: %s", w.Code, w.Body.String())
	}
	var patched v2ClientDTO
	if err := json.Unmarshal(w.Body.Bytes(), &patched); err != nil {
		t.Fatalf("decode patched: %v", err)
	}
	if len(patched.AllowedIPs) != 1 || patched.AllowedIPs[0] != "203.0.113.9" {
		t.Errorf("patched allowed_ips = %v, want [203.0.113.9]", patched.AllowedIPs)
	}
	_ = a
}

func TestV2ActionsArePostsUnderActions(t *testing.T) {
	a, _, _, cleanup := setupTestAPI(t)
	mux := v2Mux(a)
	defer cleanup()

	c, err := a.clients.CreateClient("ActionTarget", 0, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// reset-traffic lives under /actions/
	req := httptest.NewRequest(http.MethodPost, "/api/v2/clients/"+c.ID+"/actions/reset-traffic", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-API-Key", v2TestKey)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("reset-traffic = %d: %s", w.Code, w.Body.String())
	}

	// An unknown action is a 404 problem, not a fall-through to the id path.
	req = httptest.NewRequest(http.MethodPost, "/api/v2/clients/"+c.ID+"/actions/explode", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-API-Key", v2TestKey)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown action = %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		t.Errorf("unknown action Content-Type = %q, want problem+json", ct)
	}
}

// decodeStrict refuses trailing data after the first JSON value: the strict
// contract covers the frame boundary, not just the field boundary.
func TestV2StrictDecodeRefusesTrailingData(t *testing.T) {
	a, _, _, cleanup := setupTestAPI(t)
	defer cleanup()
	mux := http.NewServeMux()
	a.RegisterRoutesV2(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/clients",
		strings.NewReader(`{"display_name":"first"}{"display_name":"second"}`))
	req.Header.Set("X-API-Key", "hdns_live_testkey123")
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON = %d, want 400 — %s", w.Code, w.Body.String())
	}
}

func TestV1CarriesDeprecationHeaders(t *testing.T) {
	a, _, _, cleanup := setupTestAPI(t)
	mux := v2Mux(a)
	_ = a
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	req.RemoteAddr = "127.0.0.1:4444"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("v1 version = %d", w.Code)
	}
	if got := w.Header().Get("Deprecation"); got != "true" {
		t.Errorf("Deprecation header = %q, want true", got)
	}
	if got := w.Header().Get("Sunset"); got == "" {
		t.Error("no Sunset header on a deprecated v1 route")
	}
	if got := w.Header().Get("Link"); !strings.Contains(got, "successor-version") {
		t.Errorf("Link header = %q, want successor-version relation", got)
	}
}

func TestV2LimitIsBounded(t *testing.T) {
	a, _, _, cleanup := setupTestAPI(t)
	mux := v2Mux(a)
	_ = a
	defer cleanup()

	w := v2Get(t, mux, "/api/v2/clients?limit=10000")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("limit=10000 accepted: %d", w.Code)
	}
	w = v2Get(t, mux, "/api/v2/clients?limit=0")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("limit=0 accepted: %d", w.Code)
	}
	w = v2Get(t, mux, "/api/v2/clients?cursor=banana")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cursor=banana accepted: %d", w.Code)
	}
}
