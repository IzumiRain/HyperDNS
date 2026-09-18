package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The create form the panel posts carries the same plan fields the editor does:
// an exact expiry from the date picker and the policies chosen at creation.
// These tests pin the handler's pass-through of both, and the treatment of the
// picker's "no date chosen" sentinel — the JSON zero time, which arrives as a
// valid RFC 3339 timestamp and must not become a plan that expired in year 1.

func TestClientsCreateAcceptsAbsoluteExpiryAndPolicies(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	want := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	body := `{"name":"Picker Plan","expires_at":"` + want.Format(time.RFC3339) +
		`","traffic_limit_gb":25,"custom_policies":["enable_riot","enable_steam"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/clients/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create = %d, want 200 — %s", w.Code, w.Body.String())
	}

	// Read the record back through the service rather than trusting the response
	// echo: the point of the pass-through is what the resolver and the editor see
	// on the next load, not what the create request was told.
	var resp struct {
		ID             string    `json:"id"`
		ExpiresAt      time.Time `json:"expires_at"`
		CustomPolicies []string  `json:"custom_policies"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	stored, err := ws.clients.GetClient(resp.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !stored.ExpiresAt.Equal(want) {
		t.Errorf("stored expiry is %v, want the exact %v", stored.ExpiresAt, want)
	}
	if len(stored.CustomPolicies) != 2 || stored.CustomPolicies[0] != "enable_riot" || stored.CustomPolicies[1] != "enable_steam" {
		t.Errorf("stored policies are %v, want [enable_riot enable_steam]", stored.CustomPolicies)
	}
}

func TestClientsCreateTreatsTheZeroTimestampAsNoExpiry(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	// '0001-01-01T00:00:00Z' is what the edit form has always sent for "clear the
	// expiry", so the create form sends the same sentinel for a lifetime plan. It
	// is a well-formed timestamp and decodes into a non-nil pointer, so the
	// handler has to recognise it as "unset" rather than honour it.
	req := httptest.NewRequest(http.MethodPost, "/api/clients/add",
		strings.NewReader(`{"name":"Lifetime Plan","expires_at":"0001-01-01T00:00:00Z"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create = %d, want 200 — %s", w.Code, w.Body.String())
	}

	var resp struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	stored, err := ws.clients.GetClient(resp.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !stored.ExpiresAt.IsZero() {
		t.Errorf("a lifetime create expired at %v", stored.ExpiresAt)
	}
}
