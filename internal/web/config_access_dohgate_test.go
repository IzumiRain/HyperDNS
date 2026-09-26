package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recordingDoHGate is an http.Handler that also satisfies the narrow
// SetDoHTokens interface handleConfigAccess type-asserts to, so a test can see
// whether a save reached the live gate.
type recordingDoHGate struct {
	tokens []string
	calls  int
}

func (g *recordingDoHGate) ServeHTTP(http.ResponseWriter, *http.Request) {}
func (g *recordingDoHGate) SetDoHTokens(t []string) {
	g.tokens = t
	g.calls++
}

// TestConfigAccessAppliesDoHTokensToLiveGate is the regression for the stale-gate
// finding (audit F-3): POST /api/config/access must push the saved token list to
// the running DoH handler, not only persist it, so a first-enabled gate closes
// and a revoked token stops working without waiting for a restart.
func TestConfigAccessAppliesDoHTokensToLiveGate(t *testing.T) {
	_, db, cleanup := setupTestWebServer(t)
	defer cleanup()

	gate := &recordingDoHGate{}
	ws := &WebServer{db: db, dohHandler: gate}

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/config/access", strings.NewReader(body))
		rec := httptest.NewRecorder()
		ws.handleConfigAccess(rec, req)
		return rec
	}

	// Enable a token.
	if rec := post(`{"doh_tokens":["vfytoken12345"]}`); rec.Code != http.StatusOK {
		t.Fatalf("save status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if gate.calls == 0 {
		t.Fatal("saving DoH tokens did not reach the live gate (enforcement would wait for a restart)")
	}
	if len(gate.tokens) != 1 || gate.tokens[0] != "vfytoken12345" {
		t.Fatalf("live gate tokens = %v, want [vfytoken12345]", gate.tokens)
	}

	// Revoke: the empty list must also reach the gate immediately.
	if rec := post(`{"doh_tokens":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", rec.Code)
	}
	if len(gate.tokens) != 0 {
		t.Fatalf("revoke did not reach the live gate: tokens = %v", gate.tokens)
	}

	// And the change is persisted, not just pushed to the gate.
	if got := ws.loadAccessConfig(); len(got.DoHTokens) != 0 {
		t.Fatalf("persisted tokens = %v, want empty after revoke", got.DoHTokens)
	}
}
