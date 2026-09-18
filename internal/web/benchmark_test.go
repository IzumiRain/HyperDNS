package web

import (
	"net/http"
	"testing"
	"time"

	"hyperdns/internal/core/upstream"
	"hyperdns/internal/service"
)

// bearerFor logs the test admin in and returns the session token.
func bearerFor(t *testing.T, h http.Handler) string {
	t.Helper()
	tok, ok := decodeBody(t, login(t, h, "admin", testAdminPassword))["token"].(string)
	if !ok || tok == "" {
		t.Fatal("login did not return a token")
	}
	return tok
}

// emptyPool is an upstream pool with nothing in it, so BenchmarkAll is a no-op
// that touches no network. What these tests exercise is the handler's
// bookkeeping, not the probe.
func emptyPool() *upstream.UpstreamPool {
	return upstream.NewUpstreamPool(nil, time.Second, false, "")
}

// The endpoint used to accept any method. A benchmark is a side effect — it
// rewrites every upstream's latency estimate, which is the input to routing — so
// it must not be reachable by a GET that a browser can be talked into making.
func TestBenchmarkRejectsNonPost(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.upstreams = emptyPool()

	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if w := authedRequest(t, h, method, "/api/benchmark", tok); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/benchmark returned %d, want 405", method, w.Code)
		}
	}
	if ws.benchmark.Running() {
		t.Error("a rejected request still started a benchmark")
	}
}

func TestBenchmarkRequiresAuth(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.upstreams = emptyPool()

	h := ws.buildAdminHandler()
	if w := postJSON(t, h, "/api/benchmark", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated POST /api/benchmark returned %d, want 401", w.Code)
	}
	if ws.benchmark != nil && ws.benchmark.Running() {
		t.Error("an unauthenticated request started a benchmark")
	}
}

// The probe now runs in the background, so the handler answers 202 and the flag
// has to come back down on its own. A flag that leaks stays up for the lifetime
// of the process, and the button is dead from then on — the failure mode is a
// panel that silently stops re-ranking upstreams.
func TestBenchmarkStartsAsynchronouslyAndReleasesTheGate(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.upstreams = emptyPool()

	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	w := postJSON(t, h, "/api/benchmark", "", tok)
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST /api/benchmark returned %d, want 202: %s", w.Code, w.Body.String())
	}
	if body := decodeBody(t, w); body["started"] != true {
		t.Errorf(`response says started=%v, want true`, body["started"])
	}

	deadline := time.Now().Add(5 * time.Second)
	for ws.benchmark.Running() {
		if time.Now().After(deadline) {
			t.Fatal("benchmark gate was never released; the endpoint is wedged for good")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The panel and root-local control plane must coordinate through the same
// daemon-owned gate. Holding it here models a benchmark started by control.
func TestBenchmarkRefusesRunAlreadyStartedThroughSharedRunner(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	started := make(chan struct{})
	release := make(chan struct{})
	shared := service.NewBenchmarkRunner(func() {
		close(started)
		<-release
	})
	ws.SetControlState(shared, service.NewLoginAttemptTracker())

	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)
	if !shared.Start() {
		t.Fatal("control-side benchmark did not claim the shared gate")
	}
	<-started
	defer close(release)

	w := postJSON(t, h, "/api/benchmark", "", tok)
	if w.Code != http.StatusConflict {
		t.Fatalf("second POST /api/benchmark returned %d, want 409: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["started"] != false {
		t.Errorf(`refused response says started=%v, want false`, body["started"])
	}
	if body["running"] != true {
		t.Errorf(`refused response says running=%v, want true`, body["running"])
	}
}

// No pool configured is a real state — the daemon can be up with the resolver
// disabled — and it used to answer {"started":true} without having done
// anything at all.
func TestBenchmarkWithoutUpstreamPool(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)
	ws.upstreams = nil

	if w := postJSON(t, h, "/api/benchmark", "", tok); w.Code != http.StatusServiceUnavailable {
		t.Errorf("POST /api/benchmark with no pool returned %d, want 503: %s", w.Code, w.Body.String())
	}
	if ws.benchmark != nil && ws.benchmark.Running() {
		t.Error("a request with no pool still claimed the gate")
	}
}

// /api/matrix was a hardcoded table of invented latencies ("14 ms", "Direct
// Tunnel 0-Loss") that nothing consumed and that /api/diagnostics/run measures
// for real. It is gone; this pins it down, because a fabricated endpoint that
// looks like telemetry is worse than no endpoint.
func TestMatrixEndpointIsGone(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	ws.upstreams = emptyPool()

	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	w := authedRequest(t, h, http.MethodGet, "/api/matrix", tok)
	if ct := w.Header().Get("Content-Type"); ct == "application/json" {
		t.Errorf("/api/matrix still answers JSON (%d): %s", w.Code, w.Body.String())
	}
}
