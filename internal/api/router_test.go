package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"hyperdns/internal/database"
)

// These tests cover the parts of SecurityMiddleware and the handlers that are easy
// to get wrong in a way no manual click-through would ever reveal: a method guard
// that is not there, a loopback check that compares strings, and an error body that
// says "application/json" while carrying something that is not JSON.

const testKey = "hdns_live_testkey123"

func authedRequest(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	req.Header.Set("X-API-Key", testKey)
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

// TestFlushCacheRejectsGET is the regression test for a GET emptying the resolver's
// cache. The handler had no method guard, so anything that speculatively fetches a
// URL — a link preview, a prefetcher, an address-bar completion — could drop every
// cached answer and hand every subscriber a cold-cache latency spike at once.
func TestFlushCacheRejectsGET(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	// Seed one entry so "the cache was not flushed" is an observation, not an
	// assumption about an empty cache staying empty.
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR("example.com. 300 IN A 203.0.113.10")
	if err != nil {
		t.Fatalf("could not build the test record: %v", err)
	}
	msg.Answer = []dns.RR{rr}
	apiInst.cache.Put(q, msg)
	if got := apiInst.cache.Count(); got != 1 {
		t.Fatalf("seeding the cache failed: want 1 entry, got %d", got)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authedRequest(method, "/api/v1/cache/flush", nil))

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/v1/cache/flush: want 405, got %d", method, w.Code)
		}
		if got := apiInst.cache.Count(); got != 1 {
			t.Fatalf("%s /api/v1/cache/flush emptied the cache: %d entries left", method, got)
		}
	}

	// POST is the documented verb and must still work.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, authedRequest(http.MethodPost, "/api/v1/cache/flush", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/cache/flush: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := apiInst.cache.Count(); got != 0 {
		t.Errorf("POST /api/v1/cache/flush left %d entries in the cache", got)
	}
}

// TestMutatingSubActionsRejectGET covers the same class of bug on the two client
// sub-actions, which also used to run on any method.
func TestMutatingSubActionsRejectGET(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	created, err := apiInst.clients.CreateClient("Method Guard", 30, "")
	if err != nil {
		t.Fatalf("could not create the fixture client: %v", err)
	}

	for _, action := range []string{"regenerate-uuid", "reset-traffic"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authedRequest(http.MethodGet, "/api/v1/clients/"+created.ID+"/"+action, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET .../%s: want 405, got %d", action, w.Code)
		}
	}

	// The UUID must be unchanged after the rejected GETs.
	after, err := apiInst.clients.GetClient(created.ID)
	if err != nil {
		t.Fatalf("could not re-read the client: %v", err)
	}
	if after.UUID != created.UUID {
		t.Errorf("a rejected GET still rotated the UUID: %s -> %s", created.UUID, after.UUID)
	}
}

// TestClientErrorStatuses pins the status codes both front-ends now share. Before
// this mapping every client-service failure was a 500: a mistyped address told the
// operator the daemon was broken, and RegenerateUUID answered a blanket 404 that
// reported a database write failure as "no such client".
func TestClientErrorStatuses(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	tests := []struct {
		name   string
		method string
		path   string
		body   []byte
		want   int
	}{
		{
			name:   "unparseable address is the caller's fault",
			method: http.MethodPost,
			path:   "/api/v1/clients",
			body:   []byte(`{"name":"Bad Address","days":30,"ip":"203.0.113.999"}`),
			want:   http.StatusBadRequest,
		},
		{
			name:   "missing name is the caller's fault",
			method: http.MethodPost,
			path:   "/api/v1/clients",
			body:   []byte(`{"days":30}`),
			want:   http.StatusBadRequest,
		},
		{
			name:   "malformed JSON is the caller's fault",
			method: http.MethodPost,
			path:   "/api/v1/clients",
			body:   []byte(`{"name":`),
			want:   http.StatusBadRequest,
		},
		{
			name:   "unknown client on GET",
			method: http.MethodGet,
			path:   "/api/v1/clients/NOPE0000",
			want:   http.StatusNotFound,
		},
		{
			name:   "unknown client on PUT",
			method: http.MethodPut,
			path:   "/api/v1/clients/NOPE0000",
			body:   []byte(`{"name":"Renamed"}`),
			want:   http.StatusNotFound,
		},
		{
			name:   "unknown client on DELETE",
			method: http.MethodDelete,
			path:   "/api/v1/clients/NOPE0000",
			want:   http.StatusNotFound,
		},
		{
			name:   "unknown client on regenerate-uuid",
			method: http.MethodPost,
			path:   "/api/v1/clients/NOPE0000/regenerate-uuid",
			want:   http.StatusNotFound,
		},
		{
			name:   "unknown client on reset-traffic",
			method: http.MethodPost,
			path:   "/api/v1/clients/NOPE0000/reset-traffic",
			want:   http.StatusNotFound,
		},
		{
			name:   "policy without a key is the caller's fault",
			method: http.MethodPost,
			path:   "/api/v1/policies",
			body:   []byte(`{"enabled":true}`),
			want:   http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, authedRequest(tc.method, tc.path, tc.body))
			if w.Code != tc.want {
				t.Errorf("%s %s: want %d, got %d: %s", tc.method, tc.path, tc.want, w.Code, w.Body.String())
			}
			assertJSONErrorBody(t, w)
		})
	}
}

// TestErrorBodiesAreJSON is the regression test for hand-built error bodies. Every
// failure the dashboard shows is read with res.json(), so a body that is not JSON —
// or one declared as text/plain — costs the operator the reason and leaves them with
// a generic "the request failed".
func TestErrorBodiesAreJSON(t *testing.T) {
	apiInst, _, settings, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	// 401: no key at all.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	assertJSONErrorBody(t, w)

	// 403: a non-loopback peer while the API is bound to localhost.
	setAPIBind(t, settings, "127.0.0.1")
	w = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "198.51.100.7:40000"
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for an external peer, got %d", w.Code)
	}
	assertJSONErrorBody(t, w)

	// 405: a method the route does not serve.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, authedRequest(http.MethodPatch, "/api/v1/clients", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
	assertJSONErrorBody(t, w)
}

// TestErrorBodySurvivesQuotesInTheMessage is the specific reason the hand-built
// `{"error":"%v"}` had to go: the error text quotes the operator's own input back,
// and a %q-formatted address is exactly the shape that breaks a hand-built JSON
// string. The name here carries a double quote and a backslash.
func TestErrorBodySurvivesQuotesInTheMessage(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	body, err := json.Marshal(map[string]any{
		"name": `He said "hi" \ then left`,
		"days": 30,
		"ip":   `1.2.3."4`,
	})
	if err != nil {
		t.Fatalf("could not build the request body: %v", err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, authedRequest(http.MethodPost, "/api/v1/clients", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for an unparseable address, got %d: %s", w.Code, w.Body.String())
	}
	msg := assertJSONErrorBody(t, w)
	// The address is quoted back with %q, so the message itself contains a double
	// quote. That is the character that used to produce a body which was not JSON at
	// all — assertJSONErrorBody above is the real assertion; this one only confirms
	// the operator still gets to see what was refused.
	if !strings.Contains(msg, "1.2.3.") {
		t.Errorf("the refused address is missing from the message, so the operator cannot see what was wrong: %q", msg)
	}
	if !strings.Contains(msg, `"`) {
		t.Errorf("the quote from the input did not survive into the decoded message: %q", msg)
	}
}

// TestLoopbackFormsAreAccepted covers the reason the gate parses the peer address
// instead of comparing it to "127.0.0.1". A dual-stack listener reports loopback as
// ::ffff:127.0.0.1, and systemd-resolved hands off from 127.0.0.53 — both were
// locked out by the string compare, which is a daemon that answers on the console
// and refuses its own operator.
func TestLoopbackFormsAreAccepted(t *testing.T) {
	apiInst, _, settings, cleanup := setupTestAPI(t)
	defer cleanup()
	setAPIBind(t, settings, "127.0.0.1")

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	allowed := []string{
		"127.0.0.1:12345",
		"127.0.0.53:12345",
		"127.1.2.3:12345",
		"[::1]:12345",
		"[::ffff:127.0.0.1]:12345",
	}
	for _, peer := range allowed {
		w := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = peer
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("peer %s: want 200, got %d: %s", peer, w.Code, w.Body.String())
		}
	}

	refused := []string{
		"198.51.100.7:40000",
		"[2001:db8::1]:40000",
		// Not loopback, however much it looks like it.
		"1.0.0.127:40000",
	}
	for _, peer := range refused {
		w := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = peer
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("peer %s: want 403, got %d", peer, w.Code)
		}
	}
}

// TestForwardedHeaderCannotPassTheBindGate is the reason the gate reads the immediate
// peer rather than netutil.ClientIP: a header the caller controls must never carry a
// request past a listener the operator deliberately bound to localhost.
func TestForwardedHeaderCannotPassTheBindGate(t *testing.T) {
	apiInst, _, settings, cleanup := setupTestAPI(t)
	defer cleanup()
	setAPIBind(t, settings, "127.0.0.1")

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
		w := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "198.51.100.7:40000"
		req.Header.Set(header, "127.0.0.1")
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: a forwarding header walked past the localhost bind (got %d)", header, w.Code)
		}
	}
}

// TestOversizedBodyIsRefused covers the MaxBytesReader added to the two POSTs that
// lacked one. An authenticated caller is still a caller, and an unbounded decode
// lets one request hand the daemon as much memory as the sender feels like sending.
func TestOversizedBodyIsRefused(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	// 2 MB of name, against a 1 MB limit.
	huge := `{"name":"` + strings.Repeat("A", 2<<20) + `","days":30}`

	for _, path := range []string{"/api/v1/clients", "/api/v1/policies"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authedRequest(http.MethodPost, path, []byte(huge)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST %s with a 2MB body: want 400, got %d", path, w.Code)
		}
	}
}

// setAPIBind writes the bind mode through the accessor rather than the field, so the
// test takes the same lock the daemon does and cannot pass by racing it.
func setAPIBind(t *testing.T, settings *database.ServerSettings, bind string) {
	t.Helper()
	if err := settings.UpdateAndPersist(func(m *database.MutableSettings) { m.APIBind = bind }, nil); err != nil {
		t.Fatalf("could not set APIBind to %q: %v", bind, err)
	}
}

// assertJSONErrorBody checks that a failure response is what it claims to be, and
// returns the message so a caller can assert on its contents.
func assertJSONErrorBody(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type is %q, want application/json", ct)
	}

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("the error body is not JSON (%v): %s", err, w.Body.String())
	}
	msg, ok := payload["error"]
	if !ok {
		t.Fatalf(`the error body has no "error" field: %s`, w.Body.String())
	}
	if msg == "" {
		t.Error(`the error body carries an empty message, which reads as "it failed, no reason given"`)
	}
	return msg
}
