package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// The two upstream editors are the only handlers that persist the whole "dns"
// record, which makes them the one place an unrelated edit can wipe a settings
// key. The live installation this project runs on carries real ports, cache sizes
// and a serve-stale window, so "add a resolver" has to mean only that.

// seedDNSRecord writes a complete "dns" record the way a running daemon does and
// returns what it wrote.
func seedDNSRecord(t *testing.T, db *database.DB) *database.DNSSettings {
	t.Helper()
	cfg := &database.DNSSettings{
		Enabled:           true,
		Port:              53,
		DoTPort:           853,
		DoHPort:           8443,
		Upstreams:         []string{"1.1.1.1:53", "8.8.8.8:53"},
		CacheSize:         20000,
		CacheMinTTL:       60,
		CacheMaxTTL:       86400,
		QueryTimeout:      2 * time.Second,
		FastestRacing:     true,
		ServeStaleSeconds: 30,
	}
	if err := db.SetSetting("dns", cfg); err != nil {
		t.Fatalf("seeding the dns record: %v", err)
	}
	return cfg
}

// storedDNS reads the persisted "dns" record back.
func storedDNS(t *testing.T, db *database.DB) *database.DNSSettings {
	t.Helper()
	got := &database.DNSSettings{}
	if err := db.GetSetting("dns", got); err != nil {
		t.Fatalf("reading the dns record back: %v", err)
	}
	return got
}

// TestAddUpstreamKeepsTheRestOfTheRecord is the regression. The handler used to
// substitute a blank DNSSettings whenever it had none of its own and then persist
// that, so adding one resolver reset the ports, the cache and the serve-stale
// window to zero.
func TestAddUpstreamKeepsTheRestOfTheRecord(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()

	seeded := seedDNSRecord(t, db)
	if ws.dnsCfg != nil {
		t.Fatal("this test only means something on a server built without DNS settings")
	}

	list, errMsg, status := ws.addUpstream("9.9.9.9:53")
	if status != 0 {
		t.Fatalf("addUpstream: %s (status %d)", errMsg, status)
	}
	if !slices.Contains(list, "9.9.9.9:53") {
		t.Errorf("the returned list is missing the new upstream: %v", list)
	}

	got := storedDNS(t, db)
	if got.ServeStaleSeconds != seeded.ServeStaleSeconds {
		t.Errorf("serve_stale_seconds = %d, want %d — an upstream edit turned serve-stale off",
			got.ServeStaleSeconds, seeded.ServeStaleSeconds)
	}
	if got.Port != 53 || got.DoTPort != 853 || got.CacheSize != 20000 || got.CacheMaxTTL != 86400 {
		t.Errorf("an upstream edit rewrote unrelated DNS settings: %+v", got)
	}
	if !got.Enabled || !got.FastestRacing || got.QueryTimeout != 2*time.Second {
		t.Errorf("an upstream edit cleared DNS feature flags: %+v", got)
	}
	if len(got.Upstreams) != 3 {
		t.Errorf("stored upstreams = %v, want the two seeded plus the new one", got.Upstreams)
	}
}

func TestRemoveUpstreamKeepsTheRestOfTheRecord(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()

	seedDNSRecord(t, db)

	list, errMsg, status := ws.removeUpstream("8.8.8.8:53")
	if status != 0 {
		t.Fatalf("removeUpstream: %s (status %d)", errMsg, status)
	}
	if len(list) != 1 || list[0] != "1.1.1.1:53" {
		t.Errorf("returned list = %v, want just the remaining resolver", list)
	}

	got := storedDNS(t, db)
	if got.ServeStaleSeconds != 30 || got.CacheSize != 20000 || got.DoHPort != 8443 {
		t.Errorf("a removal rewrote unrelated DNS settings: %+v", got)
	}
	if len(got.Upstreams) != 1 {
		t.Errorf("stored upstreams = %v, want one", got.Upstreams)
	}
}

// TestUpstreamGuards covers the three refusals, the last of which matters most:
// an empty upstream list fails every query that is not already cached.
func TestUpstreamGuards(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()
	seedDNSRecord(t, db)

	if _, _, status := ws.addUpstream("1.1.1.1:53"); status != http.StatusConflict {
		t.Errorf("adding a duplicate returned %d, want 409", status)
	}
	if _, _, status := ws.removeUpstream("203.0.113.1:53"); status != http.StatusNotFound {
		t.Errorf("removing an unknown upstream returned %d, want 404", status)
	}
	if _, msg, status := ws.removeUpstream("8.8.8.8:53"); status != 0 {
		t.Fatalf("the first removal failed: %s (%d)", msg, status)
	}
	if _, _, status := ws.removeUpstream("1.1.1.1:53"); status != http.StatusBadRequest {
		t.Errorf("removing the last resolver returned %d, want 400", status)
	}
}

// TestConcurrentUpstreamAddsAllLand pins the lock. Both editors are a
// read-modify-persist over a slice inside a struct two requests can reach at
// once, so two operators saving at the same moment could lose one of the entries.
func TestConcurrentUpstreamAddsAllLand(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()
	seedDNSRecord(t, db)

	const n = 24
	var wg sync.WaitGroup
	for i := range n {
		addr := fmt.Sprintf("192.0.2.%d:53", i+1)
		wg.Go(func() {
			if _, msg, status := ws.addUpstream(addr); status != 0 {
				t.Errorf("adding %s failed: %s (%d)", addr, msg, status)
			}
		})
	}
	wg.Wait()

	got := storedDNS(t, db)
	if len(got.Upstreams) != n+2 {
		t.Errorf("stored %d upstreams, want %d — a concurrent add was lost", len(got.Upstreams), n+2)
	}
	if got.ServeStaleSeconds != 30 {
		t.Errorf("serve_stale_seconds = %d after concurrent edits, want 30", got.ServeStaleSeconds)
	}
}

// TestUpstreamErrorBodyIsJSON pins the envelope the dashboard parses. The refusal
// paths build their body with %q now rather than by hand.
func TestUpstreamErrorBodyIsJSON(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()
	seedDNSRecord(t, db)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/upstreams/add",
		strings.NewReader(`{"address":"1.1.1.1:53"}`))
	ws.handleUpstreamsAdd(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the error body is not JSON: %v (%q)", err, rec.Body.String())
	}
	if body.Error == "" {
		t.Errorf("the error body carries no message: %q", rec.Body.String())
	}
}

// TestAddUpstreamNormalizesBareIP pins that the dashboard may send a bare address.
func TestAddUpstreamNormalizesBareIP(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()
	seedDNSRecord(t, db)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/upstreams/add",
		strings.NewReader(`{"address":"9.9.9.9"}`))
	ws.handleUpstreamsAdd(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := storedDNS(t, db); !slices.Contains(got.Upstreams, "9.9.9.9:53") {
		t.Errorf("stored upstreams = %v, want the bare IP normalized to :53", got.Upstreams)
	}
}
