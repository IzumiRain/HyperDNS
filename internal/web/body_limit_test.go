package web

// The cap under test lives in exactly one place: BuildHandler's outer middleware wraps
// every r.Body in http.MaxBytesReader before the mux sees the request. That is also why
// it has to be checked somewhere other than the routes that cap for themselves —
// fifteen decoders in this package read the body with no limit of their own, and if the
// wrap is ever moved, reordered behind the mux, or dropped, those fifteen go straight
// back to allocating whatever the sender feels like sending. Nothing else in the suite
// would notice.
//
// So the subjects here are two routes that have no cap of their own, and each oversized
// request is one that would *succeed* if the body were read whole: a valid payload plus
// a large pad in a field the handler ignores.
//
// That detail is the test. The obvious version — one 2 MiB string in the address field —
// passes with the cap removed, because a 2 MiB address fails the handler's own
// validation and returns the same 400. Padding a valid payload instead makes the two
// worlds differ in what *happened* rather than only in the status code: with the cap,
// nothing is stored; without it, the resolver is added and the DoH token is persisted.

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// padded returns valid JSON — the caller's fields, then one field the handler does not
// read, holding size bytes. Only the pad is oversized, so what fails is the read rather
// than the parse, which is what makes the refusal attributable to the cap.
func padded(fields string, size int) string {
	return `{` + fields + `,"_pad":"` + strings.Repeat("9", size) + `"}`
}

// overCap is derived from the constant rather than written as a number, so raising the
// cap cannot quietly turn these tests into no-ops.
const overCap = 2 * maxRequestBody

// TestGlobalCapStopsAnUncappedWriteRoute uses /api/upstreams/add because it is capped by
// nothing but the middleware, and because what it writes is load-bearing: the pool every
// query is raced against.
func TestGlobalCapStopsAnUncappedWriteRoute(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()
	seeded := seedDNSRecord(t, db)
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	w := postJSON(t, h, "/api/upstreams/add", padded(`"address":"9.9.9.9:53"`, overCap), tok)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized POST /api/upstreams/add = %d, want 400 — %s", w.Code, w.Body.String())
	}
	if got := storedDNS(t, db).Upstreams; !slices.Equal(got, seeded.Upstreams) {
		t.Errorf("the upstream list is now %v, want %v unchanged. The payload was valid apart "+
			"from its size, so a list that grew means the whole body was read and acted on and "+
			"the cap did nothing.", got, seeded.Upstreams)
	}
}

// TestOrdinaryBodyPassesTheGlobalCap is the other half. A cap that refused everything
// would satisfy every assertion above, so the same route has to still work at a normal
// size — otherwise the test suite cannot tell "bounded" from "broken".
func TestOrdinaryBodyPassesTheGlobalCap(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()
	seedDNSRecord(t, db)
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	w := postJSON(t, h, "/api/upstreams/add", `{"address":"9.9.9.9:53"}`, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("ordinary POST /api/upstreams/add = %d, want 200 — %s", w.Code, w.Body.String())
	}
	if got := storedDNS(t, db).Upstreams; !slices.Contains(got, "9.9.9.9:53") {
		t.Errorf("the resolver was not stored: %v", got)
	}
}

// TestGlobalCapStopsAnUncappedCredentialWrite is the same property on a second route, so
// the fix is shown to be the middleware's rather than one handler's. /api/config/access
// is the sharper subject: the value in the padded payload is a DoH token, which is a
// credential the resolver accepts queries on. Without a bound, the pad is allocated
// before the request is looked at at all.
func TestGlobalCapStopsAnUncappedCredentialWrite(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	body := padded(`"doh_tokens":["smuggled-past-the-cap"]`, overCap)
	w := postJSON(t, h, "/api/config/access", body, tok)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized POST /api/config/access = %d, want 400 — %s", w.Code, w.Body.String())
	}
	if got := ws.loadAccessConfig().DoHTokens; len(got) != 0 {
		t.Errorf("the access record now carries %v. The refused request still wrote its "+
			"credential, which means the body was decoded in full first.", got)
	}
}

// TestTighterPerHandlerCapSurvivesTheGlobalOne pins the claim the middleware comment
// makes: a handler that wants a stricter bound sets its own, and wrapping an
// already-wrapped body leaves the tighter limit in force. handleSettings caps at 64 KiB,
// so a body between the two figures is refused by the inner wrap or by nothing — which
// is the property that lets a handler be stricter than the default without having to
// know a default exists.
func TestTighterPerHandlerCapSurvivesTheGlobalOne(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)

	// 128 KiB: twice handleSettings' own limit, an eighth of the middleware's.
	body := padded(`"public_ip":"203.0.113.10"`, 128<<10)
	if len(body) >= maxRequestBody {
		t.Fatalf("this body is %d bytes and the global cap is %d — the test would be "+
			"measuring the wrong wrap", len(body), maxRequestBody)
	}
	w := postJSON(t, h, "/api/settings", body, tok)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("128 KiB POST /api/settings = %d, want 400 — %s", w.Code, w.Body.String())
	}
	if ip, _ := ws.settings.Endpoint(); ip == "203.0.113.10" {
		t.Error("the advertised public IP was taken from a body the handler's own 64 KiB cap " +
			"should have refused, so the tighter wrap was lost")
	}
}
