package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The read-only endpoints of this API used to answer any verb at all. A PUT to /api/v1/status
// returned 200 and the full telemetry body; a DELETE to /api/v1/version returned 200 and the
// build info. Nothing was destroyed by that — there is nothing there to destroy — but a caller
// that used the wrong verb was told it had worked, which is the failure that costs an afternoon
// to find at the other end of an integration.
//
// The commit before this one guarded the mutating handlers and missed all three read-only ones
// (handleVersion, handleStatus, handleDocs). This file is the regression guard for the fix, and
// it deliberately checks the two directions that are easy to get wrong on the way back:
//
//   - GET and HEAD must still work. A guard written as `r.Method != http.MethodGet` alone
//     rejects HEAD, and HEAD is what an uptime probe sends.
//   - the 405 must be JSON even on /api/v1/docs, whose success path is text/html. That only
//     holds while the guard runs before the Content-Type header is set, and nothing about the
//     code's appearance tells you the order matters.

// routeHandleFuncRe reads the route patterns out of RegisterRoutes.
var routeHandleFuncRe = regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"`)

// registeredRoutes returns every pattern RegisterRoutes attaches to the mux, read from the
// source rather than listed here: http.ServeMux does not expose what has been registered on it,
// and a hand-written list would go stale exactly when a new endpoint is added — the moment the
// checks below become interesting.
func registeredRoutes(t *testing.T) []string {
	t.Helper()

	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("could not read router.go: %v", err)
	}
	var routes []string
	for _, m := range routeHandleFuncRe.FindAllStringSubmatch(string(src), -1) {
		routes = append(routes, m[1])
	}
	if len(routes) < 8 {
		t.Fatalf("parsed %d routes out of router.go, want at least the 8 v1 endpoints — the scan "+
			"is broken, which would make the checks that read it vacuous", len(routes))
	}
	return routes
}

// apiReq builds a request that reaches the handlers. The loopback RemoteAddr is not decoration:
// setupTestAPI leaves APIBind at 127.0.0.1, and SecurityMiddleware's gate reads the immediate
// peer, so httptest.NewRequest's default 192.0.2.1 would be answered 403 before any handler runs.
func apiReq(method, path string, withKey bool) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	if withKey {
		req.Header.Set("X-API-Key", "hdns_live_testkey123")
	}
	return req
}

// readOnlyEndpoints is every endpoint that answers GET/HEAD and nothing else, and whether
// SecurityMiddleware sits in front of it.
var readOnlyEndpoints = []struct {
	path   string
	authed bool
}{
	{"/api/v1/version", false},
	{"/api/v1/docs", false},
	{"/api/v1/status", true},
}

func TestReadOnlyEndpointsRejectWriteVerbs(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	for _, ep := range readOnlyEndpoints {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			w := httptest.NewRecorder()
			// The key is supplied where one is needed, so a 401 from the middleware cannot
			// stand in for the 405 this is actually testing.
			mux.ServeHTTP(w, apiReq(method, ep.path, ep.authed))

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s answered %d, want 405. A read-only endpoint that accepts a write "+
					"verb tells the caller its request was honoured when nothing happened.",
					method, ep.path, w.Code)
			}
		}
	}
}

// A guard written as a bare `r.Method != http.MethodGet` would pass the test above and break
// every uptime probe in the world, because HEAD is what they send. Both verbs, all three
// endpoints.
func TestReadOnlyEndpointsStillAnswerGetAndHead(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	for _, ep := range readOnlyEndpoints {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, apiReq(method, ep.path, ep.authed))

			if w.Code != http.StatusOK {
				t.Errorf("%s %s answered %d, want 200 — the method guard is rejecting a verb the "+
					"endpoint is supposed to serve.", method, ep.path, w.Code)
			}
		}
	}
}

// /api/v1/docs is the one endpoint whose success path is HTML, and its guard has to run before
// the Content-Type header is set or the 405 goes out labelled text/html while carrying a JSON
// body. Nothing in the code's shape hints that those two lines are ordered; this is what says so.
func TestTheDocsPageErrorIsJSONAndItsPageIsHTML(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	wErr := httptest.NewRecorder()
	mux.ServeHTTP(wErr, apiReq(http.MethodPost, "/api/v1/docs", false))
	if got := wErr.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("POST /api/v1/docs answered with Content-Type %q, want application/json — the "+
			"method guard has moved below the text/html header, so the error body and the header "+
			"now disagree about what the response is.", got)
	}

	wOK := httptest.NewRecorder()
	mux.ServeHTTP(wOK, apiReq(http.MethodGet, "/api/v1/docs", false))
	if got := wOK.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("GET /api/v1/docs answered with Content-Type %q, want text/html.", got)
	}
}

// Authentication runs in the middleware, ahead of every handler's method guard, so an anonymous
// caller gets 401 whatever verb it sends. That ordering is worth pinning: if a method guard ever
// moved in front of the auth check, the status code would start telling an unauthenticated prober
// which verbs each endpoint accepts, for free.
func TestAnonymousCallersLearnNothingFromTheMethodGuard(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, apiReq(method, "/api/v1/status", false))

		if w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s /api/v1/status answered %d, want 401 for every verb. A 405 here "+
				"would map the endpoint's accepted methods for a caller holding no key.",
				method, w.Code)
		}
	}
}

// /api/v1/version and /api/v1/docs are unauthenticated on purpose — install.sh prints the docs
// URL for the operator to open in a browser and the dashboard links to it, and SecurityMiddleware
// authenticates from headers only, so putting either behind it would 401 a URL the product tells
// people to click. This test exists so that decision is visible as a decision: whoever "hardens"
// them next has to delete a test that says why they are open.
func TestTheTwoPublicEndpointsNeedNoKey(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	mux := http.NewServeMux()
	apiInst.RegisterRoutes(mux)

	for _, path := range []string{"/api/v1/version", "/api/v1/docs"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, apiReq(http.MethodGet, path, false))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s without a key answered %d, want 200. Both are advertised to a browser "+
				"that has no way to send one.", path, w.Code)
		}
	}
}

// docsPage renders the documentation page the way a browser receives it.
func docsPage(t *testing.T, apiInst *API) string {
	t.Helper()

	w := httptest.NewRecorder()
	apiInst.handleDocs(w, apiReq(http.MethodGet, "/api/v1/docs", false))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/docs answered %d, want 200", w.Code)
	}
	return w.Body.String()
}

// specPathRe reads the path keys out of the embedded OpenAPI document.
var specPathRe = regexp.MustCompile(`"(/api/v1/[^"]*)":`)

// The spec used to omit /api/v1/api-key and /api/v1/docs: two real endpoints, one of them the
// key-rotation route, missing from the document this product publishes as its API reference.
// Reading either half tells you nothing — the route table and the spec sit 300 lines apart in the
// same file and neither mentions the other.
func TestEveryRegisteredRouteAppearsInTheSpec(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	page := docsPage(t, apiInst)

	for _, route := range registeredRoutes(t) {
		// A trailing slash is ServeMux's subtree match: that pattern serves the per-subscriber
		// routes, which the spec documents under {id} rather than as a bare prefix.
		want := `"` + route + `":`
		if strings.HasSuffix(route, "/") {
			want = `"` + route + `{id}"`
		}
		if !strings.Contains(page, want) {
			t.Errorf("RegisterRoutes serves %q and the embedded OpenAPI spec does not document it "+
				"(looked for %s). API.md and the dashboard both send people to this page, so an "+
				"endpoint missing from it is an endpoint nobody outside this file knows exists.",
				route, want)
		}
	}
}

// The mirror image, and the more embarrassing direction: a path the spec promises that no route
// serves. Matching follows ServeMux's own rule — an exact pattern, or a trailing-slash pattern the
// path begins with — so the {id} routes resolve through /api/v1/clients/ here exactly as they do
// at runtime, and a renamed or deleted endpoint is caught rather than left advertised.
func TestEveryDocumentedPathIsActuallyServed(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	routes := registeredRoutes(t)

	var paths []string
	for _, m := range specPathRe.FindAllStringSubmatch(docsPage(t, apiInst), -1) {
		paths = append(paths, m[1])
	}
	if len(paths) < 8 {
		t.Fatalf("parsed %d path keys out of the embedded spec, want at least 8 — the scan is "+
			"broken, and a broken scan here passes silently", len(paths))
	}

	for _, p := range paths {
		served := false
		for _, route := range routes {
			if p == route || (strings.HasSuffix(route, "/") && strings.HasPrefix(p, route)) {
				served = true
				break
			}
		}
		if !served {
			t.Errorf("the spec documents %q and no pattern in RegisterRoutes serves it. Try it out "+
				"on that operation answers 404, on the page the README calls the API reference.", p)
		}
	}
}

// README.md and API.md both advertise this page as live documentation with instant testing. The
// spec declared no securitySchemes at all, so Swagger UI rendered no Authorize control and had no
// way to attach a key: every Try it out on every authenticated operation returned 401, and the
// advertised feature could not have worked for anybody.
func TestTheSpecDeclaresHowToSendTheKey(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	page := docsPage(t, apiInst)

	for _, want := range []struct{ src, why string }{
		{"securitySchemes", "without it Swagger UI draws no Authorize control at all"},
		{`name: "X-API-Key"`, "the header SecurityMiddleware actually reads"},
		{`scheme: "bearer"`, "the Authorization: Bearer form the middleware also accepts"},
		{"ApiKeyAuth: []", "the document-wide requirement; without it the Authorize button applies " +
			"to no operation and the key is never sent"},
	} {
		if !strings.Contains(page, want.src) {
			t.Errorf("the embedded spec no longer contains %q — %s. Try it out then answers 401 on "+
				"every authenticated operation, on a page this product advertises as interactive.",
				want.src, want.why)
		}
	}
}

// The three per-subscriber operations take an id in the path. A path item that does not declare it
// leaves Swagger UI with no field to fill, so Try it out sends the literal {id} and comes back 404
// — which reads as a broken server rather than as a form the page forgot to draw.
func TestPathParametersAreDeclaredWhereverAnIDAppears(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	page := docsPage(t, apiInst)

	withID := 0
	for _, m := range specPathRe.FindAllStringSubmatch(page, -1) {
		if strings.Contains(m[1], "{id}") {
			withID++
		}
	}
	if withID == 0 {
		t.Fatal("no path key in the embedded spec contains {id}, so the per-subscriber operations " +
			"are either gone or no longer parameterised — the scan is broken either way.")
	}
	if got := strings.Count(page, `in: "path"`); got != withID {
		t.Errorf("%d spec paths take an {id} but %d path parameters are declared. Whichever "+
			"operations are missing theirs give Swagger UI nothing to fill in, and Try it out "+
			"requests the literal {id}.", withID, got)
	}
}

// offlineNotice returns just the static fallback block, so a check for a path inside it cannot be
// satisfied by the OpenAPI spec further down the same page.
func offlineNotice(t *testing.T, page string) string {
	t.Helper()

	start := strings.Index(page, `id="offline-notice"`)
	end := strings.Index(page, `<div id="swagger-ui">`)
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("could not find the offline-notice block ahead of #swagger-ui in the docs page "+
			"(start=%d end=%d) — either the fallback is gone or it moved, and every check that "+
			"reads it would otherwise pass on an empty string", start, end)
	}
	return page[start:end]
}

// The viewer on this page is fetched from unpkg.com by the browser, which on the networks this
// product is actually deployed to is a coin flip. Without a fallback the failure renders as an empty
// dark rectangle: no error, no hint, indistinguishable from a broken server on the one URL install.sh
// prints for the operator to open. So the page ships a static endpoint list, and that list is only
// worth having if it stays complete — an endpoint added to the route table and forgotten here is
// documentation that silently omits it exactly when nothing else on the page works.
func TestTheOfflineFallbackNamesEveryEndpoint(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	notice := offlineNotice(t, docsPage(t, apiInst))

	for _, route := range registeredRoutes(t) {
		// Same normalisation as the spec checks: a trailing-slash pattern is ServeMux's subtree
		// match, and the list names those routes by their {id} form.
		want := route
		if strings.HasSuffix(route, "/") {
			want = route + "{id}"
		}
		if !strings.Contains(notice, want) {
			t.Errorf("RegisterRoutes serves %q and the offline fallback list does not mention it "+
				"(looked for %q). That list is the whole of this page when unpkg.com is unreachable.",
				route, want)
		}
	}
}

// Which way round the fallback fails matters more than that it exists. It ships **visible** and the
// guarded inline script hides it once the viewer is known to have loaded — so anything that stops
// that script (an unreachable CDN, a CSP that drops inline script, a JS error) leaves the operator
// with the endpoint list. Invert it — hide in CSS, reveal on error — and every one of those failures
// is a blank page again, which is the exact outcome the fallback was added to remove.
func TestTheStaticFallbackOutlivesAFailedViewerLoad(t *testing.T) {
	apiInst, _, _, cleanup := setupTestAPI(t)
	defer cleanup()

	page := docsPage(t, apiInst)

	// The list is hidden in exactly one place: the guarded line of script. Not in the stylesheet,
	// not in a style attribute — either of those would hide it before the guard can decide.
	for _, css := range []string{"display: none", "display:none"} {
		if strings.Contains(page, css) {
			t.Errorf("the docs page hides something with the CSS %q. The fallback list has to ship "+
				"visible and be hidden by the script that confirmed the viewer loaded; hiding it in "+
				"CSS means a page whose script never runs shows nothing at all.", css)
		}
	}
	if got := strings.Count(page, "style.display = 'none'"); got != 1 {
		t.Errorf("the docs page hides an element through style.display %d times, want exactly one — "+
			"the guarded line that retires the fallback list once Swagger UI is really there.", got)
	}

	// Both the hide and the call read the same flag, so they cannot disagree about whether the
	// viewer is present.
	if got := strings.Count(page, "if (viewerLoaded)"); got != 2 {
		t.Errorf("%d statements in the docs page are guarded by viewerLoaded, want 2: hiding the "+
			"fallback and calling SwaggerUIBundle. If the call is guarded and the hide is not, an "+
			"unreachable CDN blanks the page; if the hide is guarded and the call is not, the "+
			"missing global throws.", got)
	}
	if !strings.Contains(page, "typeof SwaggerUIBundle === 'function'") {
		t.Error("the docs page no longer tests for SwaggerUIBundle before calling it. When the CDN " +
			"is unreachable that call is a TypeError inside an inline script, and the page renders " +
			"as an empty dark rectangle with nothing to say why.")
	}
}

// allowProbes is one concrete path per addressable resource, which is not the same list as the
// route table: /api/v1/clients/ is a subtree pattern standing for three resources with three
// different verb sets, since the two sub-actions are POST-only while the subscriber itself is not.
var allowProbes = []struct {
	path   string
	authed bool
}{
	{"/api/v1/version", false},
	{"/api/v1/docs", false},
	{"/api/v1/status", true},
	{"/api/v1/clients", true},
	{"/api/v1/clients/nosuchid", true},
	{"/api/v1/clients/nosuchid/regenerate-uuid", true},
	{"/api/v1/clients/nosuchid/reset-traffic", true},
	{"/api/v1/policies", true},
	{"/api/v1/cache/flush", true},
	{"/api/v1/api-key", true},
}

// probeVerbs ends with POST deliberately. POST is the only verb in this list that changes server
// state on a path that accepts it, and one of those paths rotates the master API key — after which
// the key every later probe sends is stale and the middleware answers 401, which is not 405 and
// would silently be read below as "this verb is allowed". Probing POST last keeps each path's
// remaining verbs ahead of any side effect.
var probeVerbs = []string{
	http.MethodGet, http.MethodHead, http.MethodPut,
	http.MethodDelete, http.MethodPatch, http.MethodPost,
}

// sortedSet renders a set of method names in a stable order, so two of them can be compared and
// printed without the map iteration order making a passing test flap.
func sortedSet(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// Every Allow value in this API is a string literal written out by hand beside the guard that
// rejects the request — thirty-odd verb names across ten handlers, with nothing connecting any list
// to the switch statement directly above it. Reading one against the other proves little: both were
// written in the same pass, by the same person, and would be wrong the same way.
//
// So this test does not read the lists. It probes every verb against every endpoint, treats
// "answered something other than 405" as the endpoint's own statement that it serves that verb, and
// requires the Allow header to name exactly that set. A wrong list then fails on the endpoint that
// owns it and prints both sides, whichever direction the mistake went: a verb advertised but not
// served sends an integrator off to write a request that 405s, and a verb served but not advertised
// hides working functionality behind the one response whose entire job is to say what to use.
func TestEveryMethodNotAllowedNamesTheVerbsItAccepts(t *testing.T) {
	for _, probe := range allowProbes {
		func() {
			// A fresh instance per path, because POST /api/v1/api-key genuinely rotates the key and
			// a rotated key would 401 — not 405 — every probe of every path examined after it.
			apiInst, _, _, cleanup := setupTestAPI(t)
			defer cleanup()

			mux := http.NewServeMux()
			apiInst.RegisterRoutes(mux)

			accepted := map[string]bool{}
			claimed := map[string]bool{}
			claimedBy := ""

			for _, verb := range probeVerbs {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, apiReq(verb, probe.path, probe.authed))

				if w.Code != http.StatusMethodNotAllowed {
					accepted[verb] = true
					continue
				}

				allow := w.Header().Get("Allow")
				if allow == "" {
					t.Errorf("%s %s answered 405 with no Allow header. RFC 9110 §15.5.6 requires "+
						"one, and without it the response tells a caller only that the verb was "+
						"wrong, never which verb to send instead.", verb, probe.path)
					continue
				}
				// Every 405 a single resource returns has to name the same set. Two different lists
				// on one path means one guard was updated and the one beside it was not.
				got := map[string]bool{}
				for m := range strings.SplitSeq(allow, ",") {
					got[strings.TrimSpace(m)] = true
				}
				if claimedBy == "" {
					claimed, claimedBy = got, verb
				} else if sortedSet(got) != sortedSet(claimed) {
					t.Errorf("%s advertises [%s] when refusing %s but [%s] when refusing %s. One "+
						"resource cannot accept two different sets of verbs.",
						probe.path, sortedSet(claimed), claimedBy, sortedSet(got), verb)
				}
			}

			if len(accepted) == 0 {
				t.Fatalf("every verb answered 405 on %s: the endpoint serves nothing at all, so the "+
					"path is wrong here or the route is gone. Comparing two empty sets would "+
					"otherwise pass and prove nothing.", probe.path)
			}
			if claimedBy == "" {
				t.Errorf("no verb was refused on %s, so there was no Allow header to check. Every "+
					"endpoint here refuses something — PATCH at the very least — and one that "+
					"refuses nothing is answering requests it has no meaning for.", probe.path)
				return
			}
			if sortedSet(accepted) != sortedSet(claimed) {
				t.Errorf("%s serves [%s] and its 405 advertises [%s]. The header is the only thing a "+
					"caller has to go on: a verb advertised but not served sends them to write a "+
					"request that 405s, and a verb served but not advertised hides an endpoint that "+
					"works.", probe.path, sortedSet(accepted), sortedSet(claimed))
			}
		}()
	}
}
