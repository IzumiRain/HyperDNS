package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/httpx"
	"hyperdns/internal/netutil"
	"hyperdns/internal/service"
	"hyperdns/internal/version"
)

type API struct {
	db          *database.DB
	clients     *service.ClientService
	stats       *service.StatsService
	cache       *cache.Cache
	matcher     *matcher.Matcher
	upstreams   *upstream.UpstreamPool
	settings    *database.ServerSettings
	tlsSettings *database.TLSSettings
	sessions    *service.SessionManager

	// totpGate is injected by the web server (this package cannot import it)
	// so the state-changing POSTs here face the same second factor the
	// dashboard's equivalents enforce. nil in harnesses: the gate then reads
	// as "2FA not in force", which is exactly what the dashboard's gate does
	// when TOTP is off.
	totpGate func(*http.Request) bool
}

// SetTOTPGate attaches the second-factor predicate for credential-changing
// POSTs. The dashboard enforces it on /api/settings/regenerate-api-key; the
// v1 route does the same work and must not become the unguarded copy of it.
func (a *API) SetTOTPGate(g func(*http.Request) bool) {
	a.totpGate = g
}

func NewAPI(
	db *database.DB,
	clients *service.ClientService,
	stats *service.StatsService,
	cache *cache.Cache,
	matcher *matcher.Matcher,
	upstreams *upstream.UpstreamPool,
	settings *database.ServerSettings,
	tlsSettings *database.TLSSettings,
	sessions *service.SessionManager,
) *API {
	return &API{
		db:          db,
		clients:     clients,
		stats:       stats,
		cache:       cache,
		matcher:     matcher,
		upstreams:   upstreams,
		settings:    settings,
		tlsSettings: tlsSettings,
		sessions:    sessions,
	}
}

// SecurityMiddleware validates APIBind access & API-Key authentication
func (a *API) SecurityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// 1. Enforce APIBind Security Gate. The gate is decided by the immediate
		// peer, deliberately not by netutil.ClientIP: a forwarding header must
		// never be able to carry a request past a listener the operator bound to
		// localhost. Comparing strings missed 127.0.0.53 and the
		// ::ffff:127.0.0.1 form a dual-stack listener reports, so parse instead.
		peerIP := netutil.PeerIP(r)
		isLoopback := false
		if ip := net.ParseIP(peerIP); ip != nil {
			isLoopback = ip.IsLoopback()
		}

		if a.settings.GetAPIBind() != "0.0.0.0" && !isLoopback {
			// Reject external calls if bound only to localhost
			httpx.WriteJSONError(w, http.StatusForbidden, "REST API is strictly bound to localhost (127.0.0.1). Enable Public API in Settings to allow external access.")
			return
		}

		// 2. Validate Authentication (X-API-Key, Bearer Token, or live dashboard session)
		apiKey := r.Header.Get("X-API-Key")
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}

		// One read of the master key, not two: the emptiness test and the comparison
		// used to be separate field reads, so a rotation landing between them meant
		// the request was compared against a key different from the one that had just
		// been found non-empty.
		var authorized bool
		if master := a.settings.GetAPIKey(); apiKey != "" && master != "" {
			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(master)) == 1 {
				authorized = true
			}
		}
		if !authorized && a.sessions != nil {
			authorized = a.sessions.Validate(apiKey)
		}
		if !authorized {
			httpx.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid or missing API Key")
			return
		}

		next(w, r)
	}
}

// BindGate applies the APIBind exposure rule to the routes that carry no
// key: build metadata and the docs page. When the REST API is bound to
// localhost, an external caller gets the same 403 every authenticated route
// gives — the endpoint map and the build version are part of the API surface
// and do not leak past a localhost bind either. Without this gate the docs
// page (and only it) answered remote browsers on an install whose operator
// believed the whole REST surface was loopback-only.
func (a *API) BindGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peerIP := netutil.PeerIP(r)
		isLoopback := false
		if ip := net.ParseIP(peerIP); ip != nil {
			isLoopback = ip.IsLoopback()
		}
		if a.settings.GetAPIBind() != "0.0.0.0" && !isLoopback {
			httpx.WriteJSONError(w, http.StatusForbidden, "REST API is strictly bound to localhost (127.0.0.1). Enable Public API in Settings to allow external access.")
			return
		}
		next(w, r)
	}
}

// RegisterRoutes attaches all /api/v1/ endpoints to the HTTP mux. Every
// authenticated route carries the v1 deprecation markers (v2 is the
// successor contract; the versioned transition keeps v1 working — with the
// same security fixes — until its sunset).
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/version", a.DeprecateV1(a.BindGate(a.handleVersion)))
	mux.HandleFunc("/api/v1/status", a.DeprecateV1(a.SecurityMiddleware(a.handleStatus)))
	mux.HandleFunc("/api/v1/clients", a.DeprecateV1(a.SecurityMiddleware(a.handleClients)))
	mux.HandleFunc("/api/v1/clients/", a.DeprecateV1(a.SecurityMiddleware(a.handleClientAction)))
	mux.HandleFunc("/api/v1/policies", a.DeprecateV1(a.SecurityMiddleware(a.handlePolicies)))
	mux.HandleFunc("/api/v1/cache/flush", a.DeprecateV1(a.SecurityMiddleware(a.handleFlushCache)))
	mux.HandleFunc("/api/v1/api-key", a.DeprecateV1(a.SecurityMiddleware(a.handleAPIKey)))
	mux.HandleFunc("/api/v1/docs", a.DeprecateV1(a.BindGate(a.handleDocs)))
	mux.HandleFunc("/api/server/restart", a.DeprecateV1(a.SecurityMiddleware(a.handleRestart)))

	// v2: the successor contract (RFC 9457 errors, cursor pagination,
	// symmetric DTOs, strict decoding).
	a.RegisterRoutesV2(mux)
}

// handleVersion is intentionally unauthenticated: build metadata is not sensitive.
//
// GET and HEAD only, like every other read-only endpoint here. This one and handleStatus
// were the two the method-guard pass missed, and both answered a PUT or a DELETE with 200
// and a body — a caller using the wrong verb was told it had worked.
func (a *API) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(version.Get())
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	// SecurityMiddleware has already answered OPTIONS by the time this runs, so this is
	// only ever a real request with a verb this endpoint has no meaning for.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	stats := a.stats.GetLiveStats()
	publicIP, apiBind := a.settings.Endpoint()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"version":   version.Get(),
		"timestamp": time.Now(),
		"telemetry": stats,
		"public_ip": publicIP,
		"api_bind":  apiBind,
	})
}

func (a *API) handleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	// HEAD runs the read path and net/http discards the body, so it costs nothing and
	// answers the uptime probes that send it. RFC 9110 §9.1 expects any resource serving
	// GET to serve HEAD; every readable endpoint in this file now does.
	case http.MethodGet, http.MethodHead:
		// Views, not stored records: an integration reading this list should not have
		// to reimplement the quota rule or the clamped-month arithmetic to know who is
		// cut off and when their allowance returns. Every field of the stored record is
		// still present and in the same place — the struct is embedded, so it flattens.
		clients, err := a.clients.ListClientViews()
		if err != nil {
			httpx.WriteJSONErrorFor(w, http.StatusInternalServerError, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"clients": clients})

	case http.MethodPost:
		var req struct {
			Name           string   `json:"name"`
			Days           int      `json:"days"`
			IP             string   `json:"ip"`
			TrafficLimitGB float64  `json:"traffic_limit_gb"`
			CustomPolicies []string `json:"custom_policies"`
			Note           string   `json:"note"`

			// "", "daily", "weekly" or "monthly": the period after which the quota
			// above comes back on its own. Omitting it keeps the pre-v1.5.0 behaviour,
			// where a spent limit stays spent until an operator resets it by hand.
			TrafficResetCycle string `json:"traffic_reset_cycle"`
		}
		// Bounded like the PUT below. An authenticated caller is still a caller: an
		// unbounded decode lets one request name a client whose length is whatever the
		// sender feels like sending, and the daemon holds all of it.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}
		// One write, so nothing can half-succeed. This used to create the account and
		// then update it to attach the quota, the cycle, the note and the policies, with
		// the second error swallowed so the request still answered 201 — an integration
		// that provisioned a 50 GB monthly plan and lost that write got back a live
		// account with no limit at all. ProvisionClient also refuses an unsupported
		// cycle, and refuses it before anything is stored.
		client, err := a.clients.ProvisionClient(service.CreateClientRequest{
			Name: req.Name,
			Days: req.Days,
			IP:   req.IP,

			TrafficLimitGB:    req.TrafficLimitGB,
			TrafficResetCycle: req.TrafficResetCycle,

			Note:           req.Note,
			CustomPolicies: req.CustomPolicies,
		})
		if err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(a.clients.ViewClient(client))

	default:
		httpx.WriteMethodNotAllowed(w, "GET, HEAD, POST")
	}
}

func (a *API) handleClientAction(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	id = strings.TrimSpace(strings.TrimSuffix(id, "/"))

	// Both sub-actions mutate state and are documented as POST, so anything else
	// is rejected rather than silently treated as a POST.
	if clientID, ok := strings.CutSuffix(id, "/regenerate-uuid"); ok {
		if r.Method != http.MethodPost {
			httpx.WriteMethodNotAllowed(w, "POST")
			return
		}
		newUUID, err := a.clients.RegenerateUUID(clientID)
		if err != nil {
			// Not a blanket 404: this reached the database, and a bbolt write failure
			// answering "no such client" sends an integration hunting for a record
			// that is sitting right there in the list.
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"uuid": newUUID})
		return
	}

	if clientID, ok := strings.CutSuffix(id, "/reset-traffic"); ok {
		if r.Method != http.MethodPost {
			httpx.WriteMethodNotAllowed(w, "POST")
			return
		}
		if err := a.clients.ResetClientTraffic(clientID); err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"reset": true})
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		client, err := a.clients.GetClient(id)
		if err != nil {
			httpx.WriteJSONError(w, http.StatusNotFound, "Client not found")
			return
		}
		// Decorated with the live usage total, so a billing integration polling this
		// route sees what the resolver sees rather than what the last flush wrote.
		_ = json.NewEncoder(w).Encode(a.clients.ViewClient(client))

	case http.MethodPut:
		var req service.UpdateClientRequest
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}
		updated, err := a.clients.UpdateClient(id, req)
		if err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		// Changing the cycle moves the next reset, so the response carries the new
		// boundary rather than leaving the caller to derive it from the name it sent.
		_ = json.NewEncoder(w).Encode(a.clients.ViewClient(updated))

	case http.MethodDelete:
		if err := a.clients.DeleteClient(id); err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"deleted": true})

	default:
		httpx.WriteMethodNotAllowed(w, "GET, HEAD, PUT, DELETE")
	}
}

func (a *API) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		policies, err := a.db.ListPolicies()
		if err != nil {
			httpx.WriteJSONErrorFor(w, http.StatusInternalServerError, err)
			return
		}
		// API.md has always described this route as "every gaming and streaming
		// preset", and it never was: ListPolicies returns the persisted *overrides*, so
		// a fresh install answered with an empty array and an integration reading it had
		// no way to learn which policy keys exist. The catalogue is what that
		// description promised, and it comes from the matcher — the package that decides
		// what a key means — rather than from a second list kept in step by hand.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policies": policies,
			"catalog":  matcher.PolicyCatalog(),
		})

	case http.MethodPost:
		var p database.Policy
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Key == "" {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}
		if err := a.db.SavePolicy(p); err != nil {
			httpx.WriteJSONErrorFor(w, http.StatusInternalServerError, err)
			return
		}
		if a.matcher != nil {
			a.matcher.SetRuleEnabled(p.Key, p.Enabled)
		}
		_ = json.NewEncoder(w).Encode(p)

	default:
		httpx.WriteMethodNotAllowed(w, "GET, HEAD, POST")
	}
}

func (a *API) handleFlushCache(w http.ResponseWriter, r *http.Request) {
	// POST-only, as API.md and the OpenAPI spec below both document it. It used to
	// accept any method, so a GET emptied the resolver's cache — and a GET is what a
	// link preview, a prefetcher or a browser's address-bar completion will issue on
	// its own. Every cached answer being dropped is not fatal, but it is a latency
	// spike on the next query for every subscriber at once, which on a resolver sold
	// for its ping is the whole product misbehaving.
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	if a.cache != nil {
		a.cache.Flush()
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"flushed": true})
}

func (a *API) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	// Restart endpoint flushes the cache. A full daemon restart with listener
	// teardown/rebuild requires process control outside the API's scope.
	// For now, this provides cache invalidation which is the primary operator need.
	if a.cache != nil {
		a.cache.Flush()
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"restarted": true})
}

func (a *API) handleAPIKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		key := a.settings.GetAPIKey()
		bind := a.settings.GetAPIBind()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":  true,
			"api_key":  key,
			"api_bind": bind,
			"data": map[string]string{
				"api_key":  key,
				"api_bind": bind,
			},
		})
	case http.MethodPost:
		// Regenerate Master API Key. The second factor first, exactly as the
		// dashboard's rotate endpoint enforces it: a live session is accepted
		// by SecurityMiddleware, so without this gate a hijacked session could
		// rotate the key with two-factor on — the one credential change the
		// dashboard refuses to do unguarded.
		if a.totpGate != nil && !a.totpGate(r) {
			httpx.WriteJSONError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		newKey := crypto.GenerateAPIKey()

		// The persist error used to be discarded, so a failed write answered with the
		// new key while the database kept the old one: every integration the operator
		// then reconfigured worked until the next restart and failed together after
		// it. UpdateAndPersist rolls the in-memory value back instead.
		if err := a.settings.UpdateAndPersist(
			func(m *database.MutableSettings) { m.APIKey = newKey },
			func(s *database.ServerSettings) error { return a.db.SetSetting("server", s) },
		); err != nil {
			log.Printf("[API] Could not persist the regenerated API key: %v", err)
			httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not save the new API key")
			return
		}
		log.Printf("[API] REST API key regenerated")

		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"api_key": newKey,
			"data": map[string]string{
				"api_key": newKey,
			},
		})
	default:
		httpx.WriteMethodNotAllowed(w, "GET, HEAD, POST")
	}
}

func (a *API) handleDocs(w http.ResponseWriter, r *http.Request) {
	// The third endpoint the method-guard pass missed, and the only one of the three that is
	// both unauthenticated and reachable from a browser, so it is the one most likely to be
	// poked with an arbitrary verb. GET/HEAD, and the 405 goes out before the text/html header
	// below so the error still carries the JSON content type every other error in this file has.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Swagger UI is vendored (web/swagger/, embedded, served same-origin under
	// the admin namespace), so this page runs under the dashboard-wide 'self'
	// policy with no per-route override — the CDN exception is gone.
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>HyperDNS REST API v1 Documentation</title>
  <meta charset="utf-8"/>
  <link rel="stylesheet" type="text/css" href="%s/swagger/swagger-ui.css">
  <style>
    body { margin: 0; background: #0b0f19; }
    .swagger-ui { filter: invert(88%%) hue-rotate(180deg); }
    #offline-notice { max-width: 52rem; margin: 0 auto; padding: 2.5rem 1.5rem; color: #e5e7eb;
      font-family: ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif; line-height: 1.65; }
    #offline-notice h1 { color: #00f0ff; font-size: 1.5rem; margin: 0 0 .25rem; }
    #offline-notice h2 { color: #e5e7eb; font-size: 1rem; margin: 2rem 0 .5rem; }
    #offline-notice p { color: #9ca3af; margin: .5rem 0; }
    #offline-notice code, #offline-notice li { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
    #offline-notice code { color: #00f0ff; }
    #offline-notice ul { list-style: none; padding: 0; margin: .5rem 0; }
    #offline-notice li { border-left: 2px solid #1f2937; padding: .3rem 0 .3rem .75rem; font-size: .9rem; }
    #offline-notice b { color: #10b981; font-weight: 600; }
  </style>
</head>
<body>
  <div id="offline-notice">
    <h1>HyperDNS REST API v1</h1>
    <p>The interactive viewer normally loads here, but this browser could not load it
      from this origin. <b>The API itself is running normally</b> &mdash; only the viewer is
      missing. Every endpoint below is live right now; from the server itself:</p>
    <p><code>curl -s "http://127.0.0.1:8080/&lt;admin-path&gt;/api/v1/version"</code></p>
    <h2>Endpoints</h2>
    <ul>
      <li>GET&nbsp;&nbsp;&nbsp;/api/v1/version &mdash; build version and sync hash (no key)</li>
      <li>GET&nbsp;&nbsp;&nbsp;/api/v1/docs &mdash; this page (no key)</li>
      <li>GET&nbsp;&nbsp;&nbsp;/api/v1/status &mdash; live telemetry: QPS, cache, latency, relays</li>
      <li>GET&nbsp;&nbsp;&nbsp;/api/v1/clients &mdash; list subscriber accounts, wrapped as <code>{"clients":[...]}</code></li>
      <li>POST&nbsp;&nbsp;/api/v1/clients &mdash; create one; body needs at least <code>name</code>, and
        omitting <code>days</code> creates an account that <b>never expires</b></li>
      <li>GET&nbsp;&nbsp;&nbsp;/api/v1/clients/{id} &mdash; one subscriber, unwrapped</li>
      <li>PUT&nbsp;&nbsp;&nbsp;/api/v1/clients/{id} &mdash; <code>days_to_add</code> renews (from now if the plan
        already lapsed); <code>allowed_ip</code> rebinds, and <code>""</code> unbinds; also
        <code>name</code>, <code>uuid</code>, <code>enabled</code>, <code>traffic_limit_gb</code>,
        <code>traffic_reset_cycle</code>, <code>expires_at</code>, <code>custom_policies</code>,
        <code>note</code>. Unknown field names are ignored silently</li>
      <li>DELETE /api/v1/clients/{id} &mdash; delete permanently</li>
      <li>POST&nbsp;&nbsp;/api/v1/clients/{id}/regenerate-uuid &mdash; invalidates the old UUID at once</li>
      <li>POST&nbsp;&nbsp;/api/v1/clients/{id}/reset-traffic &mdash; consumed bytes back to zero</li>
      <li>GET&nbsp;&nbsp;&nbsp;/api/v1/policies &mdash; <code>catalog</code>: every preset with its label and
        whether it blocks; <code>policies</code>: the ones whose state was changed from the default</li>
      <li>POST&nbsp;&nbsp;/api/v1/policies &mdash; toggle one: <code>{"key":"enable_riot","enabled":true}</code>;
        a key that is not in <code>catalog</code> is saved and answered 200 but matches nothing</li>
      <li>POST&nbsp;&nbsp;/api/v1/cache/flush &mdash; empty the DNS cache</li>
      <li>GET&nbsp;&nbsp;&nbsp;/api/v1/api-key &mdash; read the master key and its bind address</li>
      <li>POST&nbsp;&nbsp;/api/v1/api-key &mdash; rotate it; every integration must be reconfigured</li>
      <li>POST&nbsp;&nbsp;/api/server/restart &mdash; reset runtime state (flushes the cache; not a process restart)</li>
    </ul>
    <h2>Selling access</h2>
    <p>Suspending or expiring an account only stops the resolver <i>recognising</i> it. While
      <code>access.allow_all</code> is at its default of <b>true</b> the daemon is an open resolver, so
      the address behind that account is then served as anonymous <code>Public</code> &mdash; which has no
      plan to expire and no quota to exceed. Traffic limits are still enforced on accounts it does
      recognise, but <b>revocation does nothing until <code>access.allow_all</code> is false</b>. Turn it
      off on any server you sell access to.</p>
    <h2>Authenticating</h2>
    <p>Send the master API key from Settings as <code>X-API-Key: &lt;key&gt;</code>, or as
      <code>Authorization: Bearer &lt;key&gt;</code>. Both are accepted everywhere except
      <code>/version</code> and this page, which need no key at all.</p>
    <p>A <b>403</b> instead of a 401 means the key is not the problem: the REST API is bound to
      localhost and the request did not come from the server itself. Turn on Public API in Settings,
      or call it over an SSH tunnel.</p>
    <h2>Getting the viewer back</h2>
    <p>The viewer ships inside this binary (<code>web/swagger/</code>); if it is missing, read
      <b>API.md</b> in the project root &mdash; it documents every endpoint above with request and
      response bodies.</p>
  </div>
  <div id="swagger-ui"></div>
  <script src="%s/swagger/swagger-ui-bundle.js"></script>
  <script>
    // The viewer is vendored same-origin, so a load failure now means a broken embed rather
    // than an unreachable CDN. When that happens SwaggerUIBundle is never defined, and calling it
    // throws inside an inline script: nothing renders and the operator gets a dark rectangle with no
    // explanation, indistinguishable from a broken server. So the static list above ships visible
    // and is hidden only once the real viewer is known to be here to replace it.
    var viewerLoaded = typeof SwaggerUIBundle === 'function';
    if (viewerLoaded) document.getElementById('offline-notice').style.display = 'none';
    if (viewerLoaded) SwaggerUIBundle({
      dom_id: '#swagger-ui',
      spec: {
        openapi: "3.0.0",
        info: {
          title: "HyperDNS Core REST API",
          version: "%s",
          description: "REST API for the HyperDNS SmartDNS Controller: AES-256-GCM encrypted subscribers, gaming presets and real-time DNS telemetry.\n\n**Authentication.** Press Authorize and paste the master API key from Settings. It travels as the X-API-Key header, or as Authorization: Bearer <key> — both are accepted, and a live dashboard session token works in either.\n\n**If Try it out answers 403 rather than 401**, the key is not the problem: the REST API is bound to localhost and this browser is not on the server. Turn on Public API in Settings, or call the API from the machine itself."
        },
        servers: [{ url: "%s", description: "This HyperDNS instance. Since v2.1 the API lives below the install's hidden 16-hex admin path, so the base is that path and not the host root — Try it out resolves against this value." }],
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }],
        components: {
          securitySchemes: {
            ApiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" },
            BearerAuth: { type: "http", scheme: "bearer", description: "The same master key, or a dashboard session token." }
          }
        },
        paths: {
          "/api/v1/version": {
            get: { summary: "Build version and sync hash", description: "No API key required.", security: [], responses: { 200: { description: "OK" }, 405: { description: "GET and HEAD only" } } }
          },
          "/api/v1/docs": {
            get: { summary: "This documentation page", description: "No API key required.", security: [], responses: { 200: { description: "HTML" }, 405: { description: "GET and HEAD only" } } }
          },
          "/api/v1/status": {
            get: { summary: "Live service status and DNS telemetry", responses: { 200: { description: "OK" }, 401: { description: "Missing or invalid API key" }, 405: { description: "GET and HEAD only" } } }
          },
          "/api/v1/clients": {
            get: { summary: "List subscriber accounts", description: "The array is wrapped: this route answers {\"clients\": [...]} while GET /api/v1/clients/{id} answers the bare account object, so the two cannot share one unwrapping step. Every entry carries the live traffic_used_bytes, quota_exceeded and next_traffic_reset, computed per request rather than read from the last flush, so pricing a whole list needs no follow-up calls.", responses: { 200: { description: "OK" }, 401: { description: "Missing or invalid API key" } } },
            post: {
              summary: "Create subscriber account",
              requestBody: { required: true, content: { "application/json": { schema: {
                type: "object", required: ["name"],
                properties: {
                  name: { type: "string", example: "gamer-01" },
                  days: { type: "integer", description: "Subscription length in days. Omitting it, or sending 0, creates an account that NEVER expires — there is no server-side default length, so a billing integration must always send this.", example: 30 },
                  ip: { type: "string", description: "Optional fixed IP for this subscriber. Leave it empty to let them bind their own address by opening /sub/{token}.", example: "" },
                  traffic_limit_gb: { type: "number", description: "0 or omitted means unmetered.", example: 100 },
                  traffic_reset_cycle: { type: "string", enum: ["", "daily", "weekly", "monthly"], description: "Period after which the quota returns on its own. Omitted means it never does, which is the pre-1.5.0 behaviour. The cycle is anchored at the moment of this request, so the first reset is a whole period away.", example: "monthly" },
                  custom_policies: { type: "array", items: { type: "string" }, description: "Preset keys from GET /api/v1/policies (the catalog array), e.g. enable_riot. A non-empty list narrows this account to those presets; an empty list gives it every preset that is globally enabled. Unknown keys are accepted and match nothing.", example: ["enable_riot", "enable_discord"] },
                  note: { type: "string", example: "" }
                }
              } } } },
              responses: { 201: { description: "Created" }, 400: { description: "Invalid request payload, or a traffic_reset_cycle this build does not implement" }, 401: { description: "Missing or invalid API key" } }
            }
          },
          "/api/v1/clients/{id}": {
            parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" }, description: "Subscriber id" }],
            get: { summary: "Get subscriber by id", responses: { 200: { description: "OK" }, 404: { description: "Client not found" } } },
            put: {
              summary: "Update subscriber",
              description: "Every field is optional; only what is sent is changed. Unknown fields are ignored silently, so a misspelled key answers 200 and changes nothing — the field names below are the whole list.",
              requestBody: { required: true, content: { "application/json": { schema: {
                type: "object",
                properties: {
                  name: { type: "string", description: "An empty string is ignored: an account cannot be left nameless." },
                  enabled: { type: "boolean", description: "false suspends the account and keeps its plan and remaining volume. This is the revocation switch — but it only works while access.allow_all is false, since an open resolver serves the address anonymously instead." },
                  uuid: { type: "string", description: "Sets the account's UUID. An empty string is ignored; use POST /clients/{id}/regenerate-uuid for a fresh random one." },
                  allowed_ip: { type: "string", description: "Rebinds the account to one address. An empty string UNBINDS it: the plan and the remaining volume survive, but the account resolves for nobody until the subscriber opens /sub/{token} again. Note the name: this is allowed_ip here, while POST /clients calls the same thing ip." },
                  traffic_limit_gb: { type: "number", description: "0 means unlimited, not zero allowance." },
                  traffic_reset_cycle: { type: "string", enum: ["", "daily", "weekly", "monthly"], description: "Sending a different cycle re-anchors the period at now and restarts the counter; sending the one already stored changes nothing, so an unrelated edit cannot postpone a subscriber's reset. An empty value stops the quota resetting without touching the usage already recorded." },
                  days_to_add: { type: "integer", description: "The renewal field. Extends from the current expires_at, or from now if that date has already passed, so renewing a lapsed customer sells them a full period rather than a retroactive one. Negative values shorten the plan; 0 is ignored. It does not return spent volume — a plan with no traffic_reset_cycle also needs POST /clients/{id}/reset-traffic.", example: 30 },
                  expires_at: { type: "string", format: "date-time", description: "Sets the expiry absolutely, ignoring what was stored. Use days_to_add to renew and this only to correct a date. If both are sent this one lands first and days_to_add counts from it." },
                  custom_policies: { type: "array", items: { type: "string" }, description: "Replaces the account's selection wholesale; send [] to give it every globally enabled preset again." },
                  note: { type: "string" }
                }
              } } } },
              responses: { 200: { description: "Updated; the body is the full account, same shape as GET" }, 400: { description: "Invalid JSON payload, an unusable allowed_ip, or a traffic_reset_cycle this build does not implement" }, 404: { description: "Client not found" } }
            },
            delete: { summary: "Delete subscriber", responses: { 200: { description: "Deleted" }, 404: { description: "Client not found" } } }
          },
          "/api/v1/clients/{id}/regenerate-uuid": {
            parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
            post: { summary: "Regenerate client UUID", description: "The old UUID stops resolving at once; the subscriber needs the new link.", responses: { 200: { description: "New UUID" }, 404: { description: "Client not found" }, 405: { description: "POST only" } } }
          },
          "/api/v1/clients/{id}/reset-traffic": {
            parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
            post: { summary: "Reset consumed traffic to 0 bytes", responses: { 200: { description: "Reset" }, 404: { description: "Client not found" }, 405: { description: "POST only" } } }
          },
          "/api/v1/policies": {
            get: { summary: "List game and policy rules", description: "Two arrays. catalog is every preset this build knows, each with its key, label and whether it blocks rather than routes — that is the list to populate a UI from. policies holds only the presets whose state was changed from the default, so a fresh install answers with an empty array there and that is not an error.", responses: { 200: { description: "OK" } } },
            post: {
              summary: "Enable or disable a game / policy rule",
              description: "The key must be one of the keys in the catalog array of GET /api/v1/policies — they all look like enable_riot. Unknown keys are stored and answered 200 but match no domain, so a typo here is silent. A toggle reaches the resolver at once, but answers already in the cache keep their old routing until their TTL runs out; follow it with POST /api/v1/cache/flush to make the change visible immediately. Disabling a preset here also overrides every per-account custom_policies selection: an account cannot be given a preset that is globally off.",
              requestBody: { required: true, content: { "application/json": { schema: {
                type: "object", required: ["key"],
                properties: { key: { type: "string", example: "enable_riot" }, enabled: { type: "boolean", example: true } }
              } } } },
              responses: { 200: { description: "Saved; the body echoes the stored record" }, 400: { description: "Invalid request payload, or an empty key" } }
            }
          },
          "/api/v1/cache/flush": {
            post: { summary: "Flush the in-memory DNS cache", description: "POST only: a GET would let a link preview or an address-bar prefetch empty the cache.", responses: { 200: { description: "Flushed" }, 405: { description: "POST only" } } }
          },
          "/api/v1/api-key": {
            get: { summary: "Read the master API key and its bind address", description: "api_bind is the operational half of this answer: 127.0.0.1 means the REST API replies only to the server itself and every remote call gets a 403 however valid its key is, while 0.0.0.0 means Public API is on and the key is the only thing in front of an admin surface. The nested data object duplicates both fields for an older dashboard build; read the top-level names in new code.", responses: { 200: { description: "OK" } } },
            post: { summary: "Regenerate the master API key", description: "The previous key stops working the moment this returns, there is no grace period, and it is the only copy — every bot, billing hook and monitoring probe holding it starts getting 401 immediately, including whatever made this call. If the write to disk fails the answer is a 500 and the OLD key stays in force, so a failed rotation never locks the daemon out.", responses: { 200: { description: "New key" }, 500: { description: "Could not save the new API key; the previous key still works" } } }
          },
          "/api/server/restart": {
            post: { summary: "Restart the resolver's runtime state", description: "POST only. Flushes the in-memory DNS cache so the next query for every name is resolved fresh from upstream. This does not tear down and rebuild the UDP/TCP/DoT/DoH listeners — a full process restart is systemd's job (systemctl restart hyperdns) and is deliberately outside the API's reach, because an endpoint that can kill the process that serves it can lock an operator out of the panel. Use this after changing upstreams or policies, when stale answers are the problem.", responses: { 200: { description: "Runtime state reset" }, 405: { description: "POST only" } } }
          }
        }
      }
    });
  </script>
</body>
</html>`, adminServerURL(a.settings.GetAdminPath()), adminServerURL(a.settings.GetAdminPath()), version.Get().Version, adminServerURL(a.settings.GetAdminPath()))
	_, _ = w.Write([]byte(html))
}

// adminServerURL builds the OpenAPI "servers" entry from the install's hidden
// admin path. The spec document is served below the same namespace it
// describes, so an absolute path is what Try it out needs; a relative "/"
// would resolve every request against the host root, where nothing has been
// mounted since v2.1. A record with no path (never migrated) degrades to the
// pre-v2.1 root, which is the honest answer for that build state.
func adminServerURL(adminPath string) string {
	if adminPath == "" {
		return "/"
	}
	return "/" + adminPath
}
