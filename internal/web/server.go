package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperdns/internal/api"
	"hyperdns/internal/auth"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/database"
	"hyperdns/internal/httpx"
	"hyperdns/internal/presetupd"
	"hyperdns/internal/service"
	"hyperdns/internal/service/acme"
	"hyperdns/internal/version"
)

type WebServer struct {
	db             *database.DB
	clients        *service.ClientService
	stats          *service.StatsService
	cache          *cache.Cache
	matcher        *matcher.Matcher
	presetUpdater  *presetupd.Updater
	customGroups   *service.CustomGroupService
	upstreams      *upstream.UpstreamPool
	dohHandler     http.Handler
	settings       *database.ServerSettings
	tlsSettings    *database.TLSSettings
	dnsCfg         *database.DNSSettings
	subSettings    *database.SubscriptionSettings
	authSettings   *database.AuthSettings
	sessions       *service.SessionManager
	staticFS       fs.FS
	httpServer     *http.Server
	redirectServer *http.Server
	// subServer is the dedicated subscriber listener, bound when the
	// Subscription Portal record names a port different from the panel's. It
	// serves the public portal routes only — see subscriberSurface.
	subServer *http.Server
	// subListenMu serializes (re)binding of the subscriber listener. A save can
	// arrive while Start is still binding, and closing-then-listening on the same
	// port without a lock races the socket against itself.
	subListenMu   sync.Mutex
	stopServerCtx context.CancelFunc
	api           *api.API
	loginLimiter  *service.LoginAttemptTracker
	benchmark     *service.BenchmarkRunner
	sseTickets    *sseTicketStore

	// ldapAuth is the directory client used when the auth record points at
	// LDAP. It is an interface so tests can inject a fake without a network.
	ldapAuth auth.LDAPAuthenticator

	// kdfGate bounds how many password verifications run at once. Verification is
	// deliberately expensive and reachable without authentication, so without a
	// bound a burst of login attempts is a CPU-exhaustion lever against the
	// resolver sharing the box — and the resolver's latency is the product.
	kdfGate chan struct{}

	// acmeRunning is the single-flight gate for certificate issuance. Two Saves must
	// not become two ACME orders: Let's Encrypt allows five duplicate certificates
	// per name per week, and both orders would answer the same challenge tokens,
	// so the second would race the first for no gain.
	acmeRunning atomic.Bool

	// acmeManager is the embedded ACME client (nil in test harnesses). Set
	// through SetACMEManager, like the other post-construction seams.
	acmeManager *acme.Manager

	// certHolder is the hot-swappable TLS certificate source behind every
	// listener's GetCertificate; nil in harnesses that never serve TLS.
	// certHolderMu only guards the field itself (Start and SetCertHolder can
	// race during tests); the holder's internal lock does the real work.
	certHolder   *certHolder
	certHolderMu sync.Mutex

	// dotCertHolder is the hot-swap source for the DoT (853) and DoH (8443)
	// listeners' dedicated certificate — the custom DoH/DoT domain's pair.
	// nil when the transports ride the panel certificate. It is created at
	// boot when a valid pair already exists, and mid-process by the first
	// successful dot-purpose issuance otherwise (dotHolderMu guards exactly
	// that construction; the holder's own lock does the hot-swap work).
	dotCertHolder *certHolder
	dotHolderMu   sync.Mutex
	// dnsRebind installs a new dedicated DoT/DoH certificate source and
	// rebuilds the listeners that carry it — the holder when a dedicated
	// domain is newly wired, nil when it is cleared. Renewals of the same
	// name hot-swap through the holder and never call it. The error is the
	// rebuild's: a listener that did not come back up is a failed save.
	dnsRebind func(src *certHolder) error

	// totpReplay makes validated TOTP codes single-use across every gated
	// endpoint (login included) — one observed code must not authorise every
	// gated call in its validity window. Guard methods live in auth2fa.go.
	totpReplay *totpReplayGuard

	// dnsMu guards every mutation of dnsCfg. Adding an upstream is a
	// read-modify-persist over a slice inside a struct two requests can reach at
	// once, so without this two browser tabs saving at the same moment could lose
	// one of the two entries or write a half-updated "dns" record.
	dnsMu sync.Mutex

	// static holds the embedded dashboard, hashed and pre-compressed. Preparing it
	// costs one pass over every asset, so it is built on first use and reused: the
	// files came out of the binary and cannot change while the process runs, and
	// BuildHandler is called again by parts of the test suite.
	static     *staticServer
	staticOnce sync.Once

	// fallbackAdminPath covers a settings record that reached the web server
	// without an admin path — a nil settings pointer in a test harness, or a
	// record that skipped the startup migration. It is drawn once per process
	// from the CSPRNG, so an operator who somehow reaches the panel over such a
	// record still gets a hidden namespace instead of a fixed guessable one.
	// Production never lands here: main.go's ensureAdminPath generates and
	// persists the path before the web server is constructed.
	fallbackAdminPath string
	fallbackPathOnce  sync.Once
}

// staticHandler returns the prepared asset server, building it once.
func (ws *WebServer) staticHandler() *staticServer {
	ws.staticOnce.Do(func() {
		ws.static = newStaticServer(ws.staticFS)
	})
	return ws.static
}

func NewWebServer(
	db *database.DB,
	clients *service.ClientService,
	stats *service.StatsService,
	cache *cache.Cache,
	matcher *matcher.Matcher,
	upstreams *upstream.UpstreamPool,
	dohHandler http.Handler,
	settings *database.ServerSettings,
	tlsSettings *database.TLSSettings,
	dnsCfg *database.DNSSettings,
	sessions *service.SessionManager,
	staticFS fs.FS,
	presetUpdater *presetupd.Updater,
) *WebServer {
	apiInst := api.NewAPI(db, clients, stats, cache, matcher, upstreams, settings, tlsSettings, sessions)

	ws := &WebServer{
		db:            db,
		clients:       clients,
		stats:         stats,
		cache:         cache,
		matcher:       matcher,
		upstreams:     upstreams,
		dohHandler:    dohHandler,
		settings:      settings,
		tlsSettings:   tlsSettings,
		dnsCfg:        dnsCfg,
		sessions:      sessions,
		staticFS:      staticFS,
		presetUpdater: presetUpdater,
		api:           apiInst,
		sseTickets:    newSSETicketStore(),
		ldapAuth:      auth.GoLDAPAuthenticator{},
		kdfGate:       make(chan struct{}, kdfConcurrency()),
		totpReplay:    newTOTPReplayGuard(),
	}
	ws.loginLimiter = service.NewLoginAttemptTracker()
	ws.benchmark = service.NewBenchmarkRunner(func() {
		if ws.upstreams != nil {
			ws.upstreams.BenchmarkAll()
		}
	})
	// The v1 router's credential-changing POSTs face the same second factor
	// the dashboard's equivalents run: with 2FA on, a hijacked session must
	// not be able to rotate the REST key through /api/v1/api-key when
	// /api/settings/regenerate-api-key would demand the code.
	apiInst.SetTOTPGate(ws.totpRequestGate)
	return ws
}

// SetControlState attaches the daemon-owned mutable state shared by the web
// panel and root-local control plane. Main calls this before any listener starts.
func (ws *WebServer) SetControlState(benchmark *service.BenchmarkRunner, lockouts *service.LoginAttemptTracker) {
	if ws == nil {
		return
	}
	if benchmark != nil {
		ws.benchmark = benchmark
	}
	if lockouts != nil {
		ws.loginLimiter = lockouts
	}
}

// SetSubscriptionSettings attaches the subscription record after construction.
// It exists for the test harness, which builds servers without a database
// record; main passes it in through the same call.
func (ws *WebServer) SetSubscriptionSettings(s *database.SubscriptionSettings) {
	ws.subSettings = s
}

// SetCustomGroupService wires the named-custom-policy-group manager. Set by the
// daemon after construction, like the subscription and auth settings, so the
// zero WebServer used in the lighter tests carries no dependency on it.
func (ws *WebServer) SetCustomGroupService(s *service.CustomGroupService) {
	ws.customGroups = s
}

// serverSettingsView is the shape of ServerSettings that leaves the process.
//
// The point of hashing the admin password is that the verifier stays where it is
// verified. Serialising it into every /api/config response put it in browser
// memory, in devtools, and in anything that caches a dashboard response — where
// a stored-XSS payload could lift it and crack it offline at leisure. The
// dashboard never had a use for it: it renders the username, and asks for a new
// password when admin_password_weak is set.
//
// api_key is deliberately still here. Unlike the password verifier it is a
// bearer credential the operator has to be able to read — the API page shows it,
// masked until clicked, and builds the copy-paste curl snippets from it — and
// there is no other route that hands it back.
type serverSettingsView struct {
	PublicIP          string `json:"public_ip"`
	BindHost          string `json:"bind_host"`
	WebPort           int    `json:"web_port"`
	AdminUsername     string `json:"admin_username"`
	AdminPasswordWeak bool   `json:"admin_password_weak"`
	APIKey            string `json:"api_key"`
	APIBind           string `json:"api_bind"`
	// SessionIdleMinutes is the live dashboard idle window (Phase D): the
	// settings card shows what is in force and POSTs a replacement.
	SessionIdleMinutes int `json:"session_idle_minutes"`
	// AdminPath is the hidden namespace the operator is logged into. It is a
	// locator, not a credential, and this is the authenticated operator's own
	// view of their server — the settings page has to display it for the
	// regenerate workflow to be usable at all. It still never reaches a public
	// page: /api/config sits entirely inside the admin namespace.
	AdminPath string `json:"admin_path"`
}

// settingsView snapshots the server settings for a response. The snapshot is
// taken under the settings lock so a concurrent change cannot be observed
// half-applied, and it deliberately carries no password verifier to copy.
func (ws *WebServer) settingsView() serverSettingsView {
	s := ws.settings.Snapshot()
	return serverSettingsView{
		PublicIP:           s.PublicIP,
		BindHost:           s.BindHost,
		WebPort:            s.WebPort,
		AdminUsername:      s.AdminUsername,
		AdminPasswordWeak:  s.AdminPasswordWeak,
		APIKey:             s.APIKey,
		APIBind:            s.APIBind,
		SessionIdleMinutes: s.SessionIdleMinutes,
		AdminPath:          s.AdminPath,
	}
}

// spaLookup normalises a request path the way the dashboard's own router does before it
// is matched against the SPA route table.
//
// handleRouteFromURL in web/js/app.js reads the address bar as
//
//	pathname.toLowerCase().replace(/\/$/, '')
//
// so the front end has always treated /Clients and /clients/ as the clients tab. The
// server matched the raw path exactly, so both returned "404 page not found" — a trailing
// slash is one keystroke, and it is what a link written by hand or a proxy that normalises
// directories tends to produce.
//
// That snippet is an indented block rather than inline backticks because gofmt reformats
// doc comment prose and applies the TeX quoting convention to it, which rewrites a pair of
// straight single quotes into a closing typographic quote. Indented blocks are copied
// through untouched.
//
// Only the SPA table is looked up through here. Asset paths keep their original case and
// slash, because an embedded file name is matched exactly and /js/App.js is not /js/app.js.
func spaLookup(path string) string {
	p := strings.ToLower(path)
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

func (ws *WebServer) BuildHandler() http.Handler {
	inner := ws.buildAdminMux()

	// The public face of the panel. Everything the world may touch is matched
	// here by hand rather than by a mux, for one reason: the admin namespace is
	// not a fixed string. A ServeMux pins its patterns at registration time, so
	// a path generated at first install — and regenerable by an authenticated
	// operator while the daemon runs — cannot be a mux pattern without making
	// regeneration a restart. Routing on a per-request prefix read keeps the
	// boundary exact: the old namespace dies with the request that regenerated
	// the path, and nothing ever has to match "the path the server started with".
	//
	// The order is the security policy. Public routes are matched first and
	// explicitly; the admin prefix is matched after them; everything else —
	// including the /api/..., /home and /js/... routes this server answered at
	// the root for its whole life before v2.1 — falls through to the same plain
	// not-found a random path gets. There is no redirect from an old route to
	// the hidden one: a redirect would publish the path to whoever asked.
	return ws.withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean the path exactly the way ServeMux would before matching it, so a
		// traversal such as /sub/../api/stats cannot smuggle a dot-segment past
		// the prefix checks and produce a redirect that rewrites the request into
		// the admin namespace one hop later. Unclean paths that survive cleaning
		// simply miss every match and are answered 404 like any other stranger.
		p := cleanRequestPath(r.URL.Path)

		// 1. Public root: the Matrix landing page (landing.go). Nothing about the
		//    panel is linked from here.
		if p == "/" {
			ws.serveLandingPage(w, r)
			return
		}

		// 2. Subscriber portal and 1-click registration, public by design. The
		//    token in the path is the credential; these must stay reachable
		//    without knowing anything about the admin namespace.
		if strings.HasPrefix(p, "/sub/") || strings.HasPrefix(p, "/ip/") || strings.HasPrefix(p, "/api/sub/") {
			inner.ServeHTTP(w, r)
			return
		}

		// 3. DNS-over-HTTPS, a service endpoint rather than a web page.
		if p == "/dns-query" && ws.dohHandler != nil {
			ws.dohHandler.ServeHTTP(w, r)
			return
		}

		// 4. The deliberately public asset namespace. The portal pages reference
		//    exactly two stylesheets/scripts by absolute path, and both CSS files
		//    self-host the fonts through /fonts/. These stay at the root so a
		//    subscriber's browser never needs the admin path; every dashboard
		//    asset (/js/app.js, /css/style.css, the vendored libraries) is
		//    reachable only below the admin prefix.
		if p == "/css/portal.css" || p == "/js/portal.js" || strings.HasPrefix(p, "/fonts/") {
			ws.staticHandler().ServeHTTP(w, r)
			return
		}

		// 5. The admin namespace below the generated path. /<p> and /<p>/dash
		//    redirect to the dashboard root for an operator who typed the bare
		//    path; /<p>/login serves the standalone sign-in document (Phase A):
		//    a self-contained page that never loads the dashboard bundle, so
		//    the whole admin front-end is no longer readable pre-auth. The
		//    retired /<p>/dash/login — which used to serve the full SPA shell
		//    with an overlay — redirects here, keeping older bookmarks alive
		//    without publishing anything the new page does not already show.
		//    /<p>/dash/ and below strip only the /dash segment and hit the SPA
		//    route table; every other admin URL strips the whole prefix and
		//    reaches the API and asset handlers. /<p>/api/v1/... lands on the
		//    versioned external API exactly as /api/v1/... used to sit at the
		//    root.
		ap := "/" + ws.adminPath()
		if p == ap || p == ap+"/dash" {
			http.Redirect(w, r, ap+"/dash/", http.StatusFound)
			return
		}
		if p == ap+"/login" {
			if !ws.staticHandler().serveLogin(w, r, ws.adminPath()) {
				http.Error(w, "login page not found", http.StatusNotFound)
			}
			return
		}
		if p == ap+"/dash/login" {
			http.Redirect(w, r, ap+"/login", http.StatusFound)
			return
		}
		if strings.HasPrefix(p, ap+"/dash/") {
			http.StripPrefix(ap+"/dash", inner).ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(p, ap+"/") {
			http.StripPrefix(ap, inner).ServeHTTP(w, r)
			return
		}

		// 6. Everything else. http.NotFound writes the same "404 page not found"
		//    body the inner mux would, so a wrong admin prefix and a random path
		//    are byte-for-byte indistinguishable.
		http.NotFound(w, r)
	}))
}

// cleanRequestPath mirrors net/http's own path cleaning: dot segments resolved,
// a trailing slash preserved, an empty path promoted to "/". Running it before
// the outer routing keeps the traversal behaviour a mux would have provided
// without giving the mux a chance to answer a cleaned path with a redirect that
// escapes the namespace the request originally named.
func cleanRequestPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np
}

// adminPath returns the admin path segment in force right now, reading the
// settings each time so a regeneration takes effect on the next request. The
// fallback only exists for records that never had one generated; see the
// fallbackAdminPath field comment.
func (ws *WebServer) adminPath() string {
	if p := ws.settings.GetAdminPath(); p != "" {
		return p
	}
	ws.fallbackPathOnce.Do(func() {
		ws.fallbackAdminPath = GenerateAdminPath()
	})
	return ws.fallbackAdminPath
}

// AdminPath exposes the effective admin path for tests and the startup banner.
func (ws *WebServer) AdminPath() string {
	return ws.adminPath()
}

// buildAdminHandler is the admin namespace on its own, without the public
// routing layer: every /api/... route, the subscriber portal, DoH and the SPA
// mounted exactly where they lived before v2.1 moved the root. BuildHandler
// wraps this behind the generated admin prefix, and the test suite uses it
// directly so handler-level tests keep speaking the same URLs the handlers
// themselves match on.
func (ws *WebServer) buildAdminHandler() http.Handler {
	return ws.withSecurityHeaders(ws.buildAdminMux())
}

// subscriberSurface is the handler for the dedicated subscriber listener.
//
// The Subscription Portal setting advertises a port in every generated link
// (see subscriptionOrigin), and until this existed nothing ever listened on it:
// an operator who set a portal port handed their subscribers a URL that refused
// the connection. The record is a port the daemon is expected to serve, not a
// label for someone else's reverse proxy.
//
// The allow-list is the whole security model here, and it is deliberately a
// list of what IS served rather than what is not. The panel listener answers
// this same handler set behind the generated admin path; on a public port the
// admin namespace, every /api/... route, DoH and the SPA must be unreachable,
// so a request that does not match one of the four public prefixes gets the
// same bare 404 a stranger gets on the panel. In particular /api/sub/ is listed
// on its own rather than letting the /api/ prefix through, so adding an
// endpoint to the dashboard cannot silently widen this surface.
func (ws *WebServer) subscriberSurface() http.Handler {
	inner := ws.buildAdminMux()
	return ws.withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := cleanRequestPath(r.URL.Path)
		if strings.HasPrefix(p, "/sub/") ||
			strings.HasPrefix(p, "/ip/") ||
			strings.HasPrefix(p, "/api/sub/") ||
			p == "/css/portal.css" ||
			p == "/js/portal.js" ||
			strings.HasPrefix(p, "/fonts/") {
			inner.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
}

// BuildDoHHandler is the handler the DNS-over-HTTPS listener (the DoH port)
// serves. It is deliberately NOT BuildHandler.
//
// The DoH listener answered with the complete dashboard handler — the login
// page, the admin namespace, every /api route — so any network that could
// reach the DoH port could reach the panel's admin surface too, whether or
// not the operator thought of that port as exposed (Mantis v2.1.0 finding #1,
// re-confirmed unchanged by the v2.2.0 pass). The DoH listener serves exactly
// two things: the DoH endpoint itself, and the same public subscriber surface
// the portal links name. Everything else gets the bare 404 a stranger gets.
func (ws *WebServer) BuildDoHHandler() http.Handler {
	inner := ws.buildAdminMux()
	return ws.withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := cleanRequestPath(r.URL.Path)
		if p == "/dns-query" ||
			strings.HasPrefix(p, "/sub/") ||
			strings.HasPrefix(p, "/ip/") ||
			strings.HasPrefix(p, "/api/sub/") ||
			p == "/css/portal.css" ||
			p == "/js/portal.js" ||
			strings.HasPrefix(p, "/fonts/") {
			inner.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
}

// subscriberTLSConfig resolves the certificate the subscriber listener serves.
//
// TLS follows the panel listener, deliberately, because subscriptionOrigin()
// builds every generated link from that same flag: serving the portal over a
// scheme the links do not name would hand the subscriber a URL that fails the
// handshake. So a panel on plain HTTP means a plain-HTTP portal, and a panel on
// subscriberHTTPS reports whether the subscriber surface serves TLS. A
// distinct subscription domain is HTTPS by construction (its ACME pair
// exists before the domain can apply, so the links and the listener agree).
// "Distinct" mirrors the panel comparison, including the no-panel-domain
// case where an IP-named origin is the same origin the panel always used.
// Every other shape follows the panel's scheme.
func (ws *WebServer) subscriberHTTPS() bool {
	if ws.subSettings != nil {
		if d := strings.TrimSpace(ws.subSettings.GetDomain()); d != "" {
			panel := ws.effectivePanelDomain()
			if panel == "" {
				panel = ws.settings.GetPublicIP()
			}
			if panel == "" || !strings.EqualFold(d, panel) {
				return true
			}
		}
	}
	return ws.panelHTTPS()
}

// subscriberTLSConfig loads the certificate the subscriber listener serves.
//
// v2.2.0 precedence: a subscription domain distinct from the panel's is
// served by its ACME pair under certs/acme/<domain>/ — located from the
// live record, not from a form field, so the certificate always matches the
// name the links carry. A missing pair is a hard error rather than a
// fallback to the panel certificate: serving the panel's certificate for a
// foreign name is exactly the "Not Secure" the field report described. Any
// other shape (empty or panel-named domain) rides the panel pair as before.
func (ws *WebServer) subscriberTLSConfig() (*tls.Config, error) {
	if ws.subSettings == nil {
		return nil, nil
	}
	snap := ws.subSettings.Snapshot()
	certPath, keyPath := "", ""

	panel := ws.effectivePanelDomain()
	if panel == "" {
		panel = ws.settings.GetPublicIP()
	}
	if domain := strings.TrimSpace(snap.Domain); domain != "" && (panel == "" || !strings.EqualFold(domain, panel)) {
		certPath = filepath.Join(ws.acmeDir(), domain+".crt")
		keyPath = filepath.Join(ws.acmeDir(), domain+".key")
		if err := ValidatePanelCertificate(certPath, keyPath, domain); err != nil {
			return nil, fmt.Errorf("the subscription domain %s has no valid certificate under %s — use Let's Encrypt beside the domain field (%w)", domain, ws.acmeDir(), err)
		}
	} else {
		if !ws.panelHTTPS() || ws.tlsSettings == nil {
			return nil, nil
		}
		certPath, keyPath = ws.tlsSettings.CertPath, ws.tlsSettings.KeyPath
	}
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("the subscriber listener needs a certificate: either reuse the panel's or issue one for the subscription domain")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("subscriber listener certificate could not be loaded: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// panelCertificatePair resolves the certificate the PANEL listener serves.
//
// Precedence: the stored CertPath/KeyPath when they name a pair valid for the
// configured domain; otherwise the ACME pair for that domain under
// certs/acme/<domain>/; an error naming the fix when neither exists.
//
// The second step is the healing half of the v2.2.0 field report: renaming the
// panel domain saved the new name immediately (SetACME writes Domain/Email
// only) while the certificate swap ran as a best-effort background goroutine —
// so a rename whose issuance failed, or a restart in the window, left
// CertPath pointing at the OLD domain's pair while Domain named the new one,
// and every reader that trusted the stored path served a certificate browsers
// rejected as ERR_CERT_COMMON_NAME_INVALID. Resolving by the live domain —
// the same rule the subscription listener already used — makes the stale
// stored path harmless: the right pair is found where the ACME client puts
// it, with no write and no operator action.
func (ws *WebServer) panelCertificatePair() (string, string, error) {
	// Read the whole record under one lock. The fields are a set: Domain decides
	// which name the pair must cover, and CertPath/KeyPath are the pair. Reading
	// them through separate accessors let a concurrent SetCertPaths land between
	// the two reads, so the validator saw a domain from one moment and a pair
	// from another — and the race detector flagged the bare CertPath read
	// against the locked write. Snapshot is one locked copy of all of them.
	snap := ws.tlsSettings.Snapshot()
	domain := strings.TrimSpace(snap.Domain)
	if domain == "" {
		return "", "", fmt.Errorf("no panel domain is configured")
	}
	if snap.CertPath != "" && snap.KeyPath != "" {
		if err := ValidatePanelCertificate(snap.CertPath, snap.KeyPath, domain); err == nil {
			return snap.CertPath, snap.KeyPath, nil
		}
	}
	certPath := filepath.Join(ws.acmeDir(), domain+".crt")
	keyPath := filepath.Join(ws.acmeDir(), domain+".key")
	if err := ValidatePanelCertificate(certPath, keyPath, domain); err == nil {
		return certPath, keyPath, nil
	}
	return "", "", fmt.Errorf("no valid certificate covers the panel domain %s — issue one with Let's Encrypt in the SSL settings (and check the domain's A record and port 80)", domain)
}

func (ws *WebServer) buildAdminMux() *http.ServeMux {
	mux := http.NewServeMux()

	// 1. Attach REST API v1
	ws.api.RegisterRoutes(mux)

	// 2. DNS-over-HTTPS (DoH) endpoint
	if ws.dohHandler != nil {
		mux.Handle("/dns-query", ws.dohHandler)
	}

	// 3. Real-time Server-Sent Events (SSE) log stream. These two are the only
	// routes that accept ?token=, because EventSource cannot set headers.
	mux.HandleFunc("/events/stream", ws.requireAuthStream(ws.stats.ServeSSE))
	mux.HandleFunc("/api/stream/queries", ws.requireAuthStream(ws.stats.ServeSSE))

	// 4. Shecan/Shelter style 1-Click IP auto-registration & Subscriber Portal (public by design)
	// Phase B: /sub/<token> is the read-only portal page; /ip/<token> is the
	// secret-gated registration API (POST) with a GET page explaining it; the
	// JSON overview keeps its old /api/sub/<token>[.]/sync shape for existing
	// bookmarks but no longer writes.
	// Phase B: /sub/<token> is the read-only portal page; /ip/<token> is the
	// secret-gated registration API (POST) whose GET serves an explainer page
	// for old bookmarks; the JSON overview keeps its /api/sub/<token> shape but
	// no longer writes.
	mux.HandleFunc("/sub/", ws.handleSubscriptionPage)
	mux.HandleFunc("/ip/", ws.handleRegisterIPAPI)
	mux.HandleFunc("/api/sub/", ws.handleSubDataAPI)

	// 5. Authentication & Config Endpoints
	mux.HandleFunc("/api/auth/login", ws.handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", ws.requireAuth(ws.handleAuthLogout))
	// Unlock keeps the master-key path (requireAuthWithMasterKey): it is the
	// lockout RECOVERY route — the operator who fat-fingers the dashboard five
	// times reaches it through the root-local TUI, whose control client has no
	// dashboard session. Everything else on this mux refuses the REST key
	// (v2.2.0 scoping); a recovery route that refused its only caller would
	// make the lockout permanent short of an SSH restart.
	mux.HandleFunc("/api/auth/unlock", ws.requireAuthWithMasterKey(ws.handleAuthUnlock))
	mux.HandleFunc("/api/auth/me", ws.requireAuth(ws.handleAuthMe))
	mux.HandleFunc("/api/config", ws.requireAuth(ws.handleConfig))
	mux.HandleFunc("/api/config/rules", ws.requireAuth(ws.handleConfigRules))
	mux.HandleFunc("/api/config/access", ws.requireAuth(ws.handleConfigAccess))
	mux.HandleFunc("/api/config/server", ws.requireAuth(ws.handleConfigServer))

	// 6. Internal Dashboard Ajax APIs (all authenticated)
	mux.HandleFunc("/api/diagnostics/run", ws.requireAuth(ws.handleDiagnosticsRun))
	mux.HandleFunc("/api/stats", ws.requireAuth(ws.handleStats))
	mux.HandleFunc("/api/clients", ws.requireAuth(ws.handleClients))
	mux.HandleFunc("/api/clients/add", ws.requireAuth(ws.handleClientsAdd))
	mux.HandleFunc("/api/clients/delete", ws.requireAuth(ws.handleClientsDelete))
	mux.HandleFunc("/api/clients/add_ip", ws.requireAuth(ws.handleClientsAddIP))
	mux.HandleFunc("/api/clients/remove_ip", ws.requireAuth(ws.handleClientsRemoveIP))
	mux.HandleFunc("/api/clients/renew", ws.requireAuth(ws.handleClientsRenew))
	mux.HandleFunc("/api/clients/toggle", ws.requireAuth(ws.handleClientsToggle))
	mux.HandleFunc("/api/access/mode", ws.requireAuth(ws.handleAccessMode))
	mux.HandleFunc("/api/clients/", ws.requireAuth(ws.handleClientAction))
	mux.HandleFunc("/api/policies", ws.requireAuth(ws.handlePolicies))
	mux.HandleFunc("/api/custom-groups", ws.requireAuth(ws.handleCustomGroups))
	mux.HandleFunc("/api/custom-groups/", ws.requireAuth(ws.handleCustomGroupByID))
	mux.HandleFunc("/api/cache/flush", ws.requireAuth(ws.handleFlushCache))
	mux.HandleFunc("/api/presets/update", ws.requireAuth(ws.handlePresetUpdateStatus))
	mux.HandleFunc("/api/presets/update/check", ws.requireAuth(ws.handlePresetUpdateCheck))
	mux.HandleFunc("/api/presets/update/apply", ws.requireAuth(ws.handlePresetUpdateApply))
	mux.HandleFunc("/api/presets/update/rollback", ws.requireAuth(ws.handlePresetUpdateRollback))
	mux.HandleFunc("/api/settings", ws.requireAuth(ws.handleSettings))
	mux.HandleFunc("/api/settings/regenerate-api-key", ws.requireAuth(ws.handleRegenerateAPIKey))
	mux.HandleFunc("/api/settings/regenerate-admin-path", ws.requireAuth(ws.handleRegenerateAdminPath))
	mux.HandleFunc("/api/settings/subscription", ws.requireAuth(ws.handleSubscriptionSettings))
	mux.HandleFunc("/api/auth/2fa/status", ws.requireAuth(ws.handleAuth2FAStatus))
	mux.HandleFunc("/api/auth/2fa/setup", ws.requireAuth(ws.handleAuth2FASetup))
	mux.HandleFunc("/api/auth/2fa/enable", ws.requireAuth(ws.handleAuth2FAEnable))
	mux.HandleFunc("/api/auth/2fa/disable", ws.requireAuth(ws.handleAuth2FADisable))
	mux.HandleFunc("/api/auth/ldap", ws.requireAuth(ws.handleLDAPSettings))
	mux.HandleFunc("/api/auth/sse-ticket", ws.requireAuth(ws.handleSSETicket))
	mux.HandleFunc("/api/benchmark", ws.requireAuth(ws.handleBenchmark))
	mux.HandleFunc("/api/upstreams/add", ws.requireAuth(ws.handleUpstreamsAdd))
	mux.HandleFunc("/api/upstreams/delete", ws.requireAuth(ws.handleUpstreamsDelete))
	mux.HandleFunc("/api/tls/issue", ws.requireAuth(ws.handleTLSSettings))
	mux.HandleFunc("/api/tls/acme/status", ws.requireAuth(ws.handleACMEStatus))

	// 7. Embedded Offline SPA Static Assets & Clean Routes
	//
	// staticServer replaces http.FileServer here. FileServer cannot produce a
	// validator for an embedded file — embed.FS reports a zero modification time,
	// ServeContent omits Last-Modified for it, and no ETag is generated — so every
	// reload of the panel re-downloaded every asset in full and uncompressed. The
	// replacement hashes and gzips each file once at startup.
	//
	// Since v2.1 Phase 3 this mux lives below the generated admin prefix: the SPA
	// is mounted at /<admin-path>/dash/... and everything else at
	// /<admin-path>/..., so the paths matched here are the prefix-stripped forms
	// (see BuildHandler). "/" inside this mux is the dashboard document itself,
	// not the public root — the landing page lives outside, on the bare "/".
	assets := ws.staticHandler()
	spaHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean SPA direct routes. These are the paths the dashboard's own router
		// owns; a browser that lands on one directly, or reloads on one, must get
		// index.html rather than a 404, and the JS then renders the right tab.
		//
		// This set has to be exactly the key set of routeTabs in web/js/app.js, and
		// three keys used to be missing from it: /policy, /stream and /connect, the
		// aliases the front-end router accepts alongside /rules, /logs and /guide.
		// Typing or bookmarking one of those three returned "404 page not found",
		// even though the JS would have rendered the right tab had it ever been
		// handed index.html. Nothing pushes them — switchTab pushes the tabRoutes
		// value — so the only way to reach one is by hand, which is exactly the case
		// nobody clicks through while testing. dashboardRoutesMatchSPARoutes in
		// dashboard_ids_test.go now fails if the two lists drift again.
		//
		// "/" is in the table on purpose here: after the admin prefix and the /dash
		// segment are stripped, "/" is /<admin-path>/dash/, the dashboard document
		// an operator who follows the login link actually asked for.
		spaRoutes := map[string]bool{
			"/":          true,
			"/dashboard": true,
			"/panel":     true,
			"/home":      true,
			"/clients":   true,
			"/rules":     true,
			"/policy":    true,
			"/logs":      true,
			"/stream":    true,
			"/api":       true,
			"/settings":  true,
			"/guide":     true,
			"/connect":   true,
			// /login is the address the plan names for the hidden sign-in page and
			// the one the regeneration flow sends the operator to. There is no
			// separate login document: unauthenticated, the dashboard shell shows
			// the sign-in overlay on any tab, so /login renders that shell.
			"/login": true,
		}

		if spaRoutes[spaLookup(r.URL.Path)] {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// The shell is served only to an authenticated navigation. /login is
			// the one exception — it is the page an unauthenticated operator is
			// meant to reach — and it renders the standalone sign-in document, not
			// the dashboard bundle. Every other SPA route redirects to /login when
			// the document-gate cookie is missing or dead, so the dashboard shell
			// never reaches an unauthenticated browser and there is no pre-auth
			// flash of panel content.
			if spaLookup(r.URL.Path) != "/login" && !ws.documentSessionValid(r) {
				http.Redirect(w, r, "/"+ws.adminPath()+"/login", http.StatusFound)
				return
			}
			if !assets.serveIndex(w, r, ws.adminPath()) {
				http.Error(w, "index.html not found", http.StatusNotFound)
			}
			return
		}

		// Static assets
		assets.ServeHTTP(w, r)
	})

	mux.Handle("/", spaHandler)
	return mux
}

// maxRequestBody bounds every request body this server accepts. 1 MiB is the figure
// the REST API and the login handler already used by hand, and it is far more than
// any dashboard payload needs: the largest of them is the rules blob, and 1 MiB holds
// some tens of thousands of domains.
const maxRequestBody = 1 << 20

// withSecurityHeaders is the outer middleware every response passes through,
// public and admin alike. It used to wrap the single root mux; since v2.1 it
// wraps both layers (the public router and the admin namespace) so a response
// cannot lose the headers by being routed differently.
func (ws *WebServer) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// HSTS only on a request that actually arrived over TLS. It must never be
		// sent on the plain HTTP listener: a browser that records the policy from
		// an http:// response upgrades every future visit to https://, so a host
		// still served over HTTP for a reason would be locked out. Preload and
		// includeSubDomains are deliberately absent — both change behaviour for
		// every subdomain and are an explicit deployment decision, not a default.
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		// Default every dynamic response to uncacheable and unindexable, and let the
		// two kinds of response that want otherwise say so themselves.
		//
		// Without a Cache-Control header a cache is free to store a 200 on its own
		// heuristics, and what this server returns is a client list, a settings blob,
		// or a subscriber's IP, UUID, token and quota. The portal is the sharp case:
		// it is plain http on a VPS address, opened from mobile networks where a
		// transparent proxy in the path is routine, so a stored copy is one
		// subscriber's account page handed to whoever requests that URL next.
		//
		// X-Robots-Tag is the same argument for crawlers. A subscription URL *is* the
		// credential, so indexing one publishes it; the portal page also carries a
		// <meta name="robots">, but the JSON endpoint cannot, and a crawler that only
		// reads headers never sees the meta tag anyway.
		//
		// staticServer.write overwrites Cache-Control with "no-cache" for embedded
		// assets, which is what keeps /css/portal.css and /js/portal.js revalidating
		// into 304s instead of being re-sent on every visit. Handler-set values win
		// because this middleware runs first.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")

		// Every request body on every route is bounded here rather than in each
		// handler. Fifteen decoders in this package read r.Body with no limit at all,
		// and an unbounded decode is one request away from an allocation the size of
		// whatever the sender feels like sending: json.Decode on a 4 GB string field
		// allocates 4 GB, and the process that dies for it is the resolver. Being
		// authenticated is not a defence — the caller holding a session token is
		// exactly the caller those handlers are reachable by.
		//
		// One wrap in the middleware rather than fifteen written by hand, because a
		// per-handler cap is a thing to forget in the sixteenth handler. A handler
		// that wants a tighter bound still sets its own — handleSettings uses 64 KiB —
		// and wrapping an already-wrapped body simply leaves the tighter limit in
		// force. An oversized body then fails that handler's own decode and comes back
		// as its 400, which is why no route needs to learn about this.
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		next.ServeHTTP(w, r)
	})
}

// contentSecurityPolicy is the policy sent on every route this handler serves — the
// dashboard, the subscriber portal, and the JSON API alike.
//
// 'unsafe-eval' is gone (v2.1): the Tailwind Play CDN JIT engine that needed it was
// replaced by the committed purged stylesheet /css/tailwind.purged.css, and
// TestUnsafeEvalIsTiedToTheJITEngine keeps the two tied — reintroducing the engine
// without reintroducing the relaxation fails the suite, and vice versa.
//
// 'unsafe-inline' in script-src now covers exactly one block: the pre-paint
// theme/language restore at the top of index.html, which must run before the first
// paint and cannot afford a second round trip as an external file. Everything else
// that used to need it is gone — the tailwind.config block died with the JIT engine,
// index.html's event handlers became delegated listeners in app.js, and the
// subscriber portal's inline <script>, inline <style> and fifteen onclick
// attributes became /js/portal.js and /css/portal.css. style-src 'unsafe-inline'
// remains for the operator's custom portal stylesheet, which is rendered as a
// <style> element by design.
//
// What the policy already buys is the part that matters against a stored-XSS payload
// in a domain name or a client note: every source is 'self', so an injected
// <script src> or a fetch to an attacker's host is refused, and default-src blocks
// plugins and workers. 'unsafe-inline' does not weaken that.
//
// It also applies to the portal, which is worth stating because the portal is the one
// page served to a stranger: a subscription URL is public by construction, so /sub/,
// /ip/ and /api/sub/ are the routes an attacker can reach without credentials.
//
// connect-src includes ws:/wss: because the log stream may be upgraded from SSE.
// frame-ancestors duplicates X-Frame-Options for browsers that dropped the latter.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; " +
	"font-src 'self' data:; " +
	"connect-src 'self' ws: wss:; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

func (ws *WebServer) Start() error {
	// Panel exposure policy (v2.1.0 remediation, installer contract): the
	// dashboard is an ADMIN surface and must not be reachable as a bare
	// IP:port over plain HTTP.
	//   - A configured domain → the panel serves HTTPS (forced here, so a
	//     config that only names the domain cannot accidentally come up as
	//     http://panel) and binds the configured address.
	//   - No domain → the panel FAILS CLOSED to loopback only: the operator
	//     can still reach it via an SSH tunnel on the same box, but the
	//     internet cannot open an unencrypted login page on the VPS IP.
	domain := ""
	if ws.tlsSettings != nil {
		domain = strings.TrimSpace(ws.tlsSettings.GetDomain())
	}
	if domain != "" {
		ws.tlsSettings.PanelHTTPS = true
	}
	https := ws.tlsSettings != nil && ws.tlsSettings.PanelHTTPS

	bindHost := ws.settings.BindHost
	if domain != "" && (bindHost == "" || bindHost == "0.0.0.0") {
		// Dual-stack on the wildcard: "::" accepts IPv4 and IPv6, so a host
		// with AAAA records is reachable on both families (a v6-only visitor
		// to a 0.0.0.0-bound panel gets connection refused). Loopback-only
		// mode below keeps the explicit v4 loopback address.
		bindHost = "::"
	}
	addr := net.JoinHostPort(bindHost, strconv.Itoa(ws.settings.WebPort))
	if domain == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", ws.settings.WebPort)
		log.Printf("[Web] SECURITY: no panel domain configured — the dashboard is bound to %s (loopback only). "+
			"Reach it via an SSH tunnel (ssh -L %d:127.0.0.1:%d user@server) or set the panel domain to expose HTTPS.",
			addr, ws.settings.WebPort, ws.settings.WebPort)
	}

	// serverCtx is cancelled by Stop() (v2.1.0 B-22 remediation). http.Server.
	// Shutdown does not cancel active request contexts, and the SSE loop's only
	// other exit was client disconnect — so a daemon stop with a panel open
	// burned the whole drain timeout and abandoned the stream. Cancelling the
	// base context reaches every handler's r.Context(), and the SSE loop
	// returns on it immediately.
	serverCtx, stopServerCtx := context.WithCancel(context.Background())
	ws.stopServerCtx = stopServerCtx
	ws.httpServer = &http.Server{
		Addr:              addr,
		Handler:           ws.BuildHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		// WriteTimeout must stay 0: the SSE event stream (/api/stream/queries)
		// holds connections open indefinitely and would be killed by a
		// short write deadline every few seconds.
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
		BaseContext:  func(net.Listener) context.Context { return serverCtx },
	}

	scheme := "http"
	if https {
		// Fail closed. When HTTPS is required, a certificate that cannot load,
		// does not match its key, is not currently usable, or does not cover the
		// configured domain must stop the daemon rather than serve a panel that
		// no modern browser will accept. The error propagates to main, which in
		// service mode logs it as a fatal startup failure.
		// Fail closed. When HTTPS is required, a certificate that cannot load,
		// does not match its key, is not currently usable, does not cover the
		// configured domain, or is self-signed must stop the daemon rather
		// than serve a panel that no modern browser will accept. The error
		// propagates to main, which in service mode logs it as a fatal startup
		// failure.
		if err := ValidatePanelCertificate(ws.tlsSettings.CertPath, ws.tlsSettings.KeyPath, ws.tlsSettings.GetDomain()); err != nil {
			// The stored pair no longer covers the domain (a rename whose
			// issuance never landed). The resolver checks the ACME pair for
			// the live domain before failing: a rename back to a previously
			// issued name — or the window after a fresh issue — boots straight
			// to the right certificate instead of failing closed here.
			resolvedCert, resolvedKey, resErr := ws.panelCertificatePair()
			if resErr != nil {
				return fmt.Errorf("panel HTTPS certificate is not usable: %w — verify the domain's A record points here and port 80 is reachable, then use Dashboard → Settings → Issue SSL (the built-in ACME client); a self-signed fallback is never served for a configured domain", err)
			}
			ws.tlsSettings.CertPath, ws.tlsSettings.KeyPath = resolvedCert, resolvedKey
		}
		cert, err := tls.LoadX509KeyPair(ws.tlsSettings.CertPath, ws.tlsSettings.KeyPath)
		if err != nil {
			return fmt.Errorf("panel HTTPS certificate could not be loaded: %w", err)
		}
		// v2.2.0: handshakes go through the hot-swappable holder instead of a
		// static pair, so the embedded ACME renewal promotes a new certificate
		// without restarting the daemon. The pair loaded here is only the
		// initial one the holder was primed with — same file, same validator.
		ws.certHolderMu.Lock()
		if ws.certHolder == nil {
			ws.certHolder = newCertHolder(&cert)
		}
		holder := ws.certHolder
		ws.certHolderMu.Unlock()
		ws.httpServer.TLSConfig = &tls.Config{
			GetCertificate: holder.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}
		scheme = "https"
	}

	// Bind the panel listener synchronously. Binding inside the serving goroutine
	// would turn a port conflict into a log line from a goroutine that is already
	// dead, and it would leave the caller holding a Start that "succeeded" with no
	// listener. Binding here means a conflict is a Start error, and it means the
	// port is actually accepting connections by the time Start returns.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("panel listener: %w", err)
	}

	// The redirect listener is strictly additional: it answers plain HTTP with a
	// one-hop redirect to the HTTPS panel. Zero leaves it unbound. Its listener is
	// likewise bound here, so a conflict on the redirect port is a Start error and
	// does not leave the panel up with no way to reach it over plain HTTP.
	var redirLn net.Listener
	if https && ws.tlsSettings.RedirectPort > 0 {
		redirAddr := fmt.Sprintf("%s:%d", ws.settings.BindHost, ws.tlsSettings.RedirectPort)
		if ws.settings.BindHost == "" {
			redirAddr = fmt.Sprintf("0.0.0.0:%d", ws.tlsSettings.RedirectPort)
		}
		redirLn, err = net.Listen("tcp", redirAddr)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("redirect listener: %w", err)
		}
		ws.redirectServer = &http.Server{
			Addr:              redirAddr,
			Handler:           http.HandlerFunc(ws.handleHTTPSRedirect),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// The URL must be the live one (v2.1.0 B-21 remediation): printing the
	// retired /dashboard route sent a freshly started operator to a 404 their
	// own daemon produced.
	log.Printf("[Web] %s Dashboard running at %s://%s/%s/dash/", strings.ToUpper(scheme), scheme, addr, ws.adminPath())
	if https {
		go func() {
			if err := ws.httpServer.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] Server error: %v", err)
			}
		}()
	} else {
		go func() {
			if err := ws.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] Server error: %v", err)
			}
		}()
	}

	if ws.redirectServer != nil {
		go func() {
			if err := ws.redirectServer.Serve(redirLn); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] HTTP redirect listener error: %v", err)
			}
		}()
	}

	// The dedicated subscriber listener. Before this existed the Subscription
	// Portal's port field only changed the text of the links it generated, so an
	// operator who set a portal port published a URL nothing answered on. The
	// panel listener already serves these routes below its admin prefix, so the
	// second listener is bound only when the record asks for a port the panel is
	// not already on — same port means the panel is the subscriber surface, and
	// rebinding it here would fail the start for no gain.
	//
	// A bind failure is fatal rather than logged. The operator has just told the
	// daemon to serve subscribers on that port, and links naming it are already
	// being handed out; coming up without it would quietly re-create the dead
	// link this listener exists to fix.
	if err := ws.bindSubscriberListener(serverCtx, true); err != nil {
		_ = ln.Close()
		if redirLn != nil {
			_ = redirLn.Close()
		}
		return err
	}

	return nil
}

// failSubscriberBind is the failure path shared by every bind attempt: at
// startup the error stops the daemon (the operator asked for this listener and
// silent absence is the bug), and on a live save the record is already
// persisted so the conflict is reported to the operator instead.
func failSubscriberBind(fatal bool, err error) error {
	if fatal {
		return err
	}
	log.Printf("[Web] Subscriber portal listener could not be started: %v", err)
	return err
}

// bindSubscriberListener (re)binds the dedicated subscriber listener so it
// matches the current subscription record. It is called once from Start and
// again after every save of the Subscription Portal settings, which is what
// makes the port field take effect without a restart.
func (ws *WebServer) bindSubscriberListener(ctx context.Context, fatal bool) error {
	ws.subListenMu.Lock()
	defer ws.subListenMu.Unlock()

	if ws.subSettings == nil || !ws.subSettings.IsEnabled() {
		// Disabled: the dedicated listener is not wanted, so the old one is
		// retired here rather than after the early return below.
		if ws.subServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = ws.subServer.Shutdown(shutdownCtx)
			cancel()
			ws.subServer = nil
		}
		return nil
	}
	subPort := ws.subSettings.GetPort()
	if subPort <= 0 || subPort == ws.settings.WebPort {
		// Zero means "the panel's own port", which the panel already serves.
		return nil
	}

	subAddr := fmt.Sprintf("%s:%d", ws.settings.BindHost, subPort)
	if ws.settings.BindHost == "" {
		subAddr = fmt.Sprintf("0.0.0.0:%d", subPort)
	}

	// Acquire the replacement BEFORE retiring the current one. The old order —
	// shutdown, then bind — left a window with no subscriber listener at all:
	// a bind that failed (a port another process already holds, or a TLS pair
	// that does not validate) returned having already closed the socket every
	// existing subscriber link points at, and nothing restored it. The settings
	// were already persisted, so the operator's links kept pointing at a dark
	// port until the daemon was restarted. Binding first means a failed
	// replacement leaves the working listener exactly where it was.
	subLn, err := net.Listen("tcp", subAddr)
	if err != nil {
		return failSubscriberBind(fatal, fmt.Errorf("subscriber listener on port %d: %w", subPort, err))
	}
	subTLS, tlsErr := ws.subscriberTLSConfig()
	if tlsErr != nil {
		_ = subLn.Close()
		return failSubscriberBind(fatal, fmt.Errorf("subscriber listener on port %d: %w", subPort, tlsErr))
	}

	if ws.subServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = ws.subServer.Shutdown(shutdownCtx)
		cancel()
		ws.subServer = nil
	}

	ws.subServer = &http.Server{
		Addr:              subAddr,
		Handler:           ws.subscriberSurface(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	subScheme := "http"
	if subTLS != nil {
		ws.subServer.TLSConfig = subTLS
		subScheme = "https"
	}
	log.Printf("[Web] Subscriber portal listening on %s://%s/ (public routes only)", strings.ToUpper(subScheme), subAddr)
	if subTLS != nil {
		go func() {
			if err := ws.subServer.ServeTLS(subLn, "", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] Subscriber listener error: %v", err)
			}
		}()
	} else {
		go func() {
			if err := ws.subServer.Serve(subLn); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] Subscriber listener error: %v", err)
			}
		}()
	}
	return nil
}

// panelHTTPS reports whether the panel listener is serving TLS, which is the
// single flag both the generated subscription links and the subscriber listener
// take their scheme from. A configured domain forces it on, exactly as Start
// does, so a record that only names a domain cannot come up as plain HTTP.
func (ws *WebServer) panelHTTPS() bool {
	if ws.tlsSettings == nil {
		return false
	}
	if strings.TrimSpace(ws.tlsSettings.GetDomain()) != "" {
		return true
	}
	return ws.tlsSettings.PanelHTTPS
}

func (ws *WebServer) Stop() {
	// Cancel the server base context FIRST (v2.1.0 B-22 remediation): SSE
	// handlers watch r.Context() and return the moment it is cancelled, so
	// Shutdown's drain no longer waits on streams that would otherwise only
	// end at client disconnect.
	if ws.stopServerCtx != nil {
		ws.stopServerCtx()
	}
	if ws.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = ws.httpServer.Shutdown(ctx)
	}
	if ws.redirectServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = ws.redirectServer.Shutdown(ctx)
	}
	if ws.subServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = ws.subServer.Shutdown(ctx)
	}
}

// handleHTTPSRedirect answers the plain-HTTP listener. It only redirects safe
// (GET/HEAD) requests, preserving the path and query; a non-safe method is
// answered 405 because redirecting a POST with 301/302 collapses it into a GET
// and silently loses the body and semantics.
//
// The destination host is never taken raw from the client. The configured panel
// domain is preferred; falling back to SafeRedirectHost means a Host header
// carrying a scheme, userinfo, path or query cannot steer the redirect to an
// attacker-controlled origin.
func (ws *WebServer) handleHTTPSRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := ""
	if ws.tlsSettings != nil {
		host = ws.tlsSettings.GetDomain()
	}
	if host == "" {
		host = SafeRedirectHost(r.Host)
	}
	if host == "" {
		http.Error(w, "unknown host", http.StatusBadRequest)
		return
	}
	port := ""
	if ws.settings.WebPort != 0 && ws.settings.WebPort != 443 {
		port = fmt.Sprintf(":%d", ws.settings.WebPort)
	}
	target := r.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	// An IPv6 host must be re-bracketed for the Location URL (v2.1.0 B-15
	// remediation): SafeRedirectHost deliberately strips the brackets, and
	// reassembly without them produced https://2001:db8::1:8443/ — an
	// unparseable URL the browser refuses. net.JoinHostPort brackets only
	// when the host is an IP literal, which is exactly the rule.
	location := fmt.Sprintf("https://%s%s%s", redirectHost(host), port, target)
	http.Redirect(w, r, location, http.StatusTemporaryRedirect)
}

// redirectHost re-brackets a bare IPv6 literal for URL assembly (v2.1.0 B-15
// remediation). SafeRedirectHost deliberately strips brackets so a Host header
// can be compared and validated as an address; a Location header needs them
// back, or https://2001:db8::1:8443/ is an unparseable URL the browser
// refuses. Hostnames pass through untouched.
func redirectHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

// loadRulesConfig builds the effective rules state: defaults first, then any
// persisted overrides from the policies bucket.
func (ws *WebServer) loadRulesConfig() map[string]any {
	rules := map[string]any{}
	for key := range matcher.PresetRuleKeys {
		// Sensible defaults: sinkholing categories off, the bulk-download veto off,
		// everything else on. The matcher owns which categories those are, so this asks
		// it rather than naming them here and drifting from NewMatcher's own defaults.
		rules[key] = matcher.DefaultRuleEnabled(key)
	}
	rules["custom_proxied"] = []string{}
	rules["custom_blocked"] = []string{}
	rules["custom_direct"] = []string{}
	rules["custom_records"] = map[string]string{}

	policies, err := ws.db.ListPolicies()
	if err != nil {
		return rules
	}
	for _, p := range policies {
		switch p.Key {
		case "custom_proxied", "custom_blocked", "custom_direct":
			if p.CustomDomains != nil {
				rules[p.Key] = p.CustomDomains
			}
		case "custom_records":
			recs := map[string]string{}
			for _, entry := range p.CustomDomains {
				if k, v, ok := strings.Cut(entry, "="); ok {
					recs[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
			rules["custom_records"] = recs
		default:
			if _, ok := matcher.PresetRuleKeys[p.Key]; ok {
				rules[p.Key] = p.Enabled
			}
		}
	}
	return rules
}

func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Read-only: it assembles the settings, TLS, version, access and rules views and
	// hands them back. There was no guard here at all, so it answered POST, PUT and
	// DELETE with 200 and the whole blob — an endpoint agreeing to verbs it has no
	// code for, and the one response that is meant to say "use GET" was never sent.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"server":  ws.settingsView(),
		"tls":     ws.tlsSettings.Snapshot(),
		"version": version.Get(),
		"access":  ws.loadAccessConfig(),
		"rules":   ws.loadRulesConfig(),
		// The subscription record is display-only data (no secrets), so it can
		// ride the same response the settings page already renders from.
		"subscription": ws.subSettings.Snapshot(),
		// The origin the daemon will actually hand subscribers — scheme, host and
		// port as the listener serves them. The dashboard builds its Reg Link and
		// Bot Card URLs from this rather than reconstructing it, because the
		// scheme is not always the panel's: a record with its own certificate
		// pair is HTTPS even when the panel itself is plain HTTP.
		"subscription_origin": ws.subscriptionOrigin(),
		// The DoH endpoint as the daemon serves it — its own port, https, and
		// the configured domain in preference to the public IP. The Connect
		// Guide used to rebuild this from the web port and got all three wrong.
		"doh_url": ws.dohURL(),
		// Auth state for the settings panel's 2FA prompts: the snapshot type
		// structurally cannot carry the TOTP secret or the LDAP bind password.
		"auth": ws.authSettings.Snapshot(),
	})
}

// accessConfig holds optional DoH bearer tokens managed from the dashboard.
type accessConfig struct {
	DoHTokens []string `json:"doh_tokens"`
}

func (ws *WebServer) loadAccessConfig() accessConfig {
	acc := accessConfig{DoHTokens: []string{}}
	_ = ws.db.GetSetting("access", &acc)
	if acc.DoHTokens == nil {
		acc.DoHTokens = []string{}
	}
	return acc
}

func (ws *WebServer) handleConfigAccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(ws.loadAccessConfig())
	case http.MethodPost:
		var acc accessConfig
		if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		if acc.DoHTokens == nil {
			acc.DoHTokens = []string{}
		}
		_ = ws.db.SetSetting("access", acc)
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	default:
		httpx.WriteMethodNotAllowed(w, "GET, POST")
	}
}

// toStringSlice normalises a domain list from either shape it arrives in: []any
// when it was decoded from a request body, []string when it came back from
// loadRulesConfig.
//
// Accepting only the first shape is what made the "start from the persisted
// state" fallback in handleConfigRules a no-op. A Go type assertion is exact, so
// val.([]any) fails on every []string, and the three lists were reset to nil
// before the request was even inspected — meaning a payload carrying just one
// preset toggle saved three empty lists over the operator's custom domains.
func toStringSlice(val any) []string {
	add := func(out []string, s string) []string {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			return append(out, s)
		}
		return out
	}
	switch raw := val.(type) {
	case []string:
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			out = add(out, v)
		}
		return out
	case []any:
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			out = add(out, fmt.Sprint(v))
		}
		return out
	default:
		return nil
	}
}

// handleConfigRules persists dashboard rule toggles & custom domain lists to
// the database and applies them to the live matcher immediately.
func (ws *WebServer) handleConfigRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var customProxied, customBlocked, customDirect []string
	customRecords := map[string]string{}

	// Start from the persisted state so a partial update (e.g. only a preset
	// toggle in the payload) never wipes the saved custom domain lists.
	persisted := ws.loadRulesConfig()
	customProxied = toStringSlice(persisted["custom_proxied"])
	customBlocked = toStringSlice(persisted["custom_blocked"])
	customDirect = toStringSlice(persisted["custom_direct"])
	if m, ok := persisted["custom_records"].(map[string]string); ok {
		customRecords = m
	}

	for key, val := range req {
		if presetName, ok := matcher.PresetRuleKeys[key]; ok {
			enabled, isBool := val.(bool)
			if !isBool {
				continue
			}
			_ = ws.db.SavePolicy(database.Policy{Key: key, Name: presetName, Category: "preset", Enabled: enabled})
			if ws.matcher != nil {
				ws.matcher.SetRuleEnabled(presetName, enabled)
			}
			continue
		}
		switch key {
		case "custom_proxied":
			customProxied = toStringSlice(val)
		case "custom_blocked":
			customBlocked = toStringSlice(val)
		case "custom_direct":
			customDirect = toStringSlice(val)
		case "custom_records":
			// Replace rather than merge. Merging into the persisted map meant a
			// record could be added but never removed: the UI sends the full
			// desired set, so a domain the operator deleted was simply absent
			// from the payload and survived every save. The three list keys above
			// already replace, so this also makes the four behave alike.
			if m, ok := val.(map[string]any); ok {
				customRecords = make(map[string]string, len(m))
				for d, ip := range m {
					// Normalized the same way the matcher keys its index, so the
					// persisted state and the live rule set agree on "pin.example."
					d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
					ipStr := strings.TrimSpace(fmt.Sprint(ip))
					if d != "" && ipStr != "" {
						customRecords[d] = ipStr
					}
				}
			}
		}
	}

	// Persist custom lists (encoded inside Policy.CustomDomains)
	_ = ws.db.SavePolicy(database.Policy{Key: "custom_proxied", Name: "Custom Proxied Domains", Category: "custom", Enabled: true, CustomDomains: customProxied})
	_ = ws.db.SavePolicy(database.Policy{Key: "custom_blocked", Name: "Custom Blocked Domains", Category: "custom", Enabled: true, CustomDomains: customBlocked})
	_ = ws.db.SavePolicy(database.Policy{Key: "custom_direct", Name: "Custom Direct Domains", Category: "custom", Enabled: true, CustomDomains: customDirect})
	recordEntries := make([]string, 0, len(customRecords))
	for d, ip := range customRecords {
		recordEntries = append(recordEntries, d+"="+ip)
	}
	_ = ws.db.SavePolicy(database.Policy{Key: "custom_records", Name: "Custom A Records", Category: "custom", Enabled: true, CustomDomains: recordEntries})

	// Apply custom lists to the live matcher and flush stale cache entries
	if ws.matcher != nil {
		ws.matcher.SetCustomRules(customProxied, customBlocked, customDirect, customRecords)
	}
	if ws.cache != nil {
		ws.cache.Flush()
	}

	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	// The dashboard polls this with GET every two seconds and nothing in it writes,
	// so GET and HEAD are the whole set. It had no guard either.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	st := ws.stats.GetLiveStats()

	// GetUpstreamStats on a nil pool panics, and the panic would land on the
	// dashboard's 2-second poll — one misconfigured start would then look like the
	// whole panel being down.
	var upstreamStats any = []struct{}{}
	if ws.upstreams != nil {
		upstreamStats = ws.upstreams.GetUpstreamStats()
	}

	resp := map[string]any{
		// Legacy & generic fields
		"qps":                st.QPS,
		"total_queries":      st.TotalQueries,
		"cache_entries":      st.CacheItems,
		"cache_hits":         st.CacheHits,
		"cache_misses":       st.CacheMisses,
		"cache_hit_ratio":    st.CacheHitRate,
		"cache_hit_rate":     st.CacheHitRate,
		"active_proxy_conns": st.ActiveRelays,
		"total_proxy_conns":  st.TotalRelays,
		"active_relays":      st.ActiveRelays,
		"total_relays":       st.TotalRelays,
		"bytes_sent":         st.BytesSent,
		"bytes_recv":         st.BytesRecv,
		"ram_usage_mb":       st.RAMUsageMB,
		"cpu_usage":          st.CPUUsage,
		// Extended runtime telemetry (dashboard cards)
		"alloc_memory_mb":         st.AllocMemoryMB,
		"sys_memory_mb":           st.SysMemoryMB,
		"cpu_usage_percent":       st.CPUUsagePercent,
		"num_cpu":                 st.NumCPU,
		"num_goroutines":          st.NumGoroutines,
		"speed_in_kbps":           st.SpeedInKBps,
		"speed_out_kbps":          st.SpeedOutKBps,
		"total_bytes_transferred": st.BytesSent + st.BytesRecv,

		"uptime_sec":     st.UptimeSec,
		"rate_limited":   st.RateLimited,
		"rate_limit_qps": st.RateLimitQPS,

		// Machine-wide load (internal/sysmetrics): the whole server's CPU and
		// RAM, as opposed to the daemon-process figures above. Negative values
		// mean the platform cannot answer — the UI renders a dash.
		"system_cpu_percent":  st.SystemCPUPercent,
		"system_mem_used_mb":  st.SystemMemUsedMB,
		"system_mem_total_mb": st.SystemMemTotalMB,
		"system_mem_percent":  st.SystemMemPercent,

		// Cache background-refresh health. See LiveStatsResponse for why an operator
		// needs stale_served and refresh_failed side by side.
		"stale_served":    st.StaleServed,
		"refresh_started": st.RefreshStarted,
		"refresh_failed":  st.RefreshFailed,
		"refresh_dropped": st.RefreshDropped,

		// SNI proxy connections that never became relays. relays_unreadable is the
		// diagnostic one: it means a name is answered with this server's address and
		// the client then speaks something the relay cannot read a destination out of.
		"relays_refused":    st.RelaysRefused,
		"relays_unreadable": st.RelaysUnreadable,

		// Query service time. latency covers everything the resolver answered;
		// latency_uncached drops the cache hits, which is the only one of the two
		// that moves when an upstream gets slow.
		"latency":          st.Latency,
		"latency_uncached": st.LatencyUncached,

		"upstreams": upstreamStats,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (ws *WebServer) handleClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		// Views rather than stored records: the panel used to recompute "is this
		// account over its quota" and "when does the allowance come back" in
		// JavaScript, so the dashboard carried its own copy of the enforcement rule
		// and of the clamped-month arithmetic. A copy that drifts tells an operator a
		// subscriber has traffic left while the resolver is already refusing them.
		list, err := ws.clients.ListClientViews()
		if err != nil {
			httpx.WriteJSONErrorFor(w, http.StatusInternalServerError, err)
			return
		}

		pubIP := ws.settings.GetPublicIP()
		if pubIP == "" || pubIP == "127.0.0.1" || pubIP == "0.0.0.0" {
			reqHost := r.Host
			if h, _, err := net.SplitHostPort(r.Host); err == nil {
				reqHost = h
			}
			if reqHost != "" && reqHost != "127.0.0.1" && reqHost != "localhost" && reqHost != "0.0.0.0" {
				pubIP = reqHost
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"clients":   list,
			"allow_all": ws.clients.IsAllowAll(),
			"public_ip": pubIP,
		})

	case http.MethodPost:
		var req struct {
			Name        string `json:"name"`
			Days        int    `json:"days"`
			ExpiresDays int    `json:"expires_days"`
			IP          string `json:"ip"`
			InitialIP   string `json:"initial_ip"`

			// The absolute expiry the panel's picker answers. A pointer, so an omitted
			// field means "not chosen" rather than the zero time; RFC 3339, which is
			// what Date.toISOString() on the other end emits.
			ExpiresAt *time.Time `json:"expires_at"`

			// The rest of the plan, settable in the same request so a reseller does not
			// have to create the account and then reopen it in the edit modal to sell it a
			// quota. An unsupported cycle is refused before anything is written.
			TrafficLimitGB    float64  `json:"traffic_limit_gb"`
			TrafficResetCycle string   `json:"traffic_reset_cycle"`
			CustomPolicies    []string `json:"custom_policies"`
			Note              string   `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}
		days := req.Days
		if days == 0 && req.ExpiresDays != 0 {
			days = req.ExpiresDays
		}
		ip := req.IP
		if ip == "" {
			ip = req.InitialIP
		}
		// '0001-01-01T00:00:00Z' is what the panel sends for "no expiry chosen"; on
		// the wire it is a valid timestamp, so it arrives as a non-nil pointer to
		// the zero time and is treated as unset here rather than honoured as a
		// plan that expired two millennia ago.
		var expiresAt time.Time
		if req.ExpiresAt != nil && !req.ExpiresAt.IsZero() {
			expiresAt = *req.ExpiresAt
		}
		client, err := ws.clients.ProvisionClient(service.CreateClientRequest{
			Name: req.Name,
			Days: days,
			IP:   ip,

			ExpiresAt: expiresAt,

			TrafficLimitGB:    req.TrafficLimitGB,
			TrafficResetCycle: req.TrafficResetCycle,
			CustomPolicies:    req.CustomPolicies,

			Note: req.Note,
		})
		if err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(ws.clients.ViewClient(client))

	default:
		httpx.WriteMethodNotAllowed(w, "GET, POST")
	}
}

// handleClientsAdd is the path the dashboard posts a new subscriber to. It still
// delegates the work to handleClients, but only for a POST: the delegate also
// serves GET, so a GET to a route named "add" used to answer with the entire
// client list. Nothing was leaked — the caller is already authenticated and
// /api/clients returns the same list — but a route whose name promises a write and
// whose GET returns a collection is one an integrator has to read the source to
// understand, and it is one more verb the auth gate has to be right about.
func (ws *WebServer) handleClientsAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	ws.handleClients(w, r)
}

func (ws *WebServer) handleClientsDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		httpx.WriteMethodNotAllowed(w, "POST, DELETE")
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Client ID required")
		return
	}
	if err := ws.clients.DeleteClient(req.ID); err != nil {
		httpx.WriteClientError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"deleted": true})
}

func (ws *WebServer) handleClientsAddIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		ID string `json:"id"`
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.IP == "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Client ID and IP required")
		return
	}
	if err := ws.clients.SetClientIP(req.ID, req.IP); err != nil {
		httpx.WriteClientError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleClientsRemoveIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		ID string `json:"id"`
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Client ID required")
		return
	}
	if err := ws.clients.RemoveClientIP(req.ID, req.IP); err != nil {
		httpx.WriteClientError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleClientsRenew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		ID         string `json:"id"`
		ExtendDays int    `json:"extend_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Client ID required")
		return
	}
	// v2.1.0 B-19 remediation: extend_days <= 0 used to silently become a
	// 30-day renewal with a 200 — the opposite of the v1 contract, where
	// days_to_add <= 0 is ignored. A caller that sends zero (meaning "no
	// extension") got a full month of free subscription confirmed as success.
	if req.ExtendDays <= 0 {
		httpx.WriteJSONError(w, http.StatusBadRequest, "extend_days must be a positive number of days")
		return
	}
	days := req.ExtendDays
	if err := ws.clients.RenewClient(req.ID, days); err != nil {
		httpx.WriteClientError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleClientsToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Client ID required")
		return
	}
	if _, err := ws.clients.ToggleClient(req.ID, req.Enabled); err != nil {
		httpx.WriteClientError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleAccessMode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		AllowAll bool `json:"allow_all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	ws.clients.SetAllowAll(req.AllowAll)
	_ = json.NewEncoder(w).Encode(map[string]bool{"allow_all": req.AllowAll})
}

func (ws *WebServer) handleClientAction(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/clients/")
	id = strings.TrimSpace(strings.TrimSuffix(id, "/"))

	w.Header().Set("Content-Type", "application/json")

	// Both sub-actions mutate state, so they are POST-only: reached by GET they
	// would fire from anything that can make the browser issue a request.
	if clientID, ok := strings.CutSuffix(id, "/regenerate-uuid"); ok {
		if r.Method != http.MethodPost {
			httpx.WriteMethodNotAllowed(w, "POST")
			return
		}
		newUUID, err := ws.clients.RegenerateUUID(clientID)
		if err != nil {
			// Not a blanket 404: this reached the database, and a bbolt write
			// failure answering "no such client" sends the operator hunting for a
			// client that is sitting right there in the list.
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"uuid": newUUID})
		return
	}

	// Phase B: the out-of-band registration secret dies with this call, so the
	// operator is expected to re-deliver the new value. The old one stops
	// binding addresses the moment this returns.
	if clientID, ok := strings.CutSuffix(id, "/regenerate-register-secret"); ok {
		if r.Method != http.MethodPost {
			httpx.WriteMethodNotAllowed(w, "POST")
			return
		}
		newSecret, err := ws.clients.RegenerateRegisterSecret(clientID)
		if err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"register_secret": newSecret})
		return
	}

	if clientID, ok := strings.CutSuffix(id, "/reset-traffic"); ok {
		if r.Method != http.MethodPost {
			httpx.WriteMethodNotAllowed(w, "POST")
			return
		}
		if err := ws.clients.ResetClientTraffic(clientID); err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	switch r.Method {
	case http.MethodGet:
		client, err := ws.clients.GetClient(id)
		if err != nil {
			httpx.WriteJSONError(w, http.StatusNotFound, "Client not found")
			return
		}
		// A view, so the edit modal reads the same usage figure the resolver enforces
		// against — GetClient returns what is on disk, which lags by up to a flush
		// interval.
		_ = json.NewEncoder(w).Encode(ws.clients.ViewClient(client))

	case http.MethodPut:
		var req service.UpdateClientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}
		updated, err := ws.clients.UpdateClient(id, req)
		if err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		// Decorated for the same reason, and because changing the cycle moves the next
		// reset: the panel should not have to guess the new boundary from the cycle
		// name it just sent.
		_ = json.NewEncoder(w).Encode(ws.clients.ViewClient(updated))

	case http.MethodDelete:
		if err := ws.clients.DeleteClient(id); err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"deleted": true})

	default:
		httpx.WriteMethodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (ws *WebServer) handlePolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		policies, err := ws.db.ListPolicies()
		if err != nil {
			httpx.WriteJSONErrorFor(w, http.StatusInternalServerError, err)
			return
		}
		// The catalogue is served alongside the stored overrides because the dashboard's
		// per-client policy picker was filled from a 26-entry map transcribed into
		// app.js. Nothing could check that copy against this one, and it had drifted:
		// four labels were shorter, and a preset added on the Go side stayed
		// unselectable until someone remembered to retype it there too.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policies": policies,
			"catalog":  matcher.PolicyCatalog(),
		})

	case http.MethodPost:
		var p database.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Key == "" {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}
		if err := ws.db.SavePolicy(p); err != nil {
			httpx.WriteJSONErrorFor(w, http.StatusInternalServerError, err)
			return
		}
		if ws.matcher != nil {
			ws.matcher.SetRuleEnabled(p.Key, p.Enabled)
		}
		_ = json.NewEncoder(w).Encode(p)

	default:
		httpx.WriteMethodNotAllowed(w, "GET, POST")
	}
}

// handleFlushCache empties the DNS cache. POST only: it destroys every cached
// answer, which is a side effect no safe verb may have.
//
// It had no guard, so a GET flushed the cache — and a GET is what a browser
// prefetch, a link-preview fetcher, an operator pasting the URL into the address
// bar, or a stray retry sends. The v1 REST equivalent, POST /api/v1/cache/flush,
// has always been POST-only, so the two surfaces disagreed about the same action.
func (ws *WebServer) handleFlushCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	if ws.cache != nil {
		ws.cache.Flush()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"flushed": true})
}

// handleSettings reads and updates the two server settings the dashboard is
// allowed to change directly. Credentials are deliberately not reachable here:
// they go through /api/config/server, which re-authenticates first.
func (ws *WebServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		view := ws.settingsView()
		if ws.sessions != nil {
			view.SessionIdleMinutes = int(ws.sessions.IdleTimeout() / time.Minute)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server": view,
			"tls":    ws.tlsSettings.Snapshot(),
		})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var req struct {
			PublicIP           string `json:"public_ip"`
			APIBind            string `json:"api_bind"`
			SessionIdleMinutes *int   `json:"session_idle_minutes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Swallowing this used to make a malformed body look like a successful
			// no-op, which is how the API-bind toggle managed to report success
			// while changing nothing.
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// Phase D: the idle window applies live on the manager and persists with
		// the server record, clamped to the accessor's rules. The clamp is computed
		// before any validation can still reject the request, and applied only
		// after it: a save that 400s on public_ip or 500s on the persist used to
		// leave the live timeout already moved, which is a change the operator was
		// told failed.
		var idleMinutes int
		if req.SessionIdleMinutes != nil {
			idleMinutes = *req.SessionIdleMinutes
			if idleMinutes < 5 {
				idleMinutes = 5
			}
			if idleMinutes > 1440 {
				idleMinutes = 1440
			}
		}

		publicIP := strings.TrimSpace(req.PublicIP)
		if publicIP != "" && net.ParseIP(publicIP) == nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, "public_ip must be an IP address")
			return
		}

		apiBind := strings.TrimSpace(req.APIBind)
		// Only these two are meaningful, and the value is load-bearing: the REST
		// API's middleware refuses non-loopback peers whenever the bind is not
		// 0.0.0.0, so an unvalidated string here (a typo, or "0.0.0.0 ") would
		// leave the gate in a state that reads as "restricted" while the operator
		// was told the API is public — or the reverse.
		if apiBind != "" && apiBind != "127.0.0.1" && apiBind != "0.0.0.0" {
			httpx.WriteJSONError(w, http.StatusBadRequest, "api_bind must be 127.0.0.1 or 0.0.0.0")
			return
		}

		// prevBind is read before the update so the log line below can report an
		// actual transition rather than "set to X" on every save.
		_, prevBind := ws.settings.Endpoint()
		if err := ws.settings.UpdateAndPersist(
			func(m *database.MutableSettings) {
				// An empty field means "leave this one alone", so a bind-only save
				// must not blank out the advertised IP.
				if publicIP != "" {
					m.PublicIP = publicIP
				}
				if apiBind != "" {
					m.APIBind = apiBind
				}
				// The clamped value, not the raw request: the accessor clamps for
				// a reason, and storing the raw number would hand the next boot an
				// idle window the live manager never actually ran.
				if req.SessionIdleMinutes != nil {
					m.SessionIdleMinutes = idleMinutes
				}
			},
			func(s *database.ServerSettings) error { return ws.db.SetSetting("server", s) },
		); err != nil {
			log.Printf("[Web] Could not persist the server settings: %v", err)
			httpx.WriteJSONError(w, http.StatusInternalServerError, "Could not save settings")
			return
		}
		if req.SessionIdleMinutes != nil && ws.sessions != nil {
			ws.sessions.SetIdleTimeout(time.Duration(idleMinutes) * time.Minute)
			log.Printf("[Web] Dashboard session idle timeout set to %d minute(s)", idleMinutes)
		}
		if apiBind != "" && apiBind != prevBind {
			log.Printf("[Web] REST API access gate set to %s", apiBind)
		}
		_ = json.NewEncoder(w).Encode(ws.settingsView())
	default:
		httpx.WriteMethodNotAllowed(w, "GET, POST")
	}
}

// mutableDNSLocked returns the DNS settings for in-place mutation, materialising
// them from the database when this server was constructed without them.
//
// The nil guard used to substitute a blank struct, which the caller then
// persisted: adding a single upstream would overwrite the live "dns" record's
// ports, cache sizes and serve-stale window with zeros. Reading what is on disk
// first keeps an upstream edit to the upstream list.
// ws.dnsMu must be held.
func (ws *WebServer) mutableDNSLocked() *database.DNSSettings {
	if ws.dnsCfg == nil {
		cfg := &database.DNSSettings{}
		_ = ws.db.GetSetting("dns", cfg)
		ws.dnsCfg = cfg
	}
	return ws.dnsCfg
}

// addUpstream appends addr to the persisted upstream list and returns the new
// list. A failed write is rolled back so the running pool never runs ahead of
// what is on disk, and the lock is released before the caller answers the client.
func (ws *WebServer) addUpstream(addr string) (list []string, errMsg string, status int) {
	ws.dnsMu.Lock()
	defer ws.dnsMu.Unlock()

	cfg := ws.mutableDNSLocked()
	if slices.Contains(cfg.Upstreams, addr) {
		return nil, "Upstream already exists", http.StatusConflict
	}
	cfg.Upstreams = append(cfg.Upstreams, addr)
	if err := ws.db.SetSetting("dns", cfg); err != nil {
		cfg.Upstreams = cfg.Upstreams[:len(cfg.Upstreams)-1]
		return nil, "Could not persist the upstream list", http.StatusInternalServerError
	}
	return slices.Clone(cfg.Upstreams), "", 0
}

// removeUpstream drops addr from the persisted upstream list. The last resolver
// cannot be removed — an empty list fails every query that is not already cached.
func (ws *WebServer) removeUpstream(addr string) (list []string, errMsg string, status int) {
	ws.dnsMu.Lock()
	defer ws.dnsMu.Unlock()

	cfg := ws.mutableDNSLocked()
	remaining := make([]string, 0, len(cfg.Upstreams))
	removed := false
	for _, u := range cfg.Upstreams {
		if u == addr {
			removed = true
			continue
		}
		remaining = append(remaining, u)
	}
	if !removed {
		return nil, "Upstream not found", http.StatusNotFound
	}
	if len(remaining) == 0 {
		return nil, "Cannot remove the last upstream resolver", http.StatusBadRequest
	}
	previous := cfg.Upstreams
	cfg.Upstreams = remaining
	if err := ws.db.SetSetting("dns", cfg); err != nil {
		cfg.Upstreams = previous
		return nil, "Could not persist the upstream list", http.StatusInternalServerError
	}
	return slices.Clone(remaining), "", 0
}

// handleUpstreamsAdd registers a new upstream DNS resolver at runtime
// (persists to the DNS settings bucket and hot-reloads the racing pool).
//
// POST only. It had no guard, so a GET with a body — or any other verb — added a
// resolver to the pool every query is then raced against. The dashboard has always
// sent POST; nothing needed to change on the client side for this.
func (ws *WebServer) handleUpstreamsAdd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		Address string `json:"address"`
		IP      string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	addr := strings.TrimSpace(req.Address)
	if addr == "" {
		addr = strings.TrimSpace(req.IP)
	}
	if addr == "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Upstream address required (host:port)")
		return
	}
	// Normalize bare IPs to host:port. net.JoinHostPort is what brackets an
	// IPv6 literal (v2.1.0 B-06 remediation): string concatenation turned
	// 2001:db8::1 into 2001:db8::1:53, which parses as a DIFFERENT host, got
	// persisted, and pointed the resolver at a machine that was never chosen.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if net.ParseIP(addr) != nil {
			addr = net.JoinHostPort(addr, "53")
		} else {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid upstream address, expected host:port")
			return
		}
	}
	list, errMsg, status := ws.addUpstream(addr)
	if status != 0 {
		httpx.WriteJSONError(w, status, errMsg)
		return
	}
	ws.upstreams.SetUpstreams(list)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "upstreams": list})
}

// handleUpstreamsDelete removes an upstream DNS resolver at runtime.
//
// POST only, like its counterpart above and for the same reason: removing the pool's
// last working resolver is not something a safe verb may do. The address arrives in
// the body, which is also why DELETE is not advertised — the dashboard sends POST,
// and a DELETE carrying a body is legal but nothing here asks for one.
func (ws *WebServer) handleUpstreamsDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	var req struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Address == "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Upstream address required")
		return
	}
	list, errMsg, status := ws.removeUpstream(strings.TrimSpace(req.Address))
	if status != 0 {
		httpx.WriteJSONError(w, status, errMsg)
		return
	}
	ws.upstreams.SetUpstreams(list)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "upstreams": list})
}

// handleBenchmark kicks off a latency probe of every configured upstream and
// returns immediately. The probe used to run inline and answer {"started":true}
// once it had in fact already finished, which held the request open for as long
// as the slowest unreachable resolver took to time out — and told the dashboard
// a lie that the dashboard then acted on by polling for results that were
// already stale.
//
// The daemon-owned benchmark runner collapses concurrent runs: the operator
// leaning on the button and root-local control receive one shared probe.
func (ws *WebServer) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	if ws.upstreams == nil {
		httpx.WriteJSONError(w, http.StatusServiceUnavailable, "No upstream pool configured")
		return
	}
	if ws.benchmark == nil || !ws.benchmark.Start() {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"started": false,
			"running": true,
			"message": "A benchmark is already in progress",
		})
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"started": true,
		"running": true,
		"message": "Benchmark started; upstream latencies refresh as probes land",
	})
}

type diagTarget struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

type diagResult struct {
	Name      string  `json:"name"`
	Target    string  `json:"target"`
	Success   bool    `json:"success"`
	LatencyMs float64 `json:"latency_ms"`
}

// handleDiagnosticsRun measures the server's own reachability to eight game and
// voice endpoints. POST only, though it changes nothing here: one call opens eight
// TLS connections to hosts outside this machine, and a verb the specification
// calls safe is one a browser may prefetch, repeat on a back-button, or fire from
// an <img src>. It accepted GET as well until now; the session gate made that
// harmless — the token travels in a header, which an <img> cannot set — but that
// left the gate as the only thing standing between a page the operator is looking
// at and eight outbound dials. The dashboard has always sent POST, and so does the
// documented contract, so nothing depended on the other verb.
func (ws *WebServer) handleDiagnosticsRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}

	targets := []diagTarget{
		{Name: "Riot Games (Valorant / LoL)", Target: "auth.riotgames.com:443"},
		{Name: "Epic Games (Fortnite / Store)", Target: "launcher-public-service-prod06.ol.epicgames.com:443"},
		{Name: "Steam Community (CS2 / Dota 2)", Target: "steamcommunity.com:443"},
		{Name: "Discord Voice & RTC", Target: "gateway.discord.gg:443"},
		{Name: "EA / Origin Network", Target: "api.ea.com:443"},
		{Name: "Battle.net Blizzard", Target: "eu.actual.battle.net:443"},
		{Name: "PUBG Mobile & PC", Target: "prod-live-front.playbattlegrounds.com:443"},
		{Name: "Spotify CDN & Stream", Target: "apresolve.spotify.com:443"},
	}

	var wg sync.WaitGroup
	results := make([]diagResult, len(targets))

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, tgt diagTarget) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", tgt.Target, 2500*time.Millisecond)
			dur := float64(time.Since(start).Microseconds()) / 1000.0
			if err != nil {
				results[idx] = diagResult{
					Name:      tgt.Name,
					Target:    tgt.Target,
					Success:   false,
					LatencyMs: 0,
				}
			} else {
				_ = conn.Close()
				results[idx] = diagResult{
					Name:      tgt.Name,
					Target:    tgt.Target,
					Success:   true,
					LatencyMs: dur,
				}
			}
		}(i, t)
	}

	wg.Wait()

	successCount := 0
	totalLatency := 0.0
	for _, r := range results {
		if r.Success {
			successCount++
			totalLatency += r.LatencyMs
		}
	}

	// Guard the empty target list, which is the only division by zero here. The
	// previous guard fired on score == 0 instead, so a run where every single
	// target was unreachable — the one state an operator most needs to see —
	// was rewritten to 100 and reported as EXCELLENT.
	score := 100
	avgLatency := 0.0
	if len(targets) > 0 {
		// math.Round, not a plain int() conversion, which truncates towards zero:
		// 7 of 8 targets reachable is 87.5%, and truncation reported that as 87
		// while the panel's own "reachable 7/8" line read 88. Rounding makes the
		// score agree with the ratio it is derived from.
		score = int(math.Round((float64(successCount) / float64(len(targets))) * 100))
	}
	if successCount > 0 {
		avgLatency = totalLatency / float64(successCount)
	}

	quality := "EXCELLENT (A+)"
	if score < 70 {
		quality = "MODERATE (B)"
	}
	if score < 50 {
		quality = "POOR (C)"
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"overall_score":   score,
		"overall_quality": quality,
		"avg_latency_ms":  math.Round(avgLatency*100) / 100,
		"reachable":       successCount,
		"total":           len(targets),
		"results":         results,
		"timestamp":       time.Now(),
	})
}
