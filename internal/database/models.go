package database

import (
	"sync"
	"time"
)

// Client represents a subscriber account with UUID, strict 1-IP binding, traffic limit and expiration.
type Client struct {
	ID               string    `json:"id"`
	UUID             string    `json:"uuid"`
	Name             string    `json:"name"`
	Token            string    `json:"token"`
	AllowedIPs       []string  `json:"allowed_ips"`
	TrafficLimitGB   float64   `json:"traffic_limit_gb"` // 0 = Unlimited
	TrafficUsedBytes uint64    `json:"traffic_used_bytes"`
	ExpiresAt        time.Time `json:"expires_at"`
	CreatedAt        time.Time `json:"created_at"`
	LastSeen         time.Time `json:"last_seen"`
	TotalQueries     uint64    `json:"total_queries"`
	Enabled          bool      `json:"enabled"`
	Note             string    `json:"note"`
	CustomPolicies   []string  `json:"custom_policies"` // empty = inherit global policies

	// RegisterSecret is the second credential the subscriber's IP-registration
	// API (/ip/<token>) demands on top of the token in the path (v2.1.0 Phase B,
	// Mantis C-03). The token travels inside a link that gets pasted into group
	// chats and unfurled by crawlers; the secret travels out-of-band — shown to
	// the operator at creation and regenerable from the panel — so a leaked link
	// alone can read the portal but can never move the account's allowed
	// address. Encrypted at rest beside the token.
	//
	// A record written before this field existed decodes with "", and the
	// client service backfills one at startup (ClientService.ensureRegisterSecrets).
	RegisterSecret string `json:"register_secret"`

	// TrafficResetCycle turns the quota into a recurring allowance instead of a
	// one-off one: "" never resets, and "daily", "weekly" and "monthly" return the
	// usage counter to zero at each boundary. Every account written before this
	// field existed decodes with the empty string, which is exactly the behaviour
	// it already had, so no stored record has to be rewritten.
	TrafficResetCycle string `json:"traffic_reset_cycle"`

	// TrafficResetAnchor is the fixed origin the cycle is measured from, and it is
	// never moved. Boundaries are computed as anchor-plus-N-periods rather than by
	// advancing a mutable "last reset" timestamp, because a monthly cycle anchored
	// on the 31st has to fall back to the 28th in February and then return to the
	// 31st in March. Moving the anchor to each clamped date would make that
	// fallback permanent: a subscription sold on the 31st would renew three days
	// earlier every year, and the subscriber would lose those days for good.
	TrafficResetAnchor time.Time `json:"traffic_reset_anchor"`

	// TrafficResetCount is how many boundaries have been crossed. It is the cycle
	// index the anchor arithmetic needs, and it doubles as the figure that lets the
	// panel say a quota is recurring rather than spent.
	TrafficResetCount uint64 `json:"traffic_reset_count"`

	// TrafficPrevCycleBytes is what the cycle that just ended consumed, kept so a
	// subscriber can be shown last month beside this month without the daemon
	// storing a usage history per account.
	TrafficPrevCycleBytes uint64 `json:"traffic_prev_cycle_bytes"`
}

// Policy represents a rule toggle or custom domain list
type Policy struct {
	Key           string   `json:"key"`      // e.g. "enable_riot", "enable_steam"
	Name          string   `json:"name"`     // e.g. "Riot Games & Valorant"
	Category      string   `json:"category"` // "gaming", "streaming", "dev", "custom"
	Enabled       bool     `json:"enabled"`
	CustomDomains []string `json:"custom_domains"` // for custom rules
}

// QueryLogItem represents a real-time DNS telemetry record
type QueryLogItem struct {
	ID          uint64    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ClientIP    string    `json:"client_ip"`
	AccountName string    `json:"account_name"`
	Protocol    string    `json:"protocol"` // "UDP", "TCP", "DoT", "DoH"
	Domain      string    `json:"domain"`
	RuleMatched string    `json:"rule_matched"` // e.g. "Riot Games", "Direct", "Block"
	Action      string    `json:"action"`       // "PROXY", "DIRECT", "BLOCK"
	LatencyMs   float64   `json:"latency_ms"`
	Cached      bool      `json:"cached"`
}

// ServerSettings holds core daemon & network binding settings.
//
// One instance is shared by pointer between main, the DNS handler, the web panel,
// the REST API and the TUI, and six of its fields are rewritten while the daemon
// is serving requests. Those six are guarded by mu and must be reached through the
// accessors in settings_access.go — see the comment there for why a plain field
// read is not safe. BindHost and WebPort are fixed at startup and may be read
// directly.
type ServerSettings struct {
	// mu guards the six fields mutated at runtime: PublicIP, APIBind, APIKey,
	// AdminUsername, AdminPassword and AdminPasswordWeak. It is unexported, so
	// encoding/json skips it and it never reaches the database record.
	mu sync.RWMutex

	PublicIP      string `json:"public_ip"`
	BindHost      string `json:"bind_host"`
	WebPort       int    `json:"web_port"`
	AdminUsername string `json:"admin_username"`

	// AdminPassword holds a PBKDF2-HMAC-SHA256 verifier in the encoded form
	// produced by crypto.HashPassword, never the plaintext. Records written by
	// releases before v1.5.0 hold plaintext; main.go converts them in place on
	// the next start, so both forms must be assumed on read.
	AdminPassword string `json:"admin_password"`

	// AdminPasswordWeak records that the password in force was accepted before
	// the current strength policy existed (or came from a config file that
	// bypasses it). Once hashed, the password itself can no longer be inspected,
	// so this flag is what tells the dashboard to keep asking for a replacement.
	AdminPasswordWeak bool `json:"admin_password_weak"`

	APIKey  string `json:"api_key"`
	APIBind string `json:"api_bind"` // "127.0.0.1" (default) or "0.0.0.0"

	// AdminPath is a randomly generated hexadecimal string that obscures the admin
	// interface to reduce casual discovery. Exactly 16 lowercase hex characters.
	// Generated once on first run and persisted; regenerable via Settings.
	// Empty string indicates not yet generated (first-boot state).
	AdminPath string `json:"admin_path"`

	// SessionIdleMinutes is the dashboard session idle timeout in minutes
	// (Phase D). The default 15 matches the panel's flowchart contract; the
	// accessor clamps the stored value into [5, 1440] so a hand-edited config
	// cannot disable the timeout entirely. Zero means "not configured" and
	// keeps the default — a settings record from before this field existed
	// decodes with it, which is exactly the pre-existing behaviour.
	SessionIdleMinutes int `json:"session_idle_minutes"`

	// TrustedProxyCIDRs is the operator-declared list of proxy addresses (single
	// IPs or CIDR blocks) that may set X-Forwarded-For/X-Real-IP on behalf of a
	// client. Empty means headers are NEVER trusted and every client is its
	// immediate peer — the fail-closed default (v2.1.0 remediation A-01: private
	// ranges alone are not trustworthy, since a compromised private hop could
	// otherwise rewrite the address the lockout, rate limiter, DoH access and
	// portal binding all key on).
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs"`
}

// DNSSettings holds DNS server parameters.
//
// CacheSize and ServeStaleSeconds are startup-only: main.go passes CacheSize to
// cache.NewCache and ServeStaleSeconds to Cache.SetStaleWindow once, during boot,
// and nothing re-applies either afterwards. Editing them in config.json therefore
// takes effect on the next restart. Nothing exposes them for live editing — the
// dashboard has no field for either, and the only DNS mutation the API offers is
// adding or removing an upstream — so there is no request that silently answers
// 200 for a change the resolver never picks up. A future handler that writes them
// has to resize the cache and reset the stale window itself, or say out loud that
// a restart is needed.
type DNSSettings struct {
	Enabled       bool          `json:"enabled"`
	Port          int           `json:"port"`
	DoTPort       int           `json:"dot_port"`
	DoHPort       int           `json:"doh_port"`
	Upstreams     []string      `json:"upstreams"`
	CacheSize     int           `json:"cache_size"`
	CacheMinTTL   uint32        `json:"cache_min_ttl"`
	CacheMaxTTL   uint32        `json:"cache_max_ttl"`
	QueryTimeout  time.Duration `json:"query_timeout"`
	FastestRacing bool          `json:"fastest_racing"`
	ECSClientIP   string        `json:"ecs_client_ip"`

	// ServeStaleSeconds is how long past its expiry an answer may still be served
	// while a fresh one is fetched behind it (RFC 8767). Zero turns serve-stale off
	// and leaves prefetch running. Read once at startup — see the type comment.
	//
	// This key is new in v1.5.0. GetSetting unmarshals into an already-populated
	// struct, so a "dns" record written by an older release simply has no such key
	// and the built-in default survives — nothing needs converting on disk, and a
	// stored 0 means an operator turned the feature off rather than "never set".
	ServeStaleSeconds uint32 `json:"serve_stale_seconds"`
}

// SNIProxySettings holds reverse proxy and fragmentation parameters
type SNIProxySettings struct {
	Enabled   bool `json:"enabled"`
	HTTPPort  int  `json:"http_port"`
	HTTPSPort int  `json:"https_port"`

	// GameChatTLSPort / GameChatXMPPPort / RiotRTMPort / RiotPatcherPort are
	// the four extra listeners the relay opens for games whose control traffic
	// rides a non-443 port (XMPP chat, Riot's RTM and patcher). They were
	// hardcoded literals until v2.2.0; the values here are the historical
	// defaults so an existing config keeps its ports. Zero disables a listener
	// individually — the same convention HTTPPort already had.
	GameChatTLSPort  int `json:"game_chat_tls_port"`
	GameChatXMPPPort int `json:"game_chat_xmpp_port"`
	RiotRTMPort      int `json:"riot_rtm_port"`
	RiotPatcherPort  int `json:"riot_patcher_port"`

	Timeout             time.Duration `json:"timeout"`
	EnableFragmentation bool          `json:"enable_fragmentation"`
	FragmentSize        int           `json:"fragment_size"`
	FragmentDelayMs     int           `json:"fragment_delay_ms"`
}

// TLSSettings holds the custom domain and the ACME (Let's Encrypt) contact.
//
// Domain and Email are rewritten while the daemon is serving, by /api/tls/issue,
// and read from other goroutines: /api/config and /api/status serialise them into
// responses. They are guarded by mu and must be reached through the accessors in
// tls_access.go — see the note at the top of settings_access.go for why a plain
// field read of a string another goroutine may be writing is not safe. CertPath,
// KeyPath and AutoRenewACME are fixed at startup and may be read directly.
type TLSSettings struct {
	// mu guards Domain, Email and DoTDomain. It is unexported, so encoding/json
	// skips it and it never reaches the stored record.
	mu sync.RWMutex

	Domain        string `json:"domain"`
	Email         string `json:"email"` // ACME registration contact (certbot -m)
	CertPath      string `json:"cert_path"`
	KeyPath       string `json:"key_path"`
	AutoRenewACME bool   `json:"auto_renew_acme"`

	// DoTDomain is the custom hostname the DoT (853) and DoH (8443) listeners
	// serve a certificate for, when they should not ride the panel domain —
	// typically the name subscribers type into Android's Private DNS field.
	// Empty means "use the panel domain" (v2.2.0). Guarded by mu like Domain:
	// /api/tls/issue rewrites it while the daemon serves.
	DoTDomain string `json:"dot_domain"`

	// PanelHTTPS makes the dashboard listener serve TLS instead of plain HTTP on
	// WebPort. It is fixed at startup (it therefore sits outside mu, like the
	// certificate paths) and a restart is what makes a toggle take effect.
	PanelHTTPS bool `json:"panel_https"`
	// RedirectPort, when non-zero, binds an extra plain-HTTP listener that
	// answers GET/HEAD with a redirect to the HTTPS panel. Zero disables it. The
	// value is the literal port alongside the panel listener, so 80 is the
	// natural choice on a host where the SNI relay does not own it.
	RedirectPort int `json:"redirect_port"`
}

// SubscriptionSettings describes the public subscriber surface (v2.1): the
// origin subscriber links are built from, the title the portal shows, and the
// certificate material to use when that origin is not the panel's own.
//
// In this build the subscription pages are served by the panel listener with
// host-aware routing (the plan's preferred mode: no duplicate binds, no second
// certificate to rotate unless the operator chooses a different domain). The
// Domain/Port/CertPath fields therefore describe the origin that generated
// links advertise, and — when it differs from the panel's — the certificate
// that origin must present. Every field is displayable; none is a secret.
type SubscriptionSettings struct {
	// mu guards every field: any of them can be rewritten by a settings
	// handler while portal pages are being rendered, and the same tearing
	// argument as settings_access.go applies to each string.
	mu sync.RWMutex

	// Enabled turns the whole subscriber surface off: the portal routes answer
	// with the same 404 an unknown path gets, and no link is generated. A
	// reseller who stops selling can retire the pages without tearing down DNS.
	Enabled bool `json:"enabled"`

	// ListenIP is reserved for a future dedicated listener. Empty means "share
	// the panel listener", which is the only mode this build implements.
	ListenIP string `json:"listen_ip"`

	// Domain is the hostname subscriber links are built from. Empty falls back
	// to the panel's TLS domain, then to the public IP.
	Domain string `json:"domain"`

	// Port is the port subscriber links advertise. It is the panel port in this
	// build; a distinct value is stored so the settings UI can already collect
	// the operator's intent before a dedicated listener exists.
	Port int `json:"port"`

	// URIPath is the mount point of the portal pages. "/sub" is the default and
	// the only value this build serves: /sub/<token> and /ip/<token> are fixed
	// routes with years of subscriber links behind them. The field exists so a
	// future custom mount migrates without another schema change.
	URIPath string `json:"uri_path"`

	// Title is the brand line on the portal. Default "HyperDNS".
	Title string `json:"title"`

	// ThemeCSS is the operator's stylesheet injected after the built-in portal
	// CSS. Bounded and sanitised on save (Phase 7); empty means none.
	ThemeCSS string `json:"theme_css"`

	// ThemeCSSSource selects where the portal's custom CSS comes from (v2.4):
	// "" or "inline" uses ThemeCSS above; "local" reads ThemeCSSPath off the
	// server's disk and inlines it; "url" emits a <link> to ThemeCSSURL that the
	// subscriber's browser fetches. The three are mutually exclusive.
	ThemeCSSSource string `json:"theme_css_source"`
	// ThemeCSSPath is a server-local CSS file (e.g. /root/css/sub.css), read
	// only, used when ThemeCSSSource is "local".
	ThemeCSSPath string `json:"theme_css_path"`
	// ThemeCSSURL is an http(s) stylesheet URL the browser loads directly, used
	// when ThemeCSSSource is "url".
	ThemeCSSURL string `json:"theme_css_url"`

	// CertPath/KeyPath name the certificate pair for a subscription origin that
	// is NOT the panel's. Ignored while UsePanelCertificate is true.
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`

	// UsePanelCertificate is the default mode: the subscription origin is the
	// panel origin, panel domain and panel certificate included.
	UsePanelCertificate bool `json:"use_panel_certificate"`

	// PortExplicit records that the operator deliberately set a portal port
	// of their own. The dashboard sets it whenever a save names a port that
	// is neither 0 nor the panel's current port, and clears it when the port
	// returns to the panel's. The boot-time port-drift repair and the live
	// panel-port copy-follow read this: a stale seeded copy of the panel port
	// must follow the panel when it moves, but a port the operator chose must
	// survive it. Records written before the field existed decode as false —
	// seeded behaviour — which is the correct reading for everything except
	// pre-marker deliberate ports, and one re-save of the card marks those
	// permanently.
	PortExplicit bool `json:"port_explicit"`
}
