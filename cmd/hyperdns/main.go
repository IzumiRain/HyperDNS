package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"context"
	"hyperdns/internal/bootstrap"
	"hyperdns/internal/control"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/dns"

	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/proxy"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/netutil"
	"hyperdns/internal/presetupd"
	"hyperdns/internal/service"
	"hyperdns/internal/service/acme"
	"hyperdns/internal/tui"
	"hyperdns/internal/version"
	internalWeb "hyperdns/internal/web"
	webAssets "hyperdns/web"
)

const banner = `
   _    _                           _____  _   _  _____ 
  | |  | |                         |  __ \| \ | |/ ____|
  | |__| |_   _ _ __   ___ _ __    | |  | |  \| | (___  
  |  __  | | | | '_ \ / _ \ '__|   | |  | | . ' |\___ \ 
  | |  | | |_| | |_) |  __/ |      | |__| | |\  |____) |
  |_|  |_|\__, | .__/ \___|_|      |_____/|_| \_|_____/ 
           __/ | |                                      
          |___/|_|      Next-Gen Standalone SmartDNS
`

func main() {
	dbPath := flag.String("db", "", "Path to database file (e.g. /opt/hyperdns/data.db)")
	keyPath := flag.String("key", "", "Path to master encryption key (e.g. /opt/hyperdns/master.key)")
	configPath := flag.String("config", "", "Path to config.json (default settings used when DB has no value)")
	bindHost := flag.String("host", "", "Override bind host IP (e.g. 0.0.0.0)")
	dnsPort := flag.Int("dns-port", 0, "Override DNS Port (e.g. 53)")
	webPort := flag.Int("web-port", 0, "Override Web Dashboard Port (e.g. 8080)")
	publicIP := flag.String("public-ip", "", "Override Server Public IP")
	daemonMode := flag.Bool("daemon", false, "Run as background server engine (for systemd)")
	serverMode := flag.Bool("server", false, "Run as background server engine")
	showVersion := flag.Bool("version", false, "Print version information")
	flag.Parse()

	if *showVersion {
		_, exitCode := runPreDBCommand([]string{"-version"}, *configPath, os.Stdout, os.Stderr)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return
	}

	if handled, exitCode := runPreDBCommand(preDBArgs(flag.Args(), *daemonMode, *serverMode), *configPath, os.Stdout, os.Stderr); handled {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return
	}

	// 1. Resolve DB and Key paths
	dPath := *dbPath
	if dPath == "" {
		if _, err := os.Stat("/opt/hyperdns"); err == nil {
			dPath = "/opt/hyperdns/data.db"
		} else {
			dPath = "data.db"
		}
	}

	kPath := *keyPath
	if kPath == "" {
		if _, err := os.Stat("/opt/hyperdns"); err == nil {
			kPath = "/opt/hyperdns/master.key"
		} else {
			kPath = "master.key"
		}
	}

	state, stateErr := bootstrap.ClassifyPaths(dPath, kPath)
	_, policyErr := storageInitializationAllowed(state, stateErr, *daemonMode, *serverMode)
	if policyErr != nil {
		log.Fatalf("[Main] Refusing storage initialization: %v", policyErr)
	}

	// 2. Initialize AES-256-GCM AEAD Master Key. Reaching this call for a fresh
	// pair is authorized only by daemon/server mode above; incomplete pairs have
	// already failed without creating or replacing either file.
	cipher, err := crypto.LoadOrGenerateMasterKey(kPath)
	if err != nil {
		log.Fatalf("[Main] Failed to initialize cryptographic engine: %v", err)
	}

	// 3. Open the encrypted database. Existing stores are validated under the
	// same exclusive bbolt handle before any bucket or record migration can run;
	// fresh initialization uses a separate creation path.
	var db *database.DB
	if state == bootstrap.PathsComplete {
		db, err = database.OpenExisting(dPath, cipher)
	} else {
		db, err = database.Create(dPath, cipher)
	}
	if err != nil {
		// The overwhelmingly common cause is that the background daemon already
		// holds the bbolt file lock (bbolt is single-writer). `hdns` in an SSH
		// session hits exactly this. Tell the operator what to do instead of a
		// bare "timeout" (v2.1.0 installer-feedback fix #4).
		if isLockTimeout(err) {
			log.Printf("[Main] The database at %s is locked — another HyperDNS service process owns the bbolt store.", dPath)
			log.Printf("[Main] Client commands do not need direct database access:")
			log.Printf("[Main]   1. Open the live control console: hdns")
			log.Printf("[Main]   2. Show live status: hdns status")
			log.Printf("[Main]   3. Flush the daemon cache: hdns flush")
			log.Printf("[Main]   4. Use the web dashboard or inspect logs: journalctl -u hyperdns -f")
			log.Fatalf("[Main] Refusing to start a second service process while the database is owned")
		}
		log.Fatalf("[Main] Failed to open database at %s: %v", dPath, err)
	}
	defer db.Close()

	// Detect mixed/stale deployments: version.json on disk vs embedded version
	checkVersionDrift(filepath.Dir(dPath))

	// 4. Load or Initialize Settings
	//
	// A hardcoded default password is a backdoor: identical on every install and
	// readable in the published source. Generate one per install instead, and
	// announce it once below if nothing else supplies a password.
	generatedAdminPassword := generateInitialPassword()
	serverSettings := &database.ServerSettings{
		PublicIP:      "127.0.0.1",
		BindHost:      "0.0.0.0",
		WebPort:       8080,
		AdminUsername: "admin",
		AdminPassword: generatedAdminPassword,
		APIKey:        crypto.GenerateAPIKey(),
		APIBind:       "127.0.0.1",
	}

	dnsSettings := &database.DNSSettings{
		Enabled:       true,
		Port:          53,
		DoTPort:       853,
		DoHPort:       8443,
		Upstreams:     []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53", "1.0.0.1:53"},
		CacheSize:     20000,
		CacheMinTTL:   60,
		CacheMaxTTL:   86400,
		QueryTimeout:  2 * time.Second,
		FastestRacing: true,
		// Thirty seconds of grace past expiry: long enough to ride out an upstream
		// hiccup, short enough that nobody connects to an address that moved a
		// minute ago.
		ServeStaleSeconds: 30,
	}

	sniSettings := &database.SNIProxySettings{
		Enabled:   true,
		HTTPPort:  80,
		HTTPSPort: 443,
		// The four extra game listeners (v2.2.0: settings, no longer literals in
		// the relay). These are the historical hardcoded values; a config file or
		// a persisted record overrides them field by field, and 0 disables one.
		GameChatTLSPort:     5223,
		GameChatXMPPPort:    5222,
		RiotRTMPort:         2099,
		RiotPatcherPort:     8393,
		Timeout:             120 * time.Second,
		EnableFragmentation: true,
		FragmentSize:        2,
		FragmentDelayMs:     5,
	}

	tlsSettings := &database.TLSSettings{
		Domain:        "",
		CertPath:      "certs/cert.pem",
		KeyPath:       "certs/key.pem",
		AutoRenewACME: false,
	}

	subscriptionSettings := &database.SubscriptionSettings{}
	authSettings := &database.AuthSettings{}

	// Apply defaults from config.json if provided (values already stored in the
	// database always take precedence over these file defaults).
	var fileAccess *AccessConfig
	if *configPath != "" {
		fileAccess = applyConfigFile(*configPath, serverSettings, dnsSettings, sniSettings, tlsSettings)
	}

	// Persisted database settings (if any) override file defaults. Load every
	// authoritative record before any bootstrap write or service construction.
	serverWasPersisted, err := db.SettingExists("server")
	if err != nil {
		log.Fatalf("[Main] Could not inspect persisted server settings: %v", err)
	}
	// v2.2.0: an unknown source is refused by default. The file seed can still
	// say true, and a persisted record always wins (see MigrateDefaultAllowAll
	// below for how an upgrade converges), but the out-of-the-box contract is
	// whitelist — the product sells per-client accounts, and a resolver that
	// answers strangers was serving the product's non-paying half for free.
	allowAll := false
	if fileAccess != nil && fileAccess.PresentAllowAll {
		allowAll = fileAccess.AllowAll
	}
	var presetUpdateSettings struct {
		PresetsURL string `json:"presets_url"`
		AutoApply  bool   `json:"auto_apply"`
	}
	var accessSettings struct {
		DoHTokens []string `json:"doh_tokens"`
	}
	if err := bootstrap.LoadPresentSettings(db,
		bootstrap.SettingSpec{Key: "server", Target: serverSettings},
		bootstrap.SettingSpec{Key: "dns", Target: dnsSettings},
		bootstrap.SettingSpec{Key: "sniproxy", Target: sniSettings},
		bootstrap.SettingSpec{Key: "tls", Target: tlsSettings},
		bootstrap.SettingSpec{Key: "subscription", Target: subscriptionSettings},
		bootstrap.SettingSpec{Key: "auth", Target: authSettings},
		bootstrap.SettingSpec{Key: "allow_all", Target: &allowAll},
		bootstrap.SettingSpec{Key: "access", Target: &accessSettings},
		bootstrap.SettingSpec{Key: "preset_updates", Target: &presetUpdateSettings},
	); err != nil {
		log.Fatalf("[Main] Refusing to start with unreadable persisted settings: %v", err)
	}

	// One-time v2.2.0 convergence: an upgrading database lands on the whitelist
	// default. The load above already ran and holds the pre-migration value; the
	// migration writes allow_all=false only when its marker is absent, so the
	// re-read below picks up either that fresh false or the operator's own
	// record — the DB wins over the file seed for this and every later boot.
	bootstrap.MigrateDefaultAllowAll(db)
	if dbRecorded, err := db.SettingExists("allow_all"); err != nil {
		log.Fatalf("[Main] Could not inspect the persisted access mode: %v", err)
	} else if dbRecorded {
		if err := db.GetSetting("allow_all", &allowAll); err != nil {
			log.Fatalf("[Main] Could not read the persisted access mode: %v", err)
		}
	}

	// Local-plaintext hygiene (v2.1.0 A-04 remediation): a backup of the master
	// key left beside the live key, or a raw data.db copy, is exactly what a
	// leaked-backup incident is made of. The daemon cannot delete an operator's
	// files, but it must say why it objects.
	if _, err := os.Stat(filepath.Join(filepath.Dir(kPath), "master.key.bak")); err == nil {
		log.Printf("[Main] SECURITY WARNING: %s/master.key.bak exists. A plaintext key backup beside the live key is the whole database in readable form — move it offline (encrypted) and delete it.", filepath.Dir(kPath))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dPath), "data.db.bak")); err == nil {
		log.Printf("[Main] SECURITY WARNING: %s/data.db.bak exists. Combined with the key, that copy is every subscriber's plaintext — remove it once any needed restore is done.", filepath.Dir(dPath))
	}

	// Install the trusted-proxy allowlist BEFORE any listener can accept a
	// request: ClientIP refuses forwarding headers from an undeclared peer, so
	// with the default empty list every client is its own peer and a reverse
	// proxy must be declared here to be believed. Doing this after the listeners
	// come up would leave a window in which a spoofable header decides the
	// login-lockout key (v2.1.0 A-01 remediation).
	netutil.SetTrustedProxies(serverSettings.TrustedProxyCIDRs)
	if len(serverSettings.TrustedProxyCIDRs) > 0 {
		log.Printf("[Main] Trusted proxies: %v (forwarding headers believed from these only)", serverSettings.TrustedProxyCIDRs)
	} else {
		log.Printf("[Main] No trusted proxies configured; forwarding headers are ignored (set trusted_proxy_cidrs to enable)")
	}

	// An empty password means "log in with nothing", and the placeholder shipped in
	// the public config.example.json is a password everyone can read. Both are
	// treated as "no password supplied", so the generated one takes over and gets
	// announced and persisted below.
	if serverSettings.AdminPassword == "" || serverSettings.AdminPassword == exampleConfigPasswordPlaceholder {
		log.Printf("[Main] config.json carries no usable admin password (%q); generating one instead.", serverSettings.AdminPassword)
		serverSettings.AdminPassword = generatedAdminPassword
	}
	if serverSettings.AdminUsername == "" {
		serverSettings.AdminUsername = "admin"
	}

	// Explicit CLI flags are the highest precedence override
	if *bindHost != "" {
		serverSettings.BindHost = *bindHost
	}
	if *dnsPort > 0 {
		dnsSettings.Port = *dnsPort
	}
	if *webPort > 0 {
		serverSettings.WebPort = *webPort
	}
	if *publicIP != "" {
		serverSettings.PublicIP = *publicIP
	}

	// settingsDirty collects every reason the "server" record needs rewriting, so
	// the daemon persists once, at the end, after the password has been hashed.
	// Writing earlier would put the plaintext on disk on the very first run.
	settingsDirty := !serverWasPersisted

	// A missing master API key is not the same failure as a wrong one, and it used
	// to look identical from outside — see ensureAPIKey.
	if ensureAPIKey(serverSettings) {
		settingsDirty = true
	}

	// Auto-detect the public IPv4 when it is still a placeholder. The DNS handler
	// answers proxied domains with this address, so a loopback value silently
	// breaks every redirect.
	if isPlaceholderPublicIP(serverSettings.PublicIP) {
		if detected := detectPublicIP(); detected != "" {
			log.Printf("[Main] Auto-detected public IP: %s (was %q)", detected, serverSettings.PublicIP)
			serverSettings.PublicIP = detected
			settingsDirty = true
		} else {
			log.Printf("[Main] Warning: public IP is %q and auto-detection failed; proxied domains will not redirect correctly. Set it in Settings or with -public-ip.", serverSettings.PublicIP)
		}
	}

	// First run with no supplied password: the generated one is the only way in,
	// so print it once. This has to happen before the hashing step below, which
	// is the point at which the plaintext stops being recoverable.
	//
	// The plaintext goes to STDOUT ONLY (fmt.Println), never through the log
	// package (v2.1.0 A-04 remediation): log output is what systemd/journald and
	// the hyperdns_out.log the service wrapper captures persist, and a rotating
	// log file is readable by anything that can read the box's logs. The banner
	// lines around it still go through log.Printf so they show up wherever the
	// operator looks; only the credential itself is stdout-only.
	if serverSettings.AdminPassword == generatedAdminPassword {
		log.Printf("[Main] No admin password was configured. Generated one for this install — printed to STDOUT below, NOT to this log.")
		log.Printf("[Main]     username : %s", serverSettings.AdminUsername)
		fmt.Println("──────────────────────────────────────────────────────────")
		fmt.Printf("  HyperDNS first-run credentials (save them now — shown once)\n")
		fmt.Printf("    username : %s\n", serverSettings.AdminUsername)
		fmt.Printf("    password : %s\n", generatedAdminPassword)
		fmt.Println("──────────────────────────────────────────────────────────")
	}

	// Migrate the admin password to a hash. Releases before v1.5.0 stored it as
	// plaintext, and config.json can only ever supply plaintext, so both cases
	// arrive here and are converted in place. Nothing else about the record
	// changes, which is what makes this safe to run against a live database.
	if migrateAdminPassword(serverSettings) {
		settingsDirty = true
	}

	// Generate the hidden admin path on the very first run, or when a database
	// migrated from a pre-v2.1 release has none. The path is a 16-character
	// lowercase hex string chosen by the CSPRNG; it is stored immediately so it
	// stays constant across restarts. It is a locator rather than a credential,
	// so the log is an acceptable place for it — and the operator needs it in
	// the same place the credentials were announced, which is the console.
	if ensureAdminPath(serverSettings) {
		log.Printf("[Main] ──────────────────────────────────────────────────────────")
		log.Printf("[Main] Generated admin panel path for this install:")
		log.Printf("[Main]     https://<domain>/%s/dash/login", serverSettings.AdminPath)
		log.Printf("[Main] Save it now — it is not printed again. Regenerate it in Settings.")
		log.Printf("[Main] ──────────────────────────────────────────────────────────")
		settingsDirty = true
	}

	// Seed the subscription record once. A database from before v2.1 has no
	// "subscription" record; the panel's own domain and port are exactly what
	// the subscriber links named before a separate origin existed, so they are
	// the seed. The presence of the record stops a later restart from
	// overwriting whatever the operator changed.
	if seeded, err := database.EnsureSubscriptionDefaults(subscriptionSettings, tlsSettings.Domain, serverSettings.WebPort, func(s *database.SubscriptionSettings) error {
		return db.SetSetting("subscription", s)
	}); err != nil {
		log.Printf("[Main] Warning: could not persist subscription settings: %v", err)
	} else if seeded {
		log.Printf("[Main] Subscription settings seeded from the panel origin (domain %q, port %d)", subscriptionSettings.Domain, subscriptionSettings.Port)
	}

	// Port-drift reconciliation (v2.2.0): the seed copies the panel port into
	// the subscription record, and a panel-port change made before this fix
	// updated only the server record. The stale copy then differed from
	// WebPort, which the listener logic read as a DELIBERATE separate portal
	// port — binding a subscriber listener on the port the operator had just
	// moved away from, served with the subscription record's certificate
	// (field report: ERR_CERT_COMMON_NAME_INVALID on the old dashboard URL).
	// repairSubscriptionPortDrift re-points the copy when the record still
	// carries the untouched-seed signature; a deliberately separate portal
	// port (different domain or its own certificate) is left alone.
	if repaired := repairSubscriptionPortDrift(subscriptionSettings, tlsSettings.Domain, serverSettings.WebPort, func(s *database.SubscriptionSettings) error {
		return db.SetSetting("subscription", s)
	}); repaired {
		log.Printf("[Main] Subscription record's port copy re-pointed to the panel port %d", serverSettings.WebPort)
	}

	if settingsDirty {
		if err := db.SetSetting("server", serverSettings); err != nil {
			log.Printf("[Main] Warning: could not persist server settings: %v", err)
		}
	}
	// 5. Initialize Core Engine & Services
	c := cache.NewCache(dnsSettings.CacheSize, dnsSettings.CacheMinTTL, dnsSettings.CacheMaxTTL)
	// Serve-stale is only ever engaged once a refresher is installed (see
	// dns.NewHandler below), so setting the window here is safe even at zero.
	c.SetStaleWindow(time.Duration(dnsSettings.ServeStaleSeconds) * time.Second)
	if dnsSettings.ServeStaleSeconds > 0 {
		log.Printf("[Main] Cache serve-stale window: %ds", dnsSettings.ServeStaleSeconds)
	} else {
		log.Printf("[Main] Cache serve-stale: disabled (prefetch still active)")
	}
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool(dnsSettings.Upstreams, dnsSettings.QueryTimeout, dnsSettings.FastestRacing, dnsSettings.ECSClientIP)
	// Measure the pool once at startup. The constructor only seeds an estimate; this
	// is the one place that has to pay for the real numbers, and it runs detached so
	// a slow or blackholed upstream cannot delay the listeners coming up.
	go u.BenchmarkAll()

	// Access mode was resolved with every other authoritative setting before any
	// bootstrap write; constructing services cannot turn a read failure into a
	// default value.
	clientService := service.NewClientService(db, allowAll)
	log.Printf("[Main] Access mode: allow_all=%v", allowAll)

	sniServer := proxy.NewServer(*sniSettings, serverSettings.BindHost, tlsSettings.Domain, clientService)

	statsService := service.NewStatsService(db, sniServer.GetStats, c.GetStats)

	// Both of these own a ticker goroutine, and both shutdown paths below (the TUI's
	// [0] Exit and the signal handler) leave through a return, so the defers run on
	// either one. Registered after the deferred db.Close() and therefore ahead of it:
	// the telemetry loop reads counters, not the database, but stopping the samplers
	// before the store they might reach for is the order that cannot be wrong.
	defer c.Close()
	defer statsService.Close()

	// The rule sources apply in precedence order, opposite of the old sequence:
	// config.json seeds first, the database lands last. The config file supplies
	// defaults (config.go's contract: "any value already stored in the database
	// always wins over the file"), so the DB restore has to run after it — with
	// the old order, every restart re-applied the file's toggles over the
	// operator's dashboard-saved ones, and a policy disabled in the panel came
	// back on at the next boot. A key with no database row keeps the file's
	// value, which is the fresh-install seeding the file exists for.
	if *configPath != "" {
		applyRulesFromConfig(*configPath, m)
	}
	loadPersistedRules(db, m)

	// Named custom policy groups (v2.3): loaded after the flat rules so the
	// matcher's stored custom state is complete before the first query. The
	// service keeps the matcher and the database in sync on every edit.
	customGroupService := service.NewCustomGroupService(db, m)

	// The preset-update channel (v2.3.0): the embedded baseline is permanent;
	// a signed channel override is re-applied at boot and updated from the
	// dashboard or the console. Constructed here so both the dashboard and the
	// control socket share one updater state.
	presetUpdater := presetupd.New(
		presetUpdateSettings.PresetsURL, nil, m, db, log.Printf)
	if err := presetUpdater.LoadPersisted(); err != nil {
		log.Printf("[Main] preset channel override load failed: %v", err)
	}
	presetUpdater.SetAutoApply(presetUpdateSettings.AutoApply)

	// Phase D: the operator's configured idle window wins when present, and it
	// is re-applied live from the dashboard (SessionManager.SetIdleTimeout).
	// 24h absolute lifetime is unchanged: the idle window is what the flowchart
	// calls "active session in the last N minutes".
	sessionManager := service.NewSessionManager(24 * time.Hour)
	if idleMin := serverSettings.GetSessionIdleMinutes(); idleMin > 0 {
		sessionManager.SetIdleTimeout(time.Duration(idleMin) * time.Minute)
	}
	_ = sessionManager

	dnsHandler := dns.NewHandler(clientService, c, m, u, statsService, serverSettings.PublicIP)
	// v2.5: publish the server's IPv6 for proxied AAAA when one is configured, so
	// IPv6 clients reach the SNI proxy over v6 instead of being forced to IPv4.
	dnsHandler.SetPublicIPv6(serverSettings.PublicIPv6)
	dohHandler := dns.NewDoHHandler(dnsHandler)

	// DoH bearer tokens (v2.1.0 B-07 remediation): config.json's access block
	// used to parse doh_tokens and drop them on the floor, while the dashboard's
	// DoH Secret Tokens card wrote the same list into the "access" record that
	// nothing read. Now: config values seed the record, and the DoH handler
	// enforces it — a non-empty list makes ?token= mandatory.
	var dohTokens []string
	{
		dohTokens = accessSettings.DoHTokens
		if fileAccess != nil && len(fileAccess.DoHTokens) > 0 {
			// config.json wins for a fresh install; the dashboard's saved list
			// is the runtime surface afterwards.
			if len(dohTokens) == 0 {
				dohTokens = fileAccess.DoHTokens
				if err := db.SetSetting("access", map[string]any{"doh_tokens": dohTokens}); err != nil {
					log.Printf("[Main] Warning: could not seed DoH tokens into the access record: %v", err)
				} else {
					log.Printf("[Main] Seeded %d DoH token(s) from config.json into the access record", len(dohTokens))
				}
			} else {
				log.Printf("[Main] Warning: config.json doh_tokens ignored — the access record already holds %d token(s) from the dashboard", len(dohTokens))
			}
		}
		if len(dohTokens) > 0 {
			dohHandler.SetDoHTokens(dohTokens)
			log.Printf("[Main] DoH token enforcement: %d token(s) active", len(dohTokens))
		}
	}
	if fileAccess != nil && (len(fileAccess.AllowedIPs) > 0 || len(fileAccess.BlockedIPs) > 0) {
		log.Printf("[Main] Warning: config.json access.allowed_ips/blocked_ips are not implemented in this build and are ignored — the access model is subscriber accounts (allowed_ips) plus allow_all, not a global IP list.")
	}

	// Per-source query rate limit. The key is honoured even when set to 0, which
	// is how an operator turns limiting off; absent from the file leaves the
	// built-in default, because allow_all defaults to true and an unmetered
	// resolver amplifies whatever source address a flood claims to come from.
	if fileAccess != nil && fileAccess.PresentRateLimit {
		dnsHandler.SetRateLimit(fileAccess.RateLimitQPS)
		if fileAccess.RateLimitQPS > 0 {
			log.Printf("[Main] DNS rate limit: %d qps per source", fileAccess.RateLimitQPS)
		} else {
			log.Printf("[Main] DNS rate limit: disabled by config")
		}
	}

	// The limiter drops a UDP flood without replying, so nothing in the panel would
	// otherwise show that it fired. Wired after SetRateLimit so the reported limit
	// is the one actually in force.
	statsService.SetGuardStatsSource(func() (uint64, int) {
		return dnsHandler.RateLimited(), dnsHandler.RateLimitQPS()
	})

	// Serve-stale hides a dead upstream from clients on purpose, which also hides it
	// from the operator. These counters are the only place that failure is visible
	// before the grace window closes and names start going dark.
	statsService.SetPrefetchStatsSource(c.PrefetchStats)

	// The proxy's two non-relay outcomes. A connection that names no destination
	// never becomes a relay, so it appears in none of the relay figures — and it is
	// exactly the shape a proxied name whose traffic this relay cannot carry takes
	// on the wire.
	statsService.SetProxyGuardStatsSource(sniServer.GuardStats)

	webServer := internalWeb.NewWebServer(
		db,
		clientService,
		statsService,
		c,
		m,
		u,
		dohHandler,
		serverSettings,
		tlsSettings,
		dnsSettings,
		sessionManager,
		webAssets.StaticFS,
		presetUpdater,
	)
	webServer.SetSubscriptionSettings(subscriptionSettings)
	webServer.SetAuthSettings(authSettings)
	webServer.SetCustomGroupService(customGroupService)

	// v2.2.0: the embedded ACME client replaces certbot/acme.sh. It ships in
	// the binary (an offline install can issue the moment it has internet,
	// with no packages to install) and serves HTTP-01 out of the port-80
	// listener that is already running, so issuance no longer stops the
	// service. The account key persists like any other setting, encrypted.
	var acmeAccountKey []byte
	var acmeState struct {
		AccountKeyPEM []byte `json:"account_key"`
	}
	if err := db.GetSetting("acme", &acmeState); err == nil && len(acmeState.AccountKeyPEM) > 0 {
		acmeAccountKey = acmeState.AccountKeyPEM
	}
	acmeDir := "/opt/hyperdns/certs/acme"
	if _, err := os.Stat("/opt/hyperdns"); err != nil {
		acmeDir = "certs/acme" // a non-installed (dev) run keeps its tree local
	}
	_, acmeContactEmail := tlsSettings.ACMEContact()
	acmeManager := acme.NewManager("", acmeContactEmail, acmeDir, acmeAccountKey)
	webServer.SetACMEManager(acmeManager)
	// The SNI proxy serves the challenges on its port-80 listener; when the
	// proxy is disabled and a domain is configured, the manager binds :80 for
	// itself inside Issue (challenge-only).
	sniServer.SetChallengeResponder(acmeManager)

	// The web panel and local control protocol must operate on the same benchmark
	// gate and login-attempt tracker. Separate copies would let the two management
	// surfaces disagree about a running benchmark or cleared lockout.
	benchmarkRunner := service.NewBenchmarkRunner(u.BenchmarkAll)
	loginAttempts := service.NewLoginAttemptTracker()
	webServer.SetControlState(benchmarkRunner, loginAttempts)

	controlAdapter := &daemonControl{
		db:        db,
		clients:   clientService,
		stats:     statsService,
		cache:     c,
		upstreams: u,
		settings:  serverSettings,
		auth:      authSettings,
		sessions:  sessionManager,
		lockouts:  loginAttempts,
		benchmark: benchmarkRunner,
		audit:     log.Default(),
		dnsCfg:    dnsSettings,
		sniCfg:    sniSettings,
		tlsCfg:    tlsSettings,
		subs:      subscriptionSettings,
	}
	// The console's update-presets verb drives the same updater the dashboard
	// uses: check-and-apply in one call, with the updater's own rollback.
	presetsSource := controlPresetSource{updater: presetUpdater}
	controlOps := control.NewDaemonOperations(control.DaemonDependencies{
		Status:    controlAdapter,
		Clients:   controlAdapter,
		Cache:     c,
		Benchmark: benchmarkRunner,
		Settings:  controlAdapter,
		Presets:   presetsSource,
	})

	// 6. Handle the one remaining pre-listener local utility. Informational and
	// daemon-client commands were dispatched before storage access above.
	args := flag.Args()
	if len(args) > 0 && strings.ToLower(args[0]) == "uninstall" {
		tui.UninstallHyperDNS()
		return
	}

	// Panel certificate first-run issuance (installer contract: panel is
	// HTTPS-only on a domain).
	//
	// v2.2.0 ORDER REVERSAL: listeners first, issuance second. The embedded
	// client serves the HTTP-01 challenge out of the SNI proxy's port-80
	// listener, which has to be accepting before the CA's validator connects —
	// the exact opposite of the v2.1 certbot constraint (certbot needed to
	// bind :80 itself, so it had to run before the proxy did).
	//
	// The control socket is also up by this point, and the DNS resolver is
	// either started or fatally failed, so an issuance that takes a minute
	// delays only the TLS-bearing listeners — port 53 is already answering.
	if sniSettings.Enabled {
		if err := sniServer.Start(); err != nil {
			log.Printf("[Main] Warning: SNI Proxy: %v", err)
		}
	}
	webServer.StartACMEIfNeeded()

	tlsConfig, err := service.LoadOrGenerateTLSConfig(tlsSettings)
	if err != nil {
		// With a domain configured this is the "no trusted certificate" case:
		// the panel listener below refuses to start for the same reason, so
		// the daemon exits with a clear journal. DoT and the DoH/8443 listener
		// simply stay down (a nil config skips them) — port 53 keeps answering
		// for as long as the process lives.
		log.Printf("[Main] TLS configuration error: %v", err)
	}

	// The DoT/DoH listeners can carry a certificate of their own (the custom
	// DoH/DoT domain, v2.2.0). The holder is created before the DNS server so
	// the source is wired at construction; a later issue for that name
	// hot-swaps through it without touching the listeners. No pair / no
	// domain = nil source = the transports ride the panel certificate.
	var dotHolder *internalWeb.CertHolder
	if d := tlsSettings.GetDoTDomain(); d != "" {
		crt := filepath.Join(acmeDir, d+".crt")
		key := filepath.Join(acmeDir, d+".key")
		if err := internalWeb.ValidatePanelCertificate(crt, key, d); err != nil {
			log.Printf("[TLS] Configured DoH/DoT domain %s has no valid certificate yet (%v) — the transports serve the panel certificate; issue one from Settings", d, err)
		} else {
			dotHolder = internalWeb.NewCertHolderLoading(crt, key)
			log.Printf("[TLS] DoT/DoH listeners will serve the certificate for %s", d)
		}
	}
	// The DoH listener gets the restricted surface, not BuildHandler: the DoH
	// port answers /dns-query and the public portal routes, and never the
	// admin namespace (Mantis v2.1.0 finding #1).
	dnsServer := dns.NewServer(dnsHandler, tlsConfig, webServer.BuildDoHHandler(), serverSettings.BindHost, dnsSettings.Port, dnsSettings.DoTPort, dnsSettings.DoHPort)
	if dotHolder != nil {
		dnsServer.SetDOTCertSource(dotHolder)
	}
	// The rebind hook carries the source to install, not just a signal: a
	// dedicated domain's first issuance constructs its holder mid-process and
	// lands it here, and a cleared domain lands nil so the transports fall
	// back to the panel pair. Set + rebind under the DNS server's own lock is
	// what keeps the stored record and the live listeners the same fact.
	webServer.SetDOTCertHolder(dotHolder, func(src *internalWeb.CertHolder) error {
		dnsServer.SetDOTCertSource(src)
		return dnsServer.RebindTLS()
	})

	// Only explicit service modes reach runtime ownership. A bare invocation was
	// already dispatched to the storage-free control client above.
	fmt.Print(banner)
	log.Printf("[Main] Starting HyperDNS Engine (Public IP: %s)...", serverSettings.PublicIP)

	// The daemon owns the only control socket. Start it after all shared services
	// exist and before public listeners are announced ready. Bare `hdns` is a
	// client process and never reaches this branch.
	controlServer, err := startDaemonControl(*daemonMode, *serverMode, func() localControlServer {
		return control.NewServer(control.DefaultSocketPath, control.NewHandler(controlOps))
	})
	if controlStartupFatal(err) {
		log.Fatalf("[Main] Failed to start local control server: %v", err)
	}
	if err != nil {
		// Linux-only by design: the transport authorizes its peer with
		// SO_PEERCRED and there is deliberately no TCP fallback. A host without
		// it still runs the resolver, the relay and the dashboard; only the
		// `hdns` console and `hdns flush` need the socket.
		log.Printf("[Main] Local control console unavailable on this platform: %v", err)
		log.Printf("[Main] The resolver, relay and dashboard are unaffected; `hdns` client commands require a Linux host.")
	}

	if dnsSettings.Enabled {
		if err := dnsServer.Start(); err != nil {
			cleanupControlAfterStartupFailure(controlServer)
			log.Fatalf("[Main] Failed to start DNS Server: %v", err)
		}
	}

	// The relay already started above, before StartACMEIfNeeded — the port-80
	// challenge path has to be live for the issuance that follows it.

	if err := webServer.Start(); err != nil {
		cleanupControlAfterStartupFailure(controlServer)
		log.Fatalf("[Main] Failed to start Web Server: %v", err)
	}

	stopWatcher := clientService.StartExpirationWatcher(1 * time.Minute)
	defer close(stopWatcher)

	// Registered after the deferred db.Close() and therefore run before it, so the
	// final flush still has a database to write to. 0 selects the package default
	// flush interval.
	stopFlusher := clientService.StartTrafficFlusher(0)
	defer stopFlusher()

	// Certificate renewal (v2.2.0): one check a day, covering every surface
	// that carries its own certificate — the panel domain, the subscription
	// portal's own pair, and the DoH/DoT transports' pair. NeedsRenewal reads
	// each pair's leaf; when fewer than 30 days remain (or the pair is
	// missing, e.g. a boot issuance that failed), one single-flighted issuance
	// runs through the same path as the dashboard's Save — including the live
	// hot-swap, so a renewal lands without a restart and never at a moment
	// the operator has to be watching.
	stopRenewal := startACMERenewalLoop(acmeManager, db,
		webServer.RenewIfDue,
		webServer.RenewSubscriptionIfDue,
		webServer.RenewDOTIfDue,
	)
	defer func() { close(stopRenewal) }()

	// Graceful-stop path shared by signals and service shutdown. Stop the private
	// control endpoint first so no new mutation races with public listener drain.
	shutdownDone := make(chan struct{})
	gracefulStop := func() {
		log.Println("[Main] Shutting down HyperDNS gracefully...")
		shutdownDaemonRuntime(controlServer, dnsServer.Stop, sniServer.Stop, webServer.Stop)
		log.Println("[Main] HyperDNS stopped successfully.")
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		gracefulStop()
		close(shutdownDone)
	}()

	listenHost := serverSettings.BindHost
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	dashboardScheme := "http"
	if tlsSettings.PanelHTTPS {
		dashboardScheme = "https"
	}
	log.Println("================================================================")
	// The dashboard URL carries the hidden admin namespace: the panel has not
	// lived at /dashboard since v2.1, and a banner that printed the retired
	// route would send the operator to a 404.
	log.Printf(" HyperDNS Dashboard : %s://%s/%s/dash/", dashboardScheme, net.JoinHostPort(listenHost, strconv.Itoa(serverSettings.WebPort)), serverSettings.AdminPath)
	log.Printf(" Standard DNS       : %s (UDP/TCP)", net.JoinHostPort(listenHost, strconv.Itoa(dnsSettings.Port)))
	log.Printf(" DNS-over-TLS (DoT) : %s (TCP/TLS)", net.JoinHostPort(listenHost, strconv.Itoa(dnsSettings.DoTPort)))
	log.Printf(" DNS-over-HTTPS     : https://%s/dns-query", net.JoinHostPort(listenHost, strconv.Itoa(dnsSettings.DoHPort)))
	if sniSettings.Enabled {
		log.Printf(" SNI Proxy Relays   : Ports %d (HTTP) and %d (HTTPS)", sniSettings.HTTPPort, sniSettings.HTTPSPort)
	} else {
		log.Printf(" SNI Proxy Relays   : disabled")
	}
	log.Println("================================================================")

	// Non-interactive mode: park until the signal goroutine completes the
	// graceful stop, then return through main so every defer — the traffic
	// flusher's final flush and db.Close among them — runs in its intended
	// order. os.Exit here would skip them, which is the original defect.
	<-shutdownDone
}

// isLockTimeout reports whether err is bbolt's "database is locked" timeout —
// the shape a second process hits while the daemon holds the file.
func isLockTimeout(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") && strings.Contains(msg, "database")
}

// stdinIsInteractive reports whether f is a console a human could answer the
// menu on.
//
// The test used to be `fi.Mode()&os.ModeCharDevice != 0` and nothing more, which
// is wrong in exactly the case that matters: /dev/null is a character device too.
// It is what `docker run -d`, `docker compose up -d`, cron, and systemd's default
// StandardInput=null all hand a process, so all of them started the interactive
// console, hit EOF on the first prompt and exited. The container in CI came up
// cleanly, printed the menu, and was gone inside a second — with the resolver,
// DoT, DoH, the relay and the dashboard inside it.
//
// os.SameFile compares device and inode on Unix, so /dev/null is caught however
// it was opened. On Windows the handle-based stat carries no path for SameFile to
// re-open, so it answers false there and a NUL stdin would still read as
// interactive; that is the safe direction (a desktop console keeps its menu), and
// no HyperDNS service runs headless on Windows.
// controlPresetSource adapts the preset-updater for the control socket: the
// boundary returns DTOs, so a network failure surfaces as LastError text rather
// than a wrapped error type crossing the socket.
type controlPresetSource struct {
	updater *presetupd.Updater
}

func (s controlPresetSource) UpdatePresets(ctx context.Context) control.UpdatePresetsResult {
	res, err := s.updater.Apply(ctx)
	if err != nil {
		return control.UpdatePresetsResult{LastError: err.Error()}
	}
	out := control.UpdatePresetsResult{Message: res.Message}
	if res.Applied != nil {
		out.Applied = len(res.Applied)
	}
	return out
}

func stdinIsInteractive(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	// Pipes, regular files and sockets: `echo 1 | hyperdns`, `hyperdns < answers`.
	if fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if devNull, err := os.Stat(os.DevNull); err == nil && os.SameFile(fi, devNull) {
		return false
	}
	return true
}

// exampleConfigPasswordPlaceholder is the admin password shipped in the repository's
// public config.example.json. Anyone can read it, so it must never survive as a
// working login — see the guard in main().
const exampleConfigPasswordPlaceholder = "CHANGE-ME-BEFORE-FIRST-RUN"

// generateInitialPassword returns a random admin password for a first run where
// neither config.json nor the database supplied one. crypto/rand only: a
// predictable admin password is no better than no password at all.
//
// The error is discarded because crypto/rand.Read is documented never to return
// one — it fills b entirely or crashes the process — and this file targets Go 1.26.
// The check that used to be here was a log.Fatalf on a branch nothing could reach,
// which read as "this can fail" to everyone after. database.GenerateUUID already
// ignores it for the same reason.
func generateInitialPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ensureAPIKey fills in a missing master API key and reports whether it did.
//
// Both authentication paths refuse to match against an empty stored key, and
// they have to: comparing a caller's credential against "" would otherwise
// authorise everybody. The consequence was that an install whose key was blank
// answered 401 to every REST call, while Settings showed an empty field and
// nothing in the log connected the two — a missing key and a wrong key were
// indistinguishable from the outside.
//
// The state is anticipated rather than hypothetical: the installers' seeder
// exists to repair exactly it (`if "api_key" not in data["server"] or not
// data["server"]["api_key"]`), and a hand-written config.json can arrive with
// the field present and blank.
//
// Only emptiness is repaired. A key that is merely short or predictable is left
// alone, because replacing one would revoke a credential the operator chose and
// may have distributed — the same reason a legacy admin password keeps working.
func ensureAPIKey(s *database.ServerSettings) bool {
	if s == nil || s.APIKey != "" {
		return false
	}
	s.APIKey = crypto.GenerateAPIKey()
	log.Printf("[Main] No master API key was configured; generated one. Read it from Settings, the console's option 7, or GET /api/v1/api-key.")
	return true
}

// ensureAdminPath fills in the hidden admin path when the record has none, and
// reports whether it changed anything.
//
// An empty path means the record predates v2.1 (or is a genuine first run), so
// one is generated and the operator is told to save it; it is persisted in the
// same pass that writes the settings back. A path that is already present is
// left exactly as it is, so restarts — which reload the stored path — are
// idempotent and the operator's bookmark keeps working. Only emptiness is
// repaired, never a path the operator may have deliberately regenerated, just as
// ensureAPIKey never replaces a key the operator chose.
func ensureAdminPath(s *database.ServerSettings) bool {
	if s == nil || s.AdminPath != "" {
		return false
	}
	s.AdminPath = internalWeb.GenerateAdminPath()
	return true
}

// migrateAdminPassword replaces a plaintext admin password with a PBKDF2 hash,
// and re-hashes one that was stored at a weaker cost. It reports whether it
// changed anything.
//
// This is the automatic, non-destructive migration required for the live server:
// nothing else in the record is touched, the operator's existing password keeps
// working, and no action is needed on their part. An already-hashed value at the
// current cost is left exactly as it is, so restarts are idempotent.
//
// A failure to hash is deliberately not fatal. Refusing to start would take a
// working resolver offline over a storage-format upgrade; the plaintext still
// authenticates, so the daemon keeps serving and complains loudly instead.
func migrateAdminPassword(s *database.ServerSettings) bool {
	if s == nil || s.AdminPassword == "" {
		return false
	}

	if crypto.IsPasswordHash(s.AdminPassword) {
		if !crypto.NeedsRehash(s.AdminPassword) {
			return false
		}
		// The plaintext is not recoverable from a hash, so an under-cost hash can
		// only be upgraded the next time the operator types the password. Say so
		// rather than pretending it was handled.
		log.Printf("[Main] Notice: the stored admin password hash uses an older work factor; it will be upgraded next time the password is changed.")
		return false
	}

	// Evaluate strength while the plaintext is still available — after hashing,
	// this can never be determined again.
	weak := crypto.IsWeakPassword(s.AdminUsername, s.AdminPassword)

	hashed, err := crypto.HashPassword(s.AdminPassword)
	if err != nil {
		log.Printf("[Main] Warning: could not hash the admin password (%v); it stays in plaintext for now.", err)
		return false
	}

	s.AdminPassword = hashed
	s.AdminPasswordWeak = weak
	log.Printf("[Main] Admin password converted to a PBKDF2-SHA256 hash; the plaintext is no longer stored.")
	if weak {
		log.Printf("[Main] Warning: that password does not meet the minimum policy (%d+ characters, not a common word). Change it in Settings.", crypto.MinPasswordLength)
	}
	return true
}

// checkVersionDrift logs a warning when a version.json next to the binary or in
// the working directory does not match the version this binary was built with.
func checkVersionDrift(workDir string) {
	candidates := []string{
		filepath.Join(workDir, "version.json"),
		"version.json",
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := version.CheckDiskFile(data); err != nil {
			if vd, ok := err.(*version.DriftError); ok {
				log.Printf("[Main] ⚠ %v", vd)
			} else {
				log.Printf("[Main] ⚠ version.json check: %v", err)
			}
		}
		break
	}
}

// loadPersistedRules re-applies dashboard policy toggles and custom rule lists
// that were saved in the policies bucket, so they survive daemon restarts.
func loadPersistedRules(db *database.DB, m *matcher.Matcher) {
	if db == nil || m == nil {
		return
	}
	policies, err := db.ListPolicies()
	if err != nil {
		return
	}

	var customProxied, customBlocked, customDirect []string
	customRecords := map[string]string{}
	applied := 0

	for _, p := range policies {
		switch p.Key {
		case "custom_proxied":
			customProxied = p.CustomDomains
		case "custom_blocked":
			customBlocked = p.CustomDomains
		case "custom_direct":
			customDirect = p.CustomDomains
		case "custom_records":
			for _, entry := range p.CustomDomains {
				if d, ip, ok := strings.Cut(entry, "="); ok {
					customRecords[strings.TrimSpace(d)] = strings.TrimSpace(ip)
				}
			}
		default:
			if presetName, ok := matcher.PresetRuleKeys[p.Key]; ok {
				m.SetRuleEnabled(presetName, p.Enabled)
				applied++
			}
		}
	}

	m.SetCustomRules(customProxied, customBlocked, customDirect, customRecords)
	log.Printf("[Main] Restored %d policy toggle(s) and custom rule lists from database", applied)
}

// detectPublicIP probes well-known echo services for this host's public IPv4.
// Bounded by a total budget so a hung endpoint cannot delay daemon start.
func detectPublicIP() string {
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for _, ep := range endpoints {
		if time.Now().After(deadline) {
			break
		}
		resp, err := client.Get(ep)
		if err != nil {
			continue
		}
		buf, readErr := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		ipStr := strings.TrimSpace(string(buf))
		if parsed := net.ParseIP(ipStr); parsed != nil && parsed.To4() != nil && !parsed.IsLoopback() && !parsed.IsPrivate() {
			return ipStr
		}
	}
	return ""
}

// isPlaceholderPublicIP reports whether the configured public IP is a value that
// cannot work for DNS-based redirection (unset, loopback, wildcard, sample).
func isPlaceholderPublicIP(ip string) bool {
	switch strings.TrimSpace(strings.ToLower(ip)) {
	case "", "127.0.0.1", "0.0.0.0", "localhost", "::1", "example.com", "your.server.ip":
		return true
	}
	return false
}
