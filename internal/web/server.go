package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"hyperdns/internal/config"
	"hyperdns/internal/diagnostics"
	"hyperdns/internal/dns"
	"hyperdns/internal/rules"
)

type WebServer struct {
	cfg          *config.Config
	configPath   string
	matcher      *rules.Matcher
	cache        *dns.Cache
	upstreams    *dns.UpstreamPool
	dnsHandler   *dns.Handler
	dohHandler   *dns.DoHHandler
	streamHub    *StreamHub
	stats        *StatsCollector
	staticFS     fs.FS
	auth         *AuthManager
	httpServer   *http.Server
	rateLimitMu  sync.Mutex
	failedLogins map[string][]time.Time
}

func NewWebServer(
	cfg *config.Config,
	configPath string,
	matcher *rules.Matcher,
	cache *dns.Cache,
	upstreams *dns.UpstreamPool,
	dnsHandler *dns.Handler,
	stats *StatsCollector,
	staticFS fs.FS,
) *WebServer {
	return &WebServer{
		cfg:          cfg,
		configPath:   configPath,
		matcher:      matcher,
		cache:        cache,
		upstreams:    upstreams,
		dnsHandler:   dnsHandler,
		dohHandler:   dns.NewDoHHandler(dnsHandler),
		streamHub:    NewStreamHub(dnsHandler.GetLogChannel(), 100),
		stats:        stats,
		staticFS:     staticFS,
		auth:         NewAuthManager(cfg),
		failedLogins: make(map[string][]time.Time),
	}
}

func (ws *WebServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return ws.auth.RequireAuth(next)
}

func (ws *WebServer) BuildHandler() http.Handler {
	mux := http.NewServeMux()

	// REST API Endpoints
	mux.HandleFunc("/api/auth/login", ws.handleLogin)
	mux.HandleFunc("/api/auth/me", ws.requireAuth(ws.handleMe))
	mux.HandleFunc("/api/stats", ws.requireAuth(ws.handleStats))
	mux.HandleFunc("/api/config", ws.requireAuth(ws.handleGetConfig))
	mux.HandleFunc("/api/config/rules", ws.requireAuth(ws.handleUpdateRules))
	mux.HandleFunc("/api/config/server", ws.requireAuth(ws.handleUpdateServer))
	mux.HandleFunc("/api/config/access", ws.requireAuth(ws.handleUpdateAccess))
	mux.HandleFunc("/api/upstreams/add", ws.requireAuth(ws.handleAddUpstream))
	mux.HandleFunc("/api/upstreams/delete", ws.requireAuth(ws.handleDeleteUpstream))
	mux.HandleFunc("/api/cache/flush", ws.requireAuth(ws.handleFlushCache))
	mux.HandleFunc("/api/benchmark", ws.requireAuth(ws.handleBenchmark))
	mux.HandleFunc("/api/diagnostics/run", ws.requireAuth(ws.handleRunDiagnostics))
	mux.HandleFunc("/api/server/restart", ws.requireAuth(ws.handleRestartEngine))
	mux.HandleFunc("/api/tls/issue", ws.requireAuth(ws.handleIssueTLS))
	mux.Handle("/api/stream/queries", ws.streamHub)

	// Client Management APIs (Whitelisting & Subscriptions)
	mux.HandleFunc("/api/clients", ws.requireAuth(ws.handleGetClients))
	mux.HandleFunc("/api/clients/add", ws.requireAuth(ws.handleAddClient))
	mux.HandleFunc("/api/clients/delete", ws.requireAuth(ws.handleDeleteClient))
	mux.HandleFunc("/api/clients/toggle", ws.requireAuth(ws.handleToggleClient))
	mux.HandleFunc("/api/clients/add_ip", ws.requireAuth(ws.handleAddClientIP))
	mux.HandleFunc("/api/clients/remove_ip", ws.requireAuth(ws.handleRemoveClientIP))
	mux.HandleFunc("/api/clients/renew", ws.requireAuth(ws.handleRenewClient))
	mux.HandleFunc("/api/access/mode", ws.requireAuth(ws.handleToggleAccessMode))

	// =========================================================================
	// Comprehensive REST API v1 (Developer, Bot & Billing Gateway)
	// =========================================================================
	mux.HandleFunc("/api/v1/status", ws.requireAuth(ws.handleAPIv1Status))
	mux.HandleFunc("/api/v1/diagnostics", ws.requireAuth(ws.handleAPIv1Diagnostics))
	mux.HandleFunc("/api/v1/cache/flush", ws.requireAuth(ws.handleAPIv1CacheFlush))
	mux.HandleFunc("/api/v1/system/restart", ws.requireAuth(ws.handleAPIv1Restart))
	mux.HandleFunc("/api/v1/clients", ws.requireAuth(ws.handleAPIv1Clients))
	mux.HandleFunc("/api/v1/clients/", ws.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/ip") {
			ws.handleAPIv1ClientIP(w, r)
		} else if strings.HasSuffix(path, "/renew") {
			ws.handleAPIv1ClientRenew(w, r)
		} else if strings.HasSuffix(path, "/toggle") {
			ws.handleAPIv1ClientToggle(w, r)
		} else if strings.HasPrefix(path, "/api/v1/clients/lookup") {
			ws.handleAPIv1ClientLookup(w, r)
		} else {
			ws.handleAPIv1ClientByID(w, r)
		}
	}))
	mux.HandleFunc("/api/v1/rules", ws.requireAuth(ws.handleAPIv1Rules))
	mux.HandleFunc("/api/v1/upstreams", ws.requireAuth(ws.handleAPIv1Upstreams))
	mux.HandleFunc("/api/v1/access", ws.requireAuth(ws.handleAPIv1Access))
	mux.HandleFunc("/api/v1/api-key", ws.requireAuth(ws.handleAPIv1APIKey))
	mux.HandleFunc("/api/v1/docs", ws.handleAPIv1Docs)
	mux.HandleFunc("/docs", ws.handleAPIv1Docs)

	// Dedicated Handlers
	mux.HandleFunc("/ip/", ws.handleAutoRegisterIP)
	mux.HandleFunc("/matrix", ws.handleMatrix)
	mux.HandleFunc("/dashboard", ws.handleDashboard)
	mux.HandleFunc("/panel", ws.handleDashboard)

	// DoH Endpoint
	mux.Handle("/dns-query", ws.dohHandler)

	// Root Handler (Matrix on /, Assets on /css, /js)
	mux.HandleFunc("/", ws.handleRoot)

	// Wrap with OWASP Security Headers Middleware
	return ws.securityMiddleware(mux)
}

func (ws *WebServer) Start() error {
	addr := fmt.Sprintf("%s:%d", ws.cfg.Server.BindHost, ws.cfg.Server.WebPort)
	if ws.cfg.Server.BindHost == "" {
		addr = fmt.Sprintf("0.0.0.0:%d", ws.cfg.Server.WebPort)
	}

	ws.httpServer = &http.Server{
		Addr:         addr,
		Handler:      ws.BuildHandler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("[Web] HTTP Dashboard running at http://%s/dashboard (and http://%s/)", addr, addr)
		if err := ws.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Web] Server error: %v", err)
		}
	}()

	return nil
}

func (ws *WebServer) Stop() {
	if ws.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ws.httpServer.Shutdown(ctx)
	}
}

// OWASP Security Headers & CORS Middleware
func (ws *WebServer) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; font-src * data:; img-src * data: blob:; connect-src * ws: wss:;")
		next.ServeHTTP(w, r)
	})
}

// handleDashboard serves index.html (the Dashboard Controller)
func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	fileData, err := fs.ReadFile(ws.staticFS, "index.html")
	if err != nil {
		http.Error(w, "Dashboard file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(fileData)
}

// handleRoot serves Matrix on /, Dashboard on /dashboard or static assets
func (ws *WebServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "" {
		ws.handleMatrix(w, r)
		return
	}

	filePath := strings.TrimPrefix(r.URL.Path, "/")
	fileData, err := fs.ReadFile(ws.staticFS, filePath)
	if err != nil {
		if strings.HasPrefix(r.URL.Path, "/dashboard") || strings.HasPrefix(r.URL.Path, "/panel") {
			ws.handleDashboard(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}

	if strings.HasSuffix(filePath, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	} else if strings.HasSuffix(filePath, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	} else if strings.HasSuffix(filePath, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
	} else if strings.HasSuffix(filePath, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}

	_, _ = w.Write(fileData)
}

// API Handlers
func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	// Brute-force rate limiting check
	ws.rateLimitMu.Lock()
	now := time.Now()
	recentAttempts := make([]time.Time, 0)
	for _, t := range ws.failedLogins[clientIP] {
		if now.Sub(t) < 1*time.Minute {
			recentAttempts = append(recentAttempts, t)
		}
	}
	ws.failedLogins[clientIP] = recentAttempts

	if len(recentAttempts) >= 10 {
		ws.rateLimitMu.Unlock()
		http.Error(w, "Too many login attempts. Please wait 1 minute.", http.StatusTooManyRequests)
		return
	}
	ws.rateLimitMu.Unlock()

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Constant time compare to prevent timing side-channel attacks
	token, ok := ws.auth.Authenticate(req.Username, req.Password)
	if !ok {
		ws.rateLimitMu.Lock()
		ws.failedLogins[clientIP] = append(ws.failedLogins[clientIP], now)
		ws.rateLimitMu.Unlock()
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":             true,
		"token":               token,
		"user":                req.Username,
		"is_default_password": ws.cfg.IsDefaultPassword(),
	})
}

func (ws *WebServer) handleMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated":       true,
		"username":            ws.cfg.Server.AdminUsername,
		"public_ip":           ws.cfg.Server.PublicIP,
		"is_default_password": ws.cfg.IsDefaultPassword(),
	})
}

func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	st := ws.stats.GetSystemStats()
	st.Upstreams = ws.upstreams.GetStats()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (ws *WebServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ws.cfg)
}

func (ws *WebServer) handleUpdateRules(w http.ResponseWriter, r *http.Request) {
	var rulesCfg config.RulesConfig
	if err := json.NewDecoder(r.Body).Decode(&rulesCfg); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	ws.cfg.Rules = rulesCfg
	ws.matcher.Rebuild(ws.cfg)
	_ = ws.cfg.Save(ws.configPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	var srv struct {
		AdminUsername string `json:"admin_username"`
		AdminPassword string `json:"admin_password"`
		PublicIP      string `json:"public_ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&srv); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if srv.AdminUsername != "" {
		ws.cfg.Server.AdminUsername = srv.AdminUsername
	}
	if srv.AdminPassword != "" {
		ws.cfg.Server.AdminPassword = srv.AdminPassword
	}
	if srv.PublicIP != "" {
		ws.cfg.Server.PublicIP = srv.PublicIP
	}

	_ = ws.cfg.Save(ws.configPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleUpdateAccess(w http.ResponseWriter, r *http.Request) {
	var acc config.AccessConfig
	if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	ws.cfg.Access = acc
	_ = ws.cfg.Save(ws.configPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleAddUpstream(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Address == "" {
		http.Error(w, "Invalid address", http.StatusBadRequest)
		return
	}

	addr := strings.TrimSpace(req.Address)
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	// Add to upstreams list
	for _, u := range ws.cfg.DNS.Upstreams {
		if u == addr {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
	}

	ws.cfg.DNS.Upstreams = append(ws.cfg.DNS.Upstreams, addr)
	ws.upstreams.SetUpstreams(ws.cfg.DNS.Upstreams)
	_ = ws.cfg.Save(ws.configPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Address == "" {
		http.Error(w, "Invalid address", http.StatusBadRequest)
		return
	}

	filtered := make([]string, 0)
	for _, u := range ws.cfg.DNS.Upstreams {
		if u != req.Address {
			filtered = append(filtered, u)
		}
	}
	if len(filtered) == 0 {
		filtered = []string{"1.1.1.1:53"}
	}

	ws.cfg.DNS.Upstreams = filtered
	ws.upstreams.SetUpstreams(ws.cfg.DNS.Upstreams)
	_ = ws.cfg.Save(ws.configPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleFlushCache(w http.ResponseWriter, r *http.Request) {
	ws.cache.Flush()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	go ws.upstreams.BenchmarkAll()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (ws *WebServer) handleRunDiagnostics(w http.ResponseWriter, r *http.Request) {
	report := diagnostics.RunDiagnostics()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func (ws *WebServer) handleRestartEngine(w http.ResponseWriter, r *http.Request) {
	ws.cache.Flush()
	ws.matcher.Rebuild(ws.cfg)
	go ws.upstreams.BenchmarkAll()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "HyperDNS Engine restarted & all rules reloaded successfully!",
	})
}

func (ws *WebServer) handleIssueTLS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Email  string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	ws.cfg.TLS.Domain = req.Domain
	if req.Email != "" {
		ws.cfg.TLS.Email = req.Email
	}
	_ = ws.cfg.Save(ws.configPath)

	// Execute ssl_issue.sh if on Linux
	go func(dom, em string) {
		cmd := exec.Command("bash", "scripts/ssl_issue.sh", dom, em)
		_ = cmd.Run()
	}(req.Domain, req.Email)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "SSL Certificate issuance started in background. Certificates will be saved to certs/cert.pem",
	})
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + (n % 10))
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
