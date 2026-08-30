package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"hyperdns/internal/config"
	"hyperdns/internal/diagnostics"
)

// API Standard Response Envelope
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp int64       `json:"timestamp"`
}

func writeAPIJSON(w http.ResponseWriter, statusCode int, success bool, data interface{}, errMsg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	resp := APIResponse{
		Success:   success,
		Data:      data,
		Error:     errMsg,
		Timestamp: time.Now().Unix(),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// -------------------------------------------------------------
// 1. SYSTEM & STATUS APIs
// -------------------------------------------------------------

// GET /api/v1/status - Comprehensive System & Engine Telemetry
func (ws *WebServer) handleAPIv1Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
		return
	}

	clients := ws.cfg.GetClients()
	activeClients := 0
	expiredClients := 0
	now := time.Now()
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
			expiredClients++
		} else {
			activeClients++
		}
	}

	sysStats := ws.stats.GetSystemStats()

	resp := map[string]interface{}{
		"version":        "1.2.0-beta",
		"public_ip":      ws.cfg.Server.PublicIP,
		"bind_host":      ws.cfg.Server.BindHost,
		"dns_port":       ws.cfg.DNS.Port,
		"doh_port":       ws.cfg.DNS.DoHPort,
		"dot_port":       ws.cfg.DNS.DoTPort,
		"web_port":       ws.cfg.Server.WebPort,
		"allow_all_mode": ws.cfg.Access.AllowAll,
		"clients": map[string]interface{}{
			"total":   len(clients),
			"active":  activeClients,
			"expired": expiredClients,
		},
		"telemetry": map[string]interface{}{
			"qps":             sysStats.QPS,
			"total_queries":   sysStats.TotalQueries,
			"cache_hit_ratio": sysStats.CacheHitRatio,
			"cached_records":  ws.cache.Count(),
			"active_conns":    sysStats.ActiveProxyConns,
			"uptime_seconds":  sysStats.UptimeSeconds,
			"memory_mb":       sysStats.AllocMemoryMB,
			"cpu_percent":     sysStats.CPUUsagePercent,
			"goroutines":      sysStats.NumGoroutines,
		},
		"upstreams": ws.cfg.DNS.Upstreams,
	}

	writeAPIJSON(w, http.StatusOK, true, resp, "")
}

// GET /api/v1/diagnostics - Real-time Gaming Latency Benchmark
func (ws *WebServer) handleAPIv1Diagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
		return
	}

	res := diagnostics.RunDiagnostics()
	writeAPIJSON(w, http.StatusOK, true, res, "")
}

// POST /api/v1/cache/flush - Flush In-Memory DNS Cache
func (ws *WebServer) handleAPIv1CacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
		return
	}

	ws.cache.Flush()
	writeAPIJSON(w, http.StatusOK, true, map[string]string{"message": "DNS cache cleared successfully"}, "")
}

// POST /api/v1/system/restart - Gracefully restart the HyperDNS engine
func (ws *WebServer) handleAPIv1Restart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
		return
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()

	writeAPIJSON(w, http.StatusOK, true, map[string]string{"message": "HyperDNS engine restarting in background"}, "")
}

// -------------------------------------------------------------
// 2. ACCOUNTING & CLIENT MANAGEMENT APIs
// -------------------------------------------------------------

// GET /api/v1/clients & POST /api/v1/clients
func (ws *WebServer) handleAPIv1Clients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		statusFilter := strings.ToLower(r.URL.Query().Get("status"))
		clients := ws.cfg.GetClients()
		now := time.Now()

		filtered := make([]map[string]interface{}, 0, len(clients))
		for _, c := range clients {
			isExpired := !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt)
			status := "active"
			if !c.Enabled {
				status = "disabled"
			} else if isExpired {
				status = "expired"
			}

			if statusFilter != "" && status != statusFilter {
				continue
			}

			regURL := fmt.Sprintf("%s/ip/%s", ws.detectOrigin(r), c.Token)
			var singleIP string
			if len(c.AllowedIPs) > 0 {
				singleIP = c.AllowedIPs[0]
			}

			filtered = append(filtered, map[string]interface{}{
				"id":            c.ID,
				"name":          c.Name,
				"token":         c.Token,
				"registered_ip": singleIP,
				"status":        status,
				"enabled":       c.Enabled,
				"is_expired":    isExpired,
				"expires_at":    c.ExpiresAt,
				"created_at":    c.CreatedAt,
				"last_seen":     c.LastSeen,
				"total_queries": c.TotalQueries,
				"register_url":  regURL,
			})
		}

		writeAPIJSON(w, http.StatusOK, true, map[string]interface{}{
			"count":   len(filtered),
			"clients": filtered,
		}, "")

	case http.MethodPost:
		var req struct {
			Name        string `json:"name"`
			ExpiresDays int    `json:"expires_days"`
			InitialIP   string `json:"initial_ip"`
			Token       string `json:"token,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIJSON(w, http.StatusBadRequest, false, nil, "Invalid JSON body")
			return
		}

		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = "Client " + time.Now().Format("01-02 15:04")
		}

		now := time.Now()
		var expiresAt time.Time
		if req.ExpiresDays != 0 {
			expiresAt = now.Add(time.Duration(req.ExpiresDays) * 24 * time.Hour)
		}

		tok := strings.TrimSpace(req.Token)
		if tok == "" {
			tok = generateToken(8)
		}

		allowedIPs := []string{}
		if ip := strings.TrimSpace(req.InitialIP); ip != "" {
			if net.ParseIP(ip) == nil {
				writeAPIJSON(w, http.StatusBadRequest, false, nil, "Invalid IP address format")
				return
			}
			allowedIPs = append(allowedIPs, ip)
		}

		client := config.Client{
			ID:           generateNumericID(),
			Name:         name,
			Token:        tok,
			AllowedIPs:   allowedIPs,
			ExpiresAt:    expiresAt,
			CreatedAt:    now,
			LastSeen:     now,
			TotalQueries: 0,
			Enabled:      true,
		}

		ws.cfg.AddClient(client)
		_ = ws.cfg.Save(ws.configPath)

		regURL := fmt.Sprintf("%s/ip/%s", ws.detectOrigin(r), client.Token)
		res := map[string]interface{}{
			"client":       client,
			"register_url": regURL,
		}
		writeAPIJSON(w, http.StatusCreated, true, res, "")

	default:
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
	}
}

// Routes: /api/v1/clients/{id} (GET, DELETE)
func (ws *WebServer) handleAPIv1ClientByID(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /api/v1/clients/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeAPIJSON(w, http.StatusBadRequest, false, nil, "Missing client ID")
		return
	}
	clientID := parts[0]

	switch r.Method {
	case http.MethodGet:
		clients := ws.cfg.GetClients()
		for _, c := range clients {
			if c.ID == clientID {
				now := time.Now()
				isExpired := !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt)
				var singleIP string
				if len(c.AllowedIPs) > 0 {
					singleIP = c.AllowedIPs[0]
				}
				writeAPIJSON(w, http.StatusOK, true, map[string]interface{}{
					"id":            c.ID,
					"name":          c.Name,
					"token":         c.Token,
					"registered_ip": singleIP,
					"enabled":       c.Enabled,
					"is_expired":    isExpired,
					"expires_at":    c.ExpiresAt,
					"created_at":    c.CreatedAt,
					"last_seen":     c.LastSeen,
					"total_queries": c.TotalQueries,
					"register_url":  fmt.Sprintf("%s/ip/%s", ws.detectOrigin(r), c.Token),
				}, "")
				return
			}
		}
		writeAPIJSON(w, http.StatusNotFound, false, nil, "Client not found")

	case http.MethodDelete:
		if ws.cfg.DeleteClient(clientID) {
			_ = ws.cfg.Save(ws.configPath)
			writeAPIJSON(w, http.StatusOK, true, map[string]string{"message": "Client deleted"}, "")
		} else {
			writeAPIJSON(w, http.StatusNotFound, false, nil, "Client not found")
		}

	default:
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
	}
}

// POST /api/v1/clients/{id}/ip & DELETE /api/v1/clients/{id}/ip (Strict 1-IP limit)
func (ws *WebServer) handleAPIv1ClientIP(w http.ResponseWriter, r *http.Request) {
	// Extract ID: /api/v1/clients/{id}/ip
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	clientID := strings.TrimSuffix(path, "/ip")

	switch r.Method {
	case http.MethodPost:
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
			writeAPIJSON(w, http.StatusBadRequest, false, nil, "Missing or invalid IP in body")
			return
		}
		cleanIP := strings.TrimSpace(req.IP)
		if net.ParseIP(cleanIP) == nil {
			writeAPIJSON(w, http.StatusBadRequest, false, nil, "Invalid IP address format")
			return
		}

		if ws.cfg.AddClientIP(clientID, cleanIP) {
			_ = ws.cfg.Save(ws.configPath)
			writeAPIJSON(w, http.StatusOK, true, map[string]string{
				"id":            clientID,
				"registered_ip": cleanIP,
				"message":       "Client registered IP updated successfully (1-IP limit enforced)",
			}, "")
		} else {
			writeAPIJSON(w, http.StatusNotFound, false, nil, "Client not found")
		}

	case http.MethodDelete:
		clients := ws.cfg.GetClients()
		for _, c := range clients {
			if c.ID == clientID && len(c.AllowedIPs) > 0 {
				ws.cfg.RemoveClientIP(clientID, c.AllowedIPs[0])
				_ = ws.cfg.Save(ws.configPath)
				writeAPIJSON(w, http.StatusOK, true, map[string]string{"message": "Registered IP cleared"}, "")
				return
			}
		}
		writeAPIJSON(w, http.StatusOK, true, map[string]string{"message": "No registered IP to clear"}, "")

	default:
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
	}
}

// POST /api/v1/clients/{id}/renew - Extend client subscription
func (ws *WebServer) handleAPIv1ClientRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	clientID := strings.TrimSuffix(path, "/renew")

	var req struct {
		ExtendDays int `json:"extend_days"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.ExtendDays == 0 {
		req.ExtendDays = 30 // default 30 days
	}

	if ws.cfg.RenewClient(clientID, req.ExtendDays) {
		_ = ws.cfg.Save(ws.configPath)
		writeAPIJSON(w, http.StatusOK, true, map[string]interface{}{
			"id":          clientID,
			"extend_days": req.ExtendDays,
			"message":     "Subscription renewed successfully",
		}, "")
	} else {
		writeAPIJSON(w, http.StatusNotFound, false, nil, "Client not found")
	}
}

// POST /api/v1/clients/{id}/toggle - Enable / Disable client
func (ws *WebServer) handleAPIv1ClientToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	clientID := strings.TrimSuffix(path, "/toggle")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIJSON(w, http.StatusBadRequest, false, nil, "Invalid JSON body")
		return
	}

	if ws.cfg.ToggleClient(clientID, req.Enabled) {
		_ = ws.cfg.Save(ws.configPath)
		writeAPIJSON(w, http.StatusOK, true, map[string]interface{}{
			"id":      clientID,
			"enabled": req.Enabled,
		}, "")
	} else {
		writeAPIJSON(w, http.StatusNotFound, false, nil, "Client not found")
	}
}

// GET /api/v1/clients/lookup?ip=... or ?token=...
func (ws *WebServer) handleAPIv1ClientLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
		return
	}

	targetIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	targetToken := strings.TrimSpace(r.URL.Query().Get("token"))

	clients := ws.cfg.GetClients()
	now := time.Now()

	for _, c := range clients {
		match := false
		if targetToken != "" && c.Token == targetToken {
			match = true
		}
		if targetIP != "" {
			for _, ip := range c.AllowedIPs {
				if ip == targetIP {
					match = true
					break
				}
			}
		}

		if match {
			isExpired := !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt)
			var singleIP string
			if len(c.AllowedIPs) > 0 {
				singleIP = c.AllowedIPs[0]
			}
			writeAPIJSON(w, http.StatusOK, true, map[string]interface{}{
				"id":            c.ID,
				"name":          c.Name,
				"token":         c.Token,
				"registered_ip": singleIP,
				"enabled":       c.Enabled,
				"is_expired":    isExpired,
				"expires_at":    c.ExpiresAt,
				"register_url":  fmt.Sprintf("%s/ip/%s", ws.detectOrigin(r), c.Token),
			}, "")
			return
		}
	}

	writeAPIJSON(w, http.StatusNotFound, false, nil, "No matching client found")
}

// -------------------------------------------------------------
// 3. RULES & POLICIES APIs
// -------------------------------------------------------------

// GET /api/v1/rules & POST /api/v1/rules
func (ws *WebServer) handleAPIv1Rules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeAPIJSON(w, http.StatusOK, true, ws.cfg.Rules, "")

	case http.MethodPost:
		var req config.RulesConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIJSON(w, http.StatusBadRequest, false, nil, "Invalid JSON rules body")
			return
		}

		ws.cfg.Rules = req
		_ = ws.cfg.Save(ws.configPath)
		ws.matcher.Rebuild(ws.cfg)
		writeAPIJSON(w, http.StatusOK, true, ws.cfg.Rules, "")

	default:
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
	}
}

// -------------------------------------------------------------
// 4. UPSTREAMS & ACCESS MODE APIs
// -------------------------------------------------------------

// GET /api/v1/upstreams & POST /api/v1/upstreams & DELETE /api/v1/upstreams
func (ws *WebServer) handleAPIv1Upstreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeAPIJSON(w, http.StatusOK, true, map[string]interface{}{
			"upstreams":      ws.cfg.DNS.Upstreams,
			"fastest_racing": ws.cfg.DNS.FastestRacing,
		}, "")

	case http.MethodPost:
		var req struct {
			Upstream string `json:"upstream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Upstream == "" {
			writeAPIJSON(w, http.StatusBadRequest, false, nil, "Missing upstream address (e.g. 1.1.1.1:53)")
			return
		}
		up := strings.TrimSpace(req.Upstream)
		if !strings.Contains(up, ":") {
			up += ":53"
		}

		for _, u := range ws.cfg.DNS.Upstreams {
			if u == up {
				writeAPIJSON(w, http.StatusOK, true, ws.cfg.DNS.Upstreams, "Upstream already exists")
				return
			}
		}

		ws.cfg.DNS.Upstreams = append(ws.cfg.DNS.Upstreams, up)
		_ = ws.cfg.Save(ws.configPath)
		ws.upstreams.SetUpstreams(ws.cfg.DNS.Upstreams)
		writeAPIJSON(w, http.StatusCreated, true, ws.cfg.DNS.Upstreams, "")

	case http.MethodDelete:
		var req struct {
			Upstream string `json:"upstream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Upstream == "" {
			writeAPIJSON(w, http.StatusBadRequest, false, nil, "Missing upstream address to delete")
			return
		}

		target := strings.TrimSpace(req.Upstream)
		newUps := make([]string, 0, len(ws.cfg.DNS.Upstreams))
		for _, u := range ws.cfg.DNS.Upstreams {
			if u != target && u != target+":53" {
				newUps = append(newUps, u)
			}
		}
		ws.cfg.DNS.Upstreams = newUps
		_ = ws.cfg.Save(ws.configPath)
		ws.upstreams.SetUpstreams(ws.cfg.DNS.Upstreams)
		writeAPIJSON(w, http.StatusOK, true, ws.cfg.DNS.Upstreams, "")

	default:
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
	}
}

// GET /api/v1/access & POST /api/v1/access/mode
func (ws *WebServer) handleAPIv1Access(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeAPIJSON(w, http.StatusOK, true, map[string]interface{}{
			"allow_all":   ws.cfg.Access.AllowAll,
			"allowed_ips": ws.cfg.Access.AllowedIPs,
			"blocked_ips": ws.cfg.Access.BlockedIPs,
		}, "")

	case http.MethodPost:
		var req struct {
			AllowAll bool `json:"allow_all"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIJSON(w, http.StatusBadRequest, false, nil, "Invalid JSON body")
			return
		}
		ws.cfg.Access.AllowAll = req.AllowAll
		_ = ws.cfg.Save(ws.configPath)
		writeAPIJSON(w, http.StatusOK, true, map[string]bool{"allow_all": ws.cfg.Access.AllowAll}, "")

	default:
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
	}
}

// -------------------------------------------------------------
// 5. API KEY & DEVELOPER DOCUMENTATION APIs
// -------------------------------------------------------------

// GET /api/v1/api-key & POST /api/v1/api-key/regenerate
func (ws *WebServer) handleAPIv1APIKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeAPIJSON(w, http.StatusOK, true, map[string]string{
			"api_key": ws.cfg.Server.APIKey,
		}, "")

	case http.MethodPost:
		newKey := ws.cfg.RegenerateAPIKey()
		_ = ws.cfg.Save(ws.configPath)
		writeAPIJSON(w, http.StatusOK, true, map[string]string{
			"api_key": newKey,
			"message": "API key regenerated successfully",
		}, "")

	default:
		writeAPIJSON(w, http.StatusMethodNotAllowed, false, nil, "Method not allowed")
	}
}

func (ws *WebServer) detectOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

// GET /api/v1/docs - Interactive Developer API Documentation & Spec
func (ws *WebServer) handleAPIv1Docs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	apiKey := ws.cfg.Server.APIKey
	pubIP := ws.cfg.Server.PublicIP
	if pubIP == "" {
		pubIP = "YOUR_SERVER_IP"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>HyperDNS REST API Documentation (v1)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Chakra+Petch:wght@700&display=swap" rel="stylesheet">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #060913; color: #f8fafc; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    .heading { font-family: 'Chakra Petch', sans-serif; }
    .glass { background: rgba(13, 20, 38, 0.9); backdrop-filter: blur(16px); border: 1px solid rgba(56, 189, 248, 0.2); }
  </style>
</head>
<body class="p-6 md:p-12 max-w-5xl mx-auto space-y-8">
  
  <!-- Header -->
  <div class="glass p-6 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border border-cyan-500/30">
    <div>
      <h1 class="text-2xl font-bold heading text-cyan-400">⚡ HyperDNS Developer & Bot REST API (v1)</h1>
      <p class="text-sm text-slate-400 mt-1">Complete REST API gateway for Telegram/Discord bots, billing systems, and client accounting.</p>
    </div>
    <div class="text-right bg-slate-950/80 p-3 rounded-xl border border-slate-800">
      <div class="text-[11px] text-slate-500 uppercase tracking-widest font-bold">Your API Key</div>
      <div class="mono text-xs text-amber-300 font-bold select-all">%s</div>
    </div>
  </div>

  <!-- Authentication Section -->
  <div class="glass p-6 rounded-2xl space-y-4">
    <h2 class="text-lg font-bold text-white heading flex items-center gap-2">
      <span class="w-3 h-3 rounded-full bg-emerald-400"></span> Authentication
    </h2>
    <p class="text-sm text-slate-300">All requests must include your API Key in the headers or query string:</p>
    <div class="bg-slate-950 p-4 rounded-xl mono text-xs text-cyan-300 space-y-1">
      <div><span class="text-slate-500"># Header 1:</span> X-API-Key: %s</div>
      <div><span class="text-slate-500"># Header 2:</span> Authorization: Bearer %s</div>
      <div><span class="text-slate-500"># Query Param:</span> https://%s:8080/api/v1/status?api_key=%s</div>
    </div>
  </div>

  <!-- Endpoints Overview -->
  <div class="glass p-6 rounded-2xl space-y-6">
    <h2 class="text-lg font-bold text-white heading">📌 API Endpoints Reference</h2>

    <!-- Endpoint Item -->
    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-xs mono">GET</span>
        <span class="mono text-sm text-slate-200">/api/v1/status</span>
        <span class="text-xs text-slate-400">— System telemetry, QPS, cache hit ratio, client counts</span>
      </div>
    </div>

    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-xs mono">GET</span>
        <span class="mono text-sm text-slate-200">/api/v1/clients</span>
        <span class="text-xs text-slate-400">— List all clients (filter: ?status=active|expired|disabled)</span>
      </div>
    </div>

    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-xs mono">POST</span>
        <span class="mono text-sm text-slate-200">/api/v1/clients</span>
        <span class="text-xs text-slate-400">— Create client ({"name":"Gamer","expires_days":30,"initial_ip":"1.1.1.1"})</span>
      </div>
    </div>

    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-xs mono">POST</span>
        <span class="mono text-sm text-slate-200">/api/v1/clients/{id}/ip</span>
        <span class="text-xs text-slate-400">— Set/replace client registered IP (strict 1-IP limit)</span>
      </div>
    </div>

    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-xs mono">POST</span>
        <span class="mono text-sm text-slate-200">/api/v1/clients/{id}/renew</span>
        <span class="text-xs text-slate-400">— Extend client subscription ({"extend_days":30})</span>
      </div>
    </div>

    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-bold text-xs mono">DELETE</span>
        <span class="mono text-sm text-slate-200">/api/v1/clients/{id}</span>
        <span class="text-xs text-slate-400">— Delete a client account</span>
      </div>
    </div>

    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-xs mono">GET</span>
        <span class="mono text-sm text-slate-200">/api/v1/clients/lookup</span>
        <span class="text-xs text-slate-400">— Search client by IP (?ip=1.1.1.1) or Token (?token=xyz)</span>
      </div>
    </div>

    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-xs mono">GET</span>
        <span class="mono text-sm text-slate-200">/api/v1/rules</span>
        <span class="text-xs text-slate-400">— List all 18+ gaming and security presets</span>
      </div>
    </div>

    <div class="space-y-2 border-b border-slate-800 pb-4">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-xs mono">GET</span>
        <span class="mono text-sm text-slate-200">/api/v1/diagnostics</span>
        <span class="text-xs text-slate-400">— Live latency test across all games</span>
      </div>
    </div>

    <div class="space-y-2">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-xs mono">POST</span>
        <span class="mono text-sm text-slate-200">/api/v1/cache/flush</span>
        <span class="text-xs text-slate-400">— Clear DNS cache in RAM</span>
      </div>
    </div>
  </div>

  <!-- Telegram Bot Integration Example -->
  <div class="glass p-6 rounded-2xl space-y-4">
    <h2 class="text-lg font-bold text-purple-400 heading">🤖 Telegram Bot Integration Snippet (Python)</h2>
    <pre class="bg-slate-950 p-4 rounded-xl mono text-xs text-slate-300 overflow-x-auto">
import requests

API_URL = "http://%s:8080/api/v1"
HEADERS = {"X-API-Key": "%s"}

# Create client account when a user buys a plan
def create_gamer_account(user_name, days=30):
    resp = requests.post(
        f"{API_URL}/clients",
        headers=HEADERS,
        json={"name": user_name, "expires_days": days}
    ).json()
    
    if resp.get("success"):
        client = resp["data"]["client"]
        reg_link = resp["data"]["register_url"]
        return f"✅ Your SmartDNS is ready!\nRegister IP: {reg_link}\nExpire: {client['expires_at']}"
    return "Error creating account"
    </pre>
  </div>

</body>
</html>`, apiKey, apiKey, apiKey, pubIP, apiKey, pubIP, apiKey)

	_, _ = w.Write([]byte(html))
}
