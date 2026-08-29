package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"hyperdns/internal/config"
)

// GenerateRandomToken generates a cryptographic hex token
func generateToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateNumericID generates a random 9-digit client ID
func generateNumericID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	num := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return fmt.Sprintf("%09d", num%900000000+100000000)
}

// Get Client Public IP from Request
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// GET /api/clients - List all clients and access mode
func (ws *WebServer) handleGetClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clients := ws.cfg.GetClients()
	resp := map[string]interface{}{
		"allow_all": ws.cfg.Access.AllowAll,
		"public_ip": ws.cfg.Server.PublicIP,
		"web_port":  ws.cfg.Server.WebPort,
		"clients":   clients,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// POST /api/clients/add - Create a new client
func (ws *WebServer) handleAddClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name        string `json:"name"`
		ExpiresDays int    `json:"expires_days"`
		InitialIP   string `json:"initial_ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Client " + time.Now().Format("01-02 15:04")
	}

	now := time.Now()
	var expiresAt time.Time
	if req.ExpiresDays > 0 {
		expiresAt = now.Add(time.Duration(req.ExpiresDays) * 24 * time.Hour)
	}

	allowedIPs := []string{}
	if initialIP := strings.TrimSpace(req.InitialIP); initialIP != "" {
		allowedIPs = append(allowedIPs, initialIP)
	}

	client := config.Client{
		ID:           generateNumericID(),
		Name:         name,
		Token:        generateToken(8),
		AllowedIPs:   allowedIPs,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
		LastSeen:     now,
		TotalQueries: 0,
		Enabled:      true,
	}

	ws.cfg.AddClient(client)
	_ = ws.cfg.Save(ws.configPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(client)
}

// POST /api/clients/delete - Delete a client
func (ws *WebServer) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	ws.cfg.DeleteClient(req.ID)
	_ = ws.cfg.Save(ws.configPath)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"deleted"}`))
}

// POST /api/clients/toggle - Enable / Disable a client
func (ws *WebServer) handleToggleClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ws.cfg.ToggleClient(req.ID, req.Enabled)
	_ = ws.cfg.Save(ws.configPath)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"updated"}`))
}

// POST /api/clients/add_ip - Add an IP to a client
func (ws *WebServer) handleAddClientIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.IP == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ws.cfg.AddClientIP(req.ID, req.IP)
	_ = ws.cfg.Save(ws.configPath)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ip_added"}`))
}

// POST /api/clients/remove_ip - Remove an IP from a client
func (ws *WebServer) handleRemoveClientIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.IP == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ws.cfg.RemoveClientIP(req.ID, req.IP)
	_ = ws.cfg.Save(ws.configPath)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ip_removed"}`))
}

// POST /api/clients/renew - Renew / Extend client expiration
func (ws *WebServer) handleRenewClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID         string `json:"id"`
		ExtendDays int    `json:"extend_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ws.cfg.RenewClient(req.ID, req.ExtendDays)
	_ = ws.cfg.Save(ws.configPath)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"renewed"}`))
}

// POST /api/access/mode - Toggle Open Public Mode vs Client Whitelist Mode
func (ws *WebServer) handleToggleAccessMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AllowAll bool `json:"allow_all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ws.cfg.Access.AllowAll = req.AllowAll
	_ = ws.cfg.Save(ws.configPath)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"allow_all":%t}`, ws.cfg.Access.AllowAll)))
}

// GET /ip/{token} - Auto IP Registration Page (Shelter/Shecan Style)
func (ws *WebServer) handleAutoRegisterIP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/ip/")
	token = strings.TrimSpace(strings.TrimSuffix(token, "/"))

	if token == "" {
		http.Error(w, "Missing registration token", http.StatusBadRequest)
		return
	}

	clientIP := extractClientIP(r)
	client, alreadyPresent, err := ws.cfg.RegisterClientIP(token, clientIP)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err != nil {
		if err == os.ErrDeadlineExceeded {
			renderIPResultPage(w, false, "اعتبار اشتراک شما به پایان رسیده است", "Your subscription plan has expired. Please contact support to renew.", clientIP, "", "", "")
			return
		}
		renderIPResultPage(w, false, "لینک ثبت آی‌پی نامعتبر است", "Invalid or unknown registration token.", clientIP, "", "", "")
		return
	}

	// Auto-save updated client IP list to disk
	_ = ws.cfg.Save(ws.configPath)

	// Format expiration
	expStr := "نامحدود (Lifetime)"
	if !client.ExpiresAt.IsZero() {
		expStr = client.ExpiresAt.Format("2006-01-02 15:04:05")
		remaining := time.Until(client.ExpiresAt)
		if remaining > 0 {
			days := int(remaining.Hours() / 24)
			hours := int(remaining.Hours()) % 24
			expStr = fmt.Sprintf("%s (%d روز و %d ساعت باقیمانده)", expStr, days, hours)
		}
	}

	pubIP := ws.cfg.Server.PublicIP
	if pubIP == "" {
		pubIP = "127.0.0.1"
	}

	statusMsg := "آی‌پی شما با موفقیت ثبت و فعال شد!"
	if alreadyPresent {
		statusMsg = "آی‌پی شما قبلاً در سیستم ثبت شده و فعال است."
	}

	renderIPResultPage(w, true, statusMsg, "Your IP has been successfully registered on HyperDNS!", clientIP, client.Name, client.ID, expStr, pubIP)
}

func renderIPResultPage(w http.ResponseWriter, success bool, titleFa, titleEn, clientIP, clientName, clientID, expiresStr string, dnsIPs ...string) {
	dns1 := "199.247.27.134"
	if len(dnsIPs) > 0 && dnsIPs[0] != "" {
		dns1 = dnsIPs[0]
	}

	badgeColor := "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
	icon := "✓"
	if !success {
		badgeColor = "border-red-500/40 text-red-400 bg-red-500/10"
		icon = "✕"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ثبت آی‌پی هوشمند — HyperDNS</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&family=Chakra+Petch:wght@700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Vazirmatn', sans-serif; background-color: #060913; color: #f8fafc; }
    .mono { font-family: 'JetBrains Mono', monospace; direction: ltr; }
    .glass { background: rgba(13, 20, 38, 0.85); backdrop-filter: blur(20px); border: 1px solid rgba(56, 189, 248, 0.2); }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-900/20 via-slate-950 to-black">
  <div class="max-w-md w-full glass rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6 text-center border">
    
    <!-- Status Icon -->
    <div class="w-16 h-16 mx-auto rounded-2xl %s border flex items-center justify-center text-3xl font-bold shadow-lg">
      %s
    </div>

    <!-- Title -->
    <div>
      <h1 class="text-xl font-extrabold text-white mb-1">%s</h1>
      <p class="text-xs text-slate-400 font-sans mono">%s</p>
    </div>

    <!-- Detected IP Card -->
    <div class="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
      <div class="text-[11px] text-slate-400">آی‌پی شناسایی‌شده شما (Your Detected IP):</div>
      <div class="text-xl font-bold text-cyan-400 mono tracking-wider">%s</div>
      <div class="text-[10px] text-slate-500">برای اتصال بدون قطعی، بدون فیلترشکن متصل شوید</div>
    </div>`, badgeColor, icon, titleFa, titleEn, clientIP)

	if success {
		html += fmt.Sprintf(`
    <!-- Client Info -->
    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 text-xs text-slate-300 space-y-2 text-right">
      <div class="flex justify-between items-center"><span class="text-slate-400">نام کاربر:</span><span class="font-bold text-white">%s</span></div>
      <div class="flex justify-between items-center"><span class="text-slate-400">کد کاربری:</span><span class="mono text-amber-300 font-bold">%s</span></div>
      <div class="flex justify-between items-center"><span class="text-slate-400">تاریخ انقضاء:</span><span class="text-emerald-300 font-semibold">%s</span></div>
    </div>

    <!-- DNS Addresses to set -->
    <div class="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 text-right space-y-2.5">
      <div class="text-xs font-bold text-cyan-300 flex items-center justify-between">
        <span>دی‌ان‌اس‌های اختصاصی شما:</span>
        <span class="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 mono text-cyan-200">DNS Servers</span>
      </div>
      <div class="space-y-1.5 mono text-xs">
        <div class="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800">
          <span class="text-slate-400 text-[10px]">Primary DNS:</span>
          <span class="text-white font-bold">%s</span>
        </div>
        <div class="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800">
          <span class="text-slate-400 text-[10px]">Secondary DNS:</span>
          <span class="text-slate-300">1.1.1.1</span>
        </div>
      </div>
    </div>

    <div class="text-[11px] text-slate-400 leading-relaxed text-right bg-slate-950/40 p-3 rounded-lg border border-slate-800">
      💡 <strong>نکته مهم:</strong> در صورتی که اینترنت یا مودم شما ریستارت شد و آی‌پی تغییر کرد، مجدداً روی همین لینک کلیک کنید تا آی‌پی جدیدتان خودکار ثبت شود.
    </div>`, clientName, clientID, expiresStr, dns1)
	}

	html += `
    <div class="pt-2 text-[10px] text-slate-500 mono">
      HyperDNS Smart Controller — High-Performance Zero-Loss Engine
    </div>
  </div>
</body>
</html>`

	_, _ = w.Write([]byte(html))
}
