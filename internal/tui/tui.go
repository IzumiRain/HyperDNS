package tui

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"hyperdns/internal/config"
	"hyperdns/internal/dns"
	"hyperdns/internal/rules"
	"hyperdns/internal/sniproxy"
	"hyperdns/internal/web"
)

// ANSI Color Codes
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Cyan    = "\033[36m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Red     = "\033[31m"
	Purple  = "\033[35m"
	Blue    = "\033[34m"
	Clear   = "\033[H\033[2J"
)

type TUI struct {
	cfg        *config.Config
	configPath string
	matcher    *rules.Matcher
	cache      *dns.Cache
	upstreams  *dns.UpstreamPool
	dnsHandler *dns.Handler
	sniProxy   *sniproxy.Server
	stats      *web.StatsCollector
	logHistory []dns.QueryLogItem
	inMenu     bool
}

func NewTUI(
	cfg *config.Config,
	configPath string,
	matcher *rules.Matcher,
	cache *dns.Cache,
	upstreams *dns.UpstreamPool,
	dnsHandler *dns.Handler,
	sniProxy *sniproxy.Server,
	stats *web.StatsCollector,
) *TUI {
	return &TUI{
		cfg:        cfg,
		configPath: configPath,
		matcher:    matcher,
		cache:      cache,
		upstreams:  upstreams,
		dnsHandler: dnsHandler,
		sniProxy:   sniProxy,
		stats:      stats,
		logHistory: make([]dns.QueryLogItem, 0, 10),
	}
}

func (t *TUI) Run() {
	// Query log ingestion goroutine
	logChan := t.dnsHandler.GetLogChannel()
	go func() {
		for item := range logChan {
			if len(t.logHistory) >= 6 {
				t.logHistory = append(t.logHistory[1:], item)
			} else {
				t.logHistory = append(t.logHistory, item)
			}
		}
	}()

	reader := bufio.NewReader(os.Stdin)

	for {
		t.renderLive()

		fmt.Print(Cyan + Bold + "\n Enter command [m for Management Menu, f=flush, q=exit]: " + Reset)
		
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "q" || input == "exit" {
			fmt.Print(Clear)
			fmt.Println(Green + "Exiting HyperDNS TUI. The DNS server continues running in background." + Reset)
			return
		} else if input == "m" || input == "menu" {
			t.showMainMenu(reader)
		} else if input == "f" {
			t.cache.Flush()
			fmt.Println(Green + "✓ DNS Cache Flushed!" + Reset)
			time.Sleep(1 * time.Second)
		} else if input == "r" {
			t.cfg.Rules.EnableRiot = !t.cfg.Rules.EnableRiot
			t.matcher.Rebuild(t.cfg)
			_ = t.cfg.Save(t.configPath)
		} else if input == "d" {
			t.cfg.Rules.EnableDiscord = !t.cfg.Rules.EnableDiscord
			t.matcher.Rebuild(t.cfg)
			_ = t.cfg.Save(t.configPath)
		} else if input == "e" {
			t.cfg.Rules.EnableEpic = !t.cfg.Rules.EnableEpic
			t.matcher.Rebuild(t.cfg)
			_ = t.cfg.Save(t.configPath)
		} else if input == "s" {
			t.cfg.Rules.EnableSteam = !t.cfg.Rules.EnableSteam
			t.matcher.Rebuild(t.cfg)
			_ = t.cfg.Save(t.configPath)
		} else if input == "a" {
			t.cfg.Rules.EnableAdBlock = !t.cfg.Rules.EnableAdBlock
			t.matcher.Rebuild(t.cfg)
			_ = t.cfg.Save(t.configPath)
		}
	}
}

func (t *TUI) renderLive() {
	st := t.stats.GetSystemStats()
	upStats := t.upstreams.GetStats()

	var sb strings.Builder
	sb.WriteString(Clear)

	// Top Cyber Banner
	sb.WriteString(Cyan + Bold)
	sb.WriteString("╔═════════════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║               ⚡ HyperDNS CONTROLLER — HIGH-PERFORMANCE TUI                ║\n")
	sb.WriteString("╚═════════════════════════════════════════════════════════════════════════════╝\n" + Reset)

	pubIP := t.cfg.Server.PublicIP
	if pubIP == "" {
		pubIP = "127.0.0.1"
	}
	sb.WriteString(fmt.Sprintf(" %sPublic IP:%s %s%-15s%s │ %sDNS Port:%s %s%-5d%s │ %sWeb Panel:%s %shttp://%s:%d%s\n",
		Dim, Reset, Green+Bold, pubIP, Reset,
		Dim, Reset, Cyan, t.cfg.DNS.Port, Reset,
		Dim, Reset, Yellow, pubIP, t.cfg.Server.WebPort, Reset,
	))
	sb.WriteString(strings.Repeat("─", 79) + "\n")

	// Telemetry Grid
	sb.WriteString(fmt.Sprintf(" %sQuery Rate:%s  %s%-6.1f QPS%s   │ %sCache Ratio:%s %s%-5.1f%%%s  │ %sRAM Usage:%s   %s%.1f MB%s\n",
		Dim, Reset, Cyan+Bold, st.QPS, Reset,
		Dim, Reset, Green+Bold, st.CacheHitRatio, Reset,
		Dim, Reset, Blue+Bold, st.AllocMemoryMB, Reset,
	))
	sb.WriteString(fmt.Sprintf(" %sTotal Queries:%s %s%-8d%s │ %sCache Items:%s %s%-6d%s │ %sCPU Load:%s    %s%.1f%%%s\n",
		Dim, Reset, Yellow, st.TotalQueries, Reset,
		Dim, Reset, Green, st.CacheEntries, Reset,
		Dim, Reset, Purple, st.CPUUsagePercent, Reset,
	))
	sb.WriteString(fmt.Sprintf(" %sActive Relays:%s %s%-8d%s │ %sLive Speed:%s  %s↓%.1f ↑%.1f KB/s%s\n",
		Dim, Reset, Purple+Bold, st.ActiveProxyConns, Reset,
		Dim, Reset, Green, st.SpeedInKBps, st.SpeedOutKBps, Reset,
	))
	sb.WriteString(strings.Repeat("─", 79) + "\n")

	// Upstream Racing Latencies
	sb.WriteString(Bold + " [ UPSTREAM RACERS ]" + Reset + "\n")
	for _, u := range upStats {
		latMs := float64(u.Latency.Microseconds()) / 1000.0
		col := Green
		if latMs > 40 {
			col = Yellow
		}
		if latMs > 80 {
			col = Red
		}
		sb.WriteString(fmt.Sprintf("  • %-22s │ RTT: %s%5.1f ms%s │ Success: %s%3.0f%%%s\n",
			u.Address, col, latMs, Reset, Cyan, u.SuccessRate, Reset,
		))
	}
	sb.WriteString(strings.Repeat("─", 79) + "\n")

	badge := func(on bool) string {
		if on {
			return Green + "[ON]" + Reset
		}
		return Dim + "[OFF]" + Reset
	}

	sb.WriteString(Bold + " [ 1-CLICK PRESETS ]" + Reset + "\n")
	sb.WriteString(fmt.Sprintf("  [r] Riot: %s  [d] Discord: %s  [e] Epic: %s  [s] Steam: %s\n",
		badge(t.cfg.Rules.EnableRiot),
		badge(t.cfg.Rules.EnableDiscord),
		badge(t.cfg.Rules.EnableEpic),
		badge(t.cfg.Rules.EnableSteam),
	))
	sb.WriteString(fmt.Sprintf("  [a] AdBlock: %s  [m] Management Menu  [f] Flush Cache  [q] Exit\n",
		badge(t.cfg.Rules.EnableAdBlock),
	))
	sb.WriteString(strings.Repeat("─", 79) + "\n")

	// Live Query Stream
	sb.WriteString(Bold + " [ LIVE QUERY STREAM ]" + Reset + "\n")
	if len(t.logHistory) == 0 {
		sb.WriteString(Dim + "  (Listening for incoming DNS queries...)\n" + Reset)
	} else {
		for _, q := range t.logHistory {
			actCol := Cyan
			if q.Action == "PROXY" {
				actCol = Green
			} else if q.Action == "BLOCK" {
				actCol = Red
			}
			cachedStr := ""
			if q.Cached {
				cachedStr = Yellow + "[RAM]" + Reset
			}
			timeStr := q.Timestamp.Format("15:04:05")
			sb.WriteString(fmt.Sprintf("  %s%s%s │ %-15s │ %s%-6s%s │ %-28s │ %s%-6s%s %s\n",
				Dim, timeStr, Reset,
				q.ClientIP,
				Purple, q.Protocol, Reset,
				truncate(q.Domain, 28),
				actCol+Bold, q.Action, Reset,
				cachedStr,
			))
		}
	}
	sb.WriteString(strings.Repeat("─", 79) + "\n")

	fmt.Print(sb.String())
}

func (t *TUI) showMainMenu(reader *bufio.Reader) {
	for {
		fmt.Print(Clear)
		fmt.Println(Cyan + Bold + "╔═════════════════════════════════════════════════════════════════════════════╗" + Reset)
		fmt.Println(Cyan + Bold + "║                  ⚡ HyperDNS — MANAGEMENT CONTROL PANEL                     ║" + Reset)
		fmt.Println(Cyan + Bold + "╚═════════════════════════════════════════════════════════════════════════════╝" + Reset)
		fmt.Println()
		fmt.Println(Bold + " Select an option:" + Reset)
		fmt.Println("  [1] Return to Live Telemetry Dashboard")
		fmt.Println("  [2] Game & Security Presets Manager (Toggle 15+ Platforms)")
		fmt.Println("  [3] Custom Domain & TLS/SSL Setup (DoH / DoT Domain)")
		fmt.Println("  [4] Admin Credentials Manager (Change Username & Password)")
		fmt.Println("  [5] Upstream DNS Resolvers (Add/Remove upstream servers)")
		fmt.Println("  [6] Flush In-Memory DNS Cache")
		fmt.Println("  [7] Restart HyperDNS Service")
		fmt.Println("  [8] Reset Admin TLS Certificate")
		fmt.Println("  [9] Complete Uninstall HyperDNS")
		fmt.Println("  [0] Exit TUI")
		fmt.Println()
		fmt.Print(Yellow + " Enter choice [0-9]: " + Reset)

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1", "":
			return
		case "2":
			t.managePresetsMenu(reader)
		case "3":
			t.manageDomainTLS(reader)
		case "4":
			t.changeAdminCredentials(reader)
		case "5":
			t.manageUpstreams(reader)
		case "6":
			t.cache.Flush()
			fmt.Println(Green + "\n✓ DNS Cache flushed successfully!" + Reset)
			time.Sleep(1500 * time.Millisecond)
		case "7":
			t.restartService()
			time.Sleep(2 * time.Second)
		case "8":
			t.resetTLSCert()
			time.Sleep(2 * time.Second)
		case "9":
			if t.confirmUninstall(reader) {
				os.Exit(0)
			}
		case "0", "q", "exit":
			fmt.Print(Clear)
			fmt.Println(Green + "Exiting HyperDNS. Goodbye!" + Reset)
			os.Exit(0)
		}
	}
}

func (t *TUI) managePresetsMenu(reader *bufio.Reader) {
	for {
		fmt.Print(Clear)
		fmt.Println(Cyan + Bold + "=== GAME & SECURITY PRESETS MANAGER ===" + Reset)
		fmt.Println()
		
		status := func(b bool) string {
			if b {
				return Green + "[ENABLED]" + Reset
			}
			return Red + "[DISABLED]" + Reset
		}

		fmt.Printf(" [1] Riot Games (Valorant / LoL)     : %s\n", status(t.cfg.Rules.EnableRiot))
		fmt.Printf(" [2] Epic Games (Store / Fortnite)   : %s\n", status(t.cfg.Rules.EnableEpic))
		fmt.Printf(" [3] Steam & Valve (CS2 / Dota 2)    : %s\n", status(t.cfg.Rules.EnableSteam))
		fmt.Printf(" [4] PUBG Mobile & PC (Krafton)      : %s\n", status(t.cfg.Rules.EnablePUBG))
		fmt.Printf(" [5] Call of Duty Mobile & Warzone   : %s\n", status(t.cfg.Rules.EnableCallOfDuty))
		fmt.Printf(" [6] Supercell (Brawl Stars / Clash) : %s\n", status(t.cfg.Rules.EnableSupercell))
		fmt.Printf(" [7] Discord (Full Suite + RTC)      : %s\n", status(t.cfg.Rules.EnableDiscord))
		fmt.Printf(" [8] Electronic Arts & Apex Legends  : %s\n", status(t.cfg.Rules.EnableEA))
		fmt.Printf(" [9] Blizzard (Battle.net)           : %s\n", status(t.cfg.Rules.EnableBlizzard))
		fmt.Printf(" [10] Ubisoft Connect                : %s\n", status(t.cfg.Rules.EnableUbisoft))
		fmt.Printf(" [11] Rockstar Games (GTA Online)    : %s\n", status(t.cfg.Rules.EnableRockstar))
		fmt.Printf(" [12] Xbox Live & Microsoft          : %s\n", status(t.cfg.Rules.EnableXbox))
		fmt.Printf(" [13] PlayStation Network (PSN)      : %s\n", status(t.cfg.Rules.EnablePlayStation))
		fmt.Printf(" [14] Roblox                         : %s\n", status(t.cfg.Rules.EnableRoblox))
		fmt.Printf(" [15] Spotify Music                  : %s\n", status(t.cfg.Rules.EnableSpotify))
		fmt.Printf(" [16] Developer 403 Suite            : %s\n", status(t.cfg.Rules.EnableDev403))
		fmt.Printf(" [17] AdBlock & Trackers Sinkhole    : %s\n", status(t.cfg.Rules.EnableAdBlock))
		fmt.Printf(" [18] Family Safe Adult Filter       : %s\n", status(t.cfg.Rules.EnableFamilySafe))
		fmt.Println(" [0] Back to Main Menu")
		fmt.Println()
		fmt.Print(Yellow + " Select preset number to toggle: " + Reset)

		numStr, _ := reader.ReadString('\n')
		numStr = strings.TrimSpace(numStr)
		if numStr == "0" || numStr == "" {
			return
		}

		num, _ := strconv.Atoi(numStr)
		switch num {
		case 1:
			t.cfg.Rules.EnableRiot = !t.cfg.Rules.EnableRiot
		case 2:
			t.cfg.Rules.EnableEpic = !t.cfg.Rules.EnableEpic
		case 3:
			t.cfg.Rules.EnableSteam = !t.cfg.Rules.EnableSteam
		case 4:
			t.cfg.Rules.EnablePUBG = !t.cfg.Rules.EnablePUBG
		case 5:
			t.cfg.Rules.EnableCallOfDuty = !t.cfg.Rules.EnableCallOfDuty
		case 6:
			t.cfg.Rules.EnableSupercell = !t.cfg.Rules.EnableSupercell
		case 7:
			t.cfg.Rules.EnableDiscord = !t.cfg.Rules.EnableDiscord
		case 8:
			t.cfg.Rules.EnableEA = !t.cfg.Rules.EnableEA
		case 9:
			t.cfg.Rules.EnableBlizzard = !t.cfg.Rules.EnableBlizzard
		case 10:
			t.cfg.Rules.EnableUbisoft = !t.cfg.Rules.EnableUbisoft
		case 11:
			t.cfg.Rules.EnableRockstar = !t.cfg.Rules.EnableRockstar
		case 12:
			t.cfg.Rules.EnableXbox = !t.cfg.Rules.EnableXbox
		case 13:
			t.cfg.Rules.EnablePlayStation = !t.cfg.Rules.EnablePlayStation
		case 14:
			t.cfg.Rules.EnableRoblox = !t.cfg.Rules.EnableRoblox
		case 15:
			t.cfg.Rules.EnableSpotify = !t.cfg.Rules.EnableSpotify
		case 16:
			t.cfg.Rules.EnableDev403 = !t.cfg.Rules.EnableDev403
		case 17:
			t.cfg.Rules.EnableAdBlock = !t.cfg.Rules.EnableAdBlock
		case 18:
			t.cfg.Rules.EnableFamilySafe = !t.cfg.Rules.EnableFamilySafe
		}

		t.matcher.Rebuild(t.cfg)
		_ = t.cfg.Save(t.configPath)
	}
}

func (t *TUI) manageDomainTLS(reader *bufio.Reader) {
	fmt.Print(Clear)
	fmt.Println(Cyan + Bold + "=== DOMAIN & TLS/SSL CONFIGURATION ===" + Reset)
	fmt.Println()
	fmt.Printf(" Current Domain: %s%s%s\n", Yellow, t.cfg.TLS.Domain, Reset)
	fmt.Println(" Adding a domain allows DoT (Private DNS on Android) and clean DoH with valid SSL.")
	fmt.Println()
	fmt.Print(" Enter new domain name (leave empty to cancel): ")
	dom, _ := reader.ReadString('\n')
	dom = strings.TrimSpace(dom)

	if dom != "" {
		t.cfg.TLS.Domain = dom
		_ = t.cfg.Save(t.configPath)
		fmt.Println(Green + "\n✓ Domain saved. Generating updated TLS certificate..." + Reset)
		t.resetTLSCert()
	}
	time.Sleep(2 * time.Second)
}

func (t *TUI) changeAdminCredentials(reader *bufio.Reader) {
	fmt.Print(Clear)
	fmt.Println(Cyan + Bold + "=== ADMIN CREDENTIALS CONFIGURATION ===" + Reset)
	fmt.Println()
	fmt.Printf(" Current Username: %s%s%s\n", Yellow, t.cfg.Server.AdminUsername, Reset)
	fmt.Println()
	fmt.Print(" Enter new Admin Username: ")
	newUser, _ := reader.ReadString('\n')
	newUser = strings.TrimSpace(newUser)

	fmt.Print(" Enter new Admin Password: ")
	newPass, _ := reader.ReadString('\n')
	newPass = strings.TrimSpace(newPass)

	if newUser != "" && newPass != "" {
		t.cfg.Server.AdminUsername = newUser
		t.cfg.Server.AdminPassword = newPass
		_ = t.cfg.Save(t.configPath)
		fmt.Println(Green + "\n✓ Admin credentials updated successfully!" + Reset)
	} else {
		fmt.Println(Yellow + "\nAction cancelled. Username/password cannot be empty." + Reset)
	}
	time.Sleep(2 * time.Second)
}

func (t *TUI) manageUpstreams(reader *bufio.Reader) {
	fmt.Print(Clear)
	fmt.Println(Cyan + Bold + "=== UPSTREAM DNS RESOLVERS ===" + Reset)
	fmt.Println()
	fmt.Println(" Current Upstreams:")
	for i, u := range t.cfg.DNS.Upstreams {
		fmt.Printf("  [%d] %s\n", i+1, u)
	}
	fmt.Println()
	fmt.Println(" Options: [A]dd upstream, [D]elete upstream, [R]eset to defaults, [0] Back")
	fmt.Print(Yellow + " Select option: " + Reset)

	opt, _ := reader.ReadString('\n')
	opt = strings.TrimSpace(strings.ToUpper(opt))

	if opt == "A" {
		fmt.Print(" Enter upstream address (e.g. 1.1.1.1:53 or 8.8.8.8:53): ")
		addr, _ := reader.ReadString('\n')
		addr = strings.TrimSpace(addr)
		if addr != "" {
			if !strings.Contains(addr, ":") {
				addr += ":53"
			}
			t.cfg.DNS.Upstreams = append(t.cfg.DNS.Upstreams, addr)
			t.upstreams.SetUpstreams(t.cfg.DNS.Upstreams)
			_ = t.cfg.Save(t.configPath)
			fmt.Println(Green + "✓ Upstream added!" + Reset)
		}
	} else if opt == "R" {
		t.cfg.DNS.Upstreams = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53", "1.0.0.1:53"}
		t.upstreams.SetUpstreams(t.cfg.DNS.Upstreams)
		_ = t.cfg.Save(t.configPath)
		fmt.Println(Green + "✓ Upstreams reset to Cloudflare/Google/Quad9 defaults!" + Reset)
	}
	time.Sleep(1500 * time.Millisecond)
}

func (t *TUI) restartService() {
	fmt.Println(Yellow + "\nRestarting HyperDNS system service..." + Reset)
	cmd := exec.Command("systemctl", "restart", "hyperdns")
	if err := cmd.Run(); err == nil {
		fmt.Println(Green + "✓ HyperDNS service restarted successfully!" + Reset)
	} else {
		fmt.Printf(Red+"Failed to restart systemd service (might be running standalone): %v\n"+Reset, err)
	}
}

func (t *TUI) resetTLSCert() {
	_ = os.Remove("certs/cert.pem")
	_ = os.Remove("certs/key.pem")
	fmt.Println(Green + "✓ TLS Certificates regenerated. Restarting services..." + Reset)
	t.restartService()
}

func (t *TUI) confirmUninstall(reader *bufio.Reader) bool {
	fmt.Print(Clear)
	fmt.Println(Red + Bold + "⚠️  DANGER: UNINSTALL HyperDNS" + Reset)
	fmt.Println()
	fmt.Println(" This will stop the service, remove systemd unit, and delete all configurations.")
	fmt.Print(Red + " Are you absolutely sure? Type 'yes' to proceed: " + Reset)

	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))

	if ans == "yes" {
		fmt.Println(Yellow + "\nStopping and removing HyperDNS..." + Reset)
		_ = exec.Command("systemctl", "stop", "hyperdns").Run()
		_ = exec.Command("systemctl", "disable", "hyperdns").Run()
		_ = os.Remove("/etc/systemd/system/hyperdns.service")
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = os.Remove("/etc/systemd/resolved.conf.d/hyperdns.conf")
		_ = exec.Command("systemctl", "restart", "systemd-resolved").Run()
		_ = os.Remove("/usr/local/bin/hdns")
		_ = os.RemoveAll("/opt/hyperdns")
		fmt.Println(Green + Bold + "\n✓ HyperDNS has been cleanly uninstalled from your server." + Reset)
		fmt.Println(Dim + "Thank you for using HyperDNS! 👋\n" + Reset)
		return true
	}

	fmt.Println(Yellow + "Uninstall cancelled." + Reset)
	time.Sleep(1500 * time.Millisecond)
	return false
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-2] + ".."
	}
	return s
}
