package tui

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"hyperdns/internal/config"
	"hyperdns/internal/diagnostics"
)

// PrintHelp outputs the CLI help reference
func PrintHelp() {
	fmt.Println(Cyan + Bold + `
  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███╗   ██╗███████╗
  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔════╝
  ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║██╔██╗ ██║███████╗
  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║  ██║██║╚██╗██║╚════██║
  ██║  ██║   ██║   ██║     ███████╗██║  ██║██████╔╝██║ ╚████║███████║
  ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝
       ⚡ HyperDNS Standalone Controller & Management Console ⚡` + Reset)
	fmt.Println()
	fmt.Println(Bold + "USAGE:" + Reset)
	fmt.Println("  hdns                     Open Interactive Management TUI Console")
	fmt.Println("  hdns status              Display live service health, ports & stats")
	fmt.Println("  hdns restart             Restart the HyperDNS background service")
	fmt.Println("  hdns stop                Stop the HyperDNS background service")
	fmt.Println("  hdns start               Start the HyperDNS background service")
	fmt.Println("  hdns logs                Stream live query & system logs")
	fmt.Println("  hdns flush               Flush the in-memory DNS cache")
	fmt.Println("  hdns diag                Run latency benchmark & gaming diagnostics")
	fmt.Println("  hdns clients             List registered clients & whitelist IPs")
	fmt.Println()
}

// PrintStatus checks service status and prints an informative dashboard
func PrintStatus(cPath string) {
	cfg, _ := config.LoadConfig(cPath)
	pubIP := "127.0.0.1"
	if cfg != nil && cfg.Server.PublicIP != "" {
		pubIP = cfg.Server.PublicIP
	}

	fmt.Println(Cyan + Bold + "=== HyperDNS Service Status ===" + Reset)
	
	// Check systemctl status
	cmd := exec.Command("systemctl", "is-active", "hyperdns")
	out, err := cmd.Output()
	status := strings.TrimSpace(string(out))
	if err == nil && status == "active" {
		fmt.Printf(" Service State : %s● ACTIVE (Running in background)%s\n", Green+Bold, Reset)
	} else {
		fmt.Printf(" Service State : %s● INACTIVE (%s)%s\n", Yellow, status, Reset)
	}

	fmt.Printf(" Public IP     : %s%s%s\n", Green, pubIP, Reset)
	fmt.Printf(" Web Dashboard : %shttp://%s:8080/dashboard%s\n", Cyan, pubIP, Reset)
	fmt.Printf(" Matrix Gateway: %shttp://%s:8080/%s\n", Cyan, pubIP, Reset)
	fmt.Printf(" Standard DNS  : %s%s:53%s\n", Yellow, pubIP, Reset)
	fmt.Printf(" DoH Endpoint  : %shttps://%s:8443/dns-query%s\n", Purple, pubIP, Reset)
	fmt.Printf(" DoT Endpoint  : %s%s:853%s\n", Purple, pubIP, Reset)

	if cfg != nil {
		fmt.Printf(" Whitelist Mode: %s%v%s (%d clients)\n", 
			Cyan, !cfg.Access.AllowAll, Reset, len(cfg.Access.Clients))
	}
	fmt.Println()
}

// RestartService restarts systemd service
func RestartService() {
	fmt.Println(Yellow + "Restarting HyperDNS service..." + Reset)
	cmd := exec.Command("systemctl", "restart", "hyperdns")
	if err := cmd.Run(); err == nil {
		fmt.Println(Green + "✓ HyperDNS service restarted successfully!" + Reset)
	} else {
		fmt.Printf(Red+"✕ Error restarting service: %v\n"+Reset, err)
	}
}

// StopService stops systemd service
func StopService() {
	fmt.Println(Yellow + "Stopping HyperDNS service..." + Reset)
	_ = exec.Command("systemctl", "stop", "hyperdns").Run()
	fmt.Println(Green + "✓ HyperDNS service stopped." + Reset)
}

// StartService starts systemd service
func StartService() {
	fmt.Println(Yellow + "Starting HyperDNS service..." + Reset)
	_ = exec.Command("systemctl", "start", "hyperdns").Run()
	fmt.Println(Green + "✓ HyperDNS service started." + Reset)
}

// StreamLogs streams journalctl logs live
func StreamLogs() {
	fmt.Println(Cyan + "Streaming HyperDNS live logs (Ctrl+C to exit)..." + Reset)
	cmd := exec.Command("journalctl", "-u", "hyperdns", "-f", "-n", "30", "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
}

// FlushCacheDirect flushes the DNS cache
func FlushCacheDirect(cPath string) {
	fmt.Println(Yellow + "Flushing DNS Cache..." + Reset)
	resp, err := http.Post("http://127.0.0.1:8080/api/cache/flush", "application/json", nil)
	if err == nil && resp.StatusCode == 200 {
		fmt.Println(Green + "✓ DNS Cache flushed successfully!" + Reset)
		return
	}
	// Fallback to restart
	RestartService()
}

// RunConsoleDiagnostics runs gaming diagnostics and outputs formatted table
func RunConsoleDiagnostics(cPath string) {
	fmt.Println(Cyan + Bold + "\nRunning HyperDNS Gaming & Anti-Sanction Diagnostics Suite..." + Reset)
	rep := diagnostics.RunDiagnostics()

	fmt.Println()
	fmt.Printf(" Gaming Suitability Score: %s%d%%%s (%s)\n", Green+Bold, rep.OverallScore, Reset, rep.OverallQuality)
	fmt.Println(strings.Repeat("─", 65))
	fmt.Printf(" %-32s │ %-10s │ %s\n", "TARGET SERVICE", "STATUS", "LATENCY")
	fmt.Println(strings.Repeat("─", 65))

	for _, r := range rep.Results {
		statCol := Green
		if r.Status == "GOOD" {
			statCol = Yellow
		} else if !r.Success {
			statCol = Red
		}
		fmt.Printf(" %-32s │ %s%-10s%s │ %6.1f ms\n", r.Name, statCol, r.Status, Reset, r.LatencyMs)
	}
	fmt.Println(strings.Repeat("─", 65))
	fmt.Println()
}

// ListClients lists registered clients and whitelisted IPs
func ListClients(cPath string) {
	cfg, err := config.LoadConfig(cPath)
	if err != nil {
		fmt.Printf(Red+"Failed to load config: %v\n"+Reset, err)
		return
	}

	fmt.Println(Cyan + Bold + "\n=== REGISTERED CLIENTS & WHITELISTED IPS ===" + Reset)
	fmt.Println()
	if len(cfg.Access.Clients) == 0 {
		fmt.Println(Dim + " No clients created yet. Create one via Web UI or 'hdns'." + Reset)
		return
	}

	for i, c := range cfg.Access.Clients {
		status := Green + "ACTIVE" + Reset
		if !c.Enabled {
			status = Red + "DISABLED" + Reset
		}
		ips := strings.Join(c.AllowedIPs, ", ")
		if ips == "" {
			ips = Dim + "(No IPs registered yet)" + Reset
		}
		fmt.Printf(" [%d] %s%s%s (%s)\n", i+1, Bold, c.Name, Reset, status)
		regHost := cfg.Server.PublicIP
		regProto := "http"
		regPort := fmt.Sprintf(":%d", cfg.Server.WebPort)
		if cfg.TLS.Domain != "" {
			regHost = cfg.TLS.Domain
			regProto = "https"
			regPort = fmt.Sprintf(":%d", cfg.DNS.DoHPort)
		}
		fmt.Printf("     • Auto-Register URL: %s://%s%s/ip/%s\n", regProto, regHost, regPort, c.Token)
		fmt.Println()
	}
}

// RunInteractiveManager runs the main interactive terminal menu
func RunInteractiveManager(cPath string) {
	reader := bufio.NewReader(os.Stdin)

	for {
		cfg, err := config.LoadConfig(cPath)
		if err != nil {
			fmt.Printf(Red+"Failed to load config from %s: %v\n"+Reset, cPath, err)
			return
		}

		fmt.Print(Clear)
		fmt.Println(Cyan + Bold + `
  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███╗   ██╗███████╗
  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔════╝
  ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║██╔██╗ ██║███████╗
  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║  ██║██║╚██╗██║╚════██║
  ██║  ██║   ██║   ██║     ███████╗██║  ██║██████╔╝██║ ╚████║███████║
  ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝
       ⚡ HyperDNS Standalone Controller & Management Console ⚡` + Reset)
		fmt.Println()

		pubIP := cfg.Server.PublicIP
		if pubIP == "" {
			pubIP = "127.0.0.1"
		}

		// Check service status
		cmd := exec.Command("systemctl", "is-active", "hyperdns")
		out, err := cmd.Output()
		srvStatus := strings.TrimSpace(string(out))
		statusBadge := Green + "● ACTIVE" + Reset
		if err != nil || srvStatus != "active" {
			statusBadge = Yellow + "● INACTIVE" + Reset
		}

		modeBadge := Green + "PUBLIC" + Reset
		if !cfg.Access.AllowAll {
			modeBadge = Purple + "WHITELIST ONLY" + Reset
		}

		fmt.Printf(" [●] Service: %s   [●] Access Mode: %s   [●] Clients: %s%d%s\n", 
			statusBadge, modeBadge, Yellow, len(cfg.Access.Clients), Reset)
		fmt.Printf(" [●] Web Dashboard: %shttp://%s:8080/dashboard%s\n", Cyan, pubIP, Reset)
		fmt.Println(strings.Repeat("─", 74))

		fmt.Println(Bold + " SELECT AN OPTION:" + Reset)
		fmt.Println("  [1] 📊 View Service Status & Info")
		fmt.Println("  [2] 👥 Manage Clients & Whitelist IPs (Shelter/Shecan Style)")
		fmt.Println("  [3] 🎯 Toggle Game & Anti-Sanction Policies (Valorant, Steam, PUBG...)")
		fmt.Println("  [4] 🧹 Flush DNS Cache")
		fmt.Println("  [5] ⚡ Run Diagnostics Suite (Ping & Latency Benchmark)")
		fmt.Println("  [6] 📜 View Live DNS Logs (journalctl stream)")
		fmt.Println("  [7] 🔒 Configure Custom Domain & SSL / HTTPS")
		fmt.Println("  [8] 🔑 Change Admin Web Panel Credentials")
		fmt.Println("  [9] 🔄 Restart HyperDNS Service Engine")
		fmt.Println("  [0] 🚪 Exit Console")
		fmt.Println(strings.Repeat("─", 74))
		fmt.Print(Yellow + " Enter choice [0-9]: " + Reset)

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			fmt.Print(Clear)
			PrintStatus(cPath)
			fmt.Print(Dim + "\nPress Enter to return..." + Reset)
			_, _ = reader.ReadString('\n')
		case "2":
			interactiveClientMenu(reader, cfg, cPath)
		case "3":
			interactivePoliciesMenu(reader, cfg, cPath)
		case "4":
			FlushCacheDirect(cPath)
			time.Sleep(1500 * time.Millisecond)
		case "5":
			RunConsoleDiagnostics(cPath)
			fmt.Print(Dim + "Press Enter to return..." + Reset)
			_, _ = reader.ReadString('\n')
		case "6":
			StreamLogs()
		case "7":
			interactiveDomainTLS(reader, cfg, cPath)
		case "8":
			interactiveAdminCredentials(reader, cfg, cPath)
		case "9":
			RestartService()
			time.Sleep(2 * time.Second)
		case "0", "q", "exit":
			fmt.Print(Clear)
			fmt.Println(Green + "Exiting HyperDNS Controller. Service continues running in background." + Reset)
			return
		}
	}
}

func interactiveClientMenu(reader *bufio.Reader, cfg *config.Config, cPath string) {
	for {
		fmt.Print(Clear)
		fmt.Println(Cyan + Bold + "=== CLIENTS & WHITELIST MANAGEMENT ===" + Reset)
		fmt.Println()

		modeStr := Green + "PUBLIC (Any IP can resolve)" + Reset
		if !cfg.Access.AllowAll {
			modeStr = Purple + "RESTRICTED (Only whitelisted clients)" + Reset
		}
		fmt.Printf(" Current Access Mode: %s\n", modeStr)
		fmt.Println()

		if len(cfg.Access.Clients) == 0 {
			fmt.Println(Dim + " No clients created yet." + Reset)
		} else {
			for i, c := range cfg.Access.Clients {
				st := Green + "ACTIVE" + Reset
				if !c.Enabled {
					st = Red + "DISABLED" + Reset
				}
				ips := strings.Join(c.AllowedIPs, ", ")
				if ips == "" {
					ips = Dim + "none" + Reset
				}
				fmt.Printf(" [%d] %-20s │ %s │ IPs: %s\n", i+1, c.Name, st, ips)
				fmt.Printf("     Token: %s%s%s (Link: http://%s:8080/ip/%s)\n", 
					Yellow, c.Token, Reset, cfg.Server.PublicIP, c.Token)
			}
		}

		fmt.Println()
		fmt.Println(" [T] Toggle Access Mode (Public <-> Whitelist)")
		fmt.Println(" [A] Add New Client")
		fmt.Println(" [D] Delete Client")
		fmt.Println(" [I] Add IP to Client Manually")
		fmt.Println(" [0] Back to Main Menu")
		fmt.Println()
		fmt.Print(Yellow + " Select option: " + Reset)

		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(strings.ToUpper(opt))

		switch opt {
		case "0", "":
			return
		case "T":
			cfg.Access.AllowAll = !cfg.Access.AllowAll
			_ = cfg.Save(cPath)
			RestartService()
		case "A":
			fmt.Print(" Enter Client Name (e.g. Ali Gamer): ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name != "" {
				client := config.Client{
					ID:         fmt.Sprintf("%d", time.Now().Unix()%1000000000),
					Name:       name,
					Token:      fmt.Sprintf("%x", time.Now().UnixNano())[:16],
					AllowedIPs: make([]string, 0),
					ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
					CreatedAt:  time.Now(),
					Enabled:    true,
				}
				cfg.Access.Clients = append(cfg.Access.Clients, client)
				_ = cfg.Save(cPath)
				RestartService()
				fmt.Println(Green + "✓ Client created successfully!" + Reset)
				time.Sleep(1500 * time.Millisecond)
			}
		case "D":
			fmt.Print(" Enter Client number to delete: ")
			numStr, _ := reader.ReadString('\n')
			num, _ := strconv.Atoi(strings.TrimSpace(numStr))
			if num > 0 && num <= len(cfg.Access.Clients) {
				cfg.Access.Clients = append(cfg.Access.Clients[:num-1], cfg.Access.Clients[num:]...)
				_ = cfg.Save(cPath)
				RestartService()
				fmt.Println(Green + "✓ Client deleted!" + Reset)
				time.Sleep(1500 * time.Millisecond)
			}
		case "I":
			fmt.Print(" Enter Client number: ")
			numStr, _ := reader.ReadString('\n')
			num, _ := strconv.Atoi(strings.TrimSpace(numStr))
			if num > 0 && num <= len(cfg.Access.Clients) {
				fmt.Print(" Enter IPv4 to whitelist: ")
				ipStr, _ := reader.ReadString('\n')
				ipStr = strings.TrimSpace(ipStr)
				if ipStr != "" {
					cfg.Access.Clients[num-1].AllowedIPs = append(cfg.Access.Clients[num-1].AllowedIPs, ipStr)
					_ = cfg.Save(cPath)
					RestartService()
					fmt.Println(Green + "✓ IP added to whitelist!" + Reset)
					time.Sleep(1500 * time.Millisecond)
				}
			}
		}
	}
}

func interactivePoliciesMenu(reader *bufio.Reader, cfg *config.Config, cPath string) {
	for {
		fmt.Print(Clear)
		fmt.Println(Cyan + Bold + "=== GAME & ANTI-SANCTION POLICIES ===" + Reset)
		fmt.Println()

		st := func(b bool) string {
			if b {
				return Green + "[ENABLED]" + Reset
			}
			return Dim + "[DISABLED]" + Reset
		}

		fmt.Printf(" [1] Riot Games (Valorant / LoL)     : %s\n", st(cfg.Rules.EnableRiot))
		fmt.Printf(" [2] Epic Games (Fortnite / Store)   : %s\n", st(cfg.Rules.EnableEpic))
		fmt.Printf(" [3] Steam & Valve (CS2 / Dota 2)    : %s\n", st(cfg.Rules.EnableSteam))
		fmt.Printf(" [4] PUBG Mobile & PC (Krafton)      : %s\n", st(cfg.Rules.EnablePUBG))
		fmt.Printf(" [5] Call of Duty (Warzone / Mobile) : %s\n", st(cfg.Rules.EnableCallOfDuty))
		fmt.Printf(" [6] Supercell (Brawl Stars / Clash) : %s\n", st(cfg.Rules.EnableSupercell))
		fmt.Printf(" [7] Discord (Voice & App)           : %s\n", st(cfg.Rules.EnableDiscord))
		fmt.Printf(" [8] Electronic Arts & Apex Legends  : %s\n", st(cfg.Rules.EnableEA))
		fmt.Printf(" [9] Blizzard (Battle.net)           : %s\n", st(cfg.Rules.EnableBlizzard))
		fmt.Printf(" [10] Ubisoft (Rainbow Six Siege)    : %s\n", st(cfg.Rules.EnableUbisoft))
		fmt.Printf(" [11] Rockstar Games (GTA Online)    : %s\n", st(cfg.Rules.EnableRockstar))
		fmt.Printf(" [12] Xbox Live & Microsoft          : %s\n", st(cfg.Rules.EnableXbox))
		fmt.Printf(" [13] PlayStation Network (PSN)      : %s\n", st(cfg.Rules.EnablePlayStation))
		fmt.Printf(" [14] Spotify Music                  : %s\n", st(cfg.Rules.EnableSpotify))
		fmt.Printf(" [15] Developer 403 Suite            : %s\n", st(cfg.Rules.EnableDev403))
		fmt.Printf(" [16] AdBlock & Trackers Sinkhole    : %s\n", st(cfg.Rules.EnableAdBlock))
		fmt.Println(" [0] Back")
		fmt.Println()
		fmt.Print(Yellow + " Select number to toggle policy: " + Reset)

		numStr, _ := reader.ReadString('\n')
		numStr = strings.TrimSpace(numStr)
		if numStr == "0" || numStr == "" {
			return
		}

		num, _ := strconv.Atoi(numStr)
		switch num {
		case 1:
			cfg.Rules.EnableRiot = !cfg.Rules.EnableRiot
		case 2:
			cfg.Rules.EnableEpic = !cfg.Rules.EnableEpic
		case 3:
			cfg.Rules.EnableSteam = !cfg.Rules.EnableSteam
		case 4:
			cfg.Rules.EnablePUBG = !cfg.Rules.EnablePUBG
		case 5:
			cfg.Rules.EnableCallOfDuty = !cfg.Rules.EnableCallOfDuty
		case 6:
			cfg.Rules.EnableSupercell = !cfg.Rules.EnableSupercell
		case 7:
			cfg.Rules.EnableDiscord = !cfg.Rules.EnableDiscord
		case 8:
			cfg.Rules.EnableEA = !cfg.Rules.EnableEA
		case 9:
			cfg.Rules.EnableBlizzard = !cfg.Rules.EnableBlizzard
		case 10:
			cfg.Rules.EnableUbisoft = !cfg.Rules.EnableUbisoft
		case 11:
			cfg.Rules.EnableRockstar = !cfg.Rules.EnableRockstar
		case 12:
			cfg.Rules.EnableXbox = !cfg.Rules.EnableXbox
		case 13:
			cfg.Rules.EnablePlayStation = !cfg.Rules.EnablePlayStation
		case 14:
			cfg.Rules.EnableSpotify = !cfg.Rules.EnableSpotify
		case 15:
			cfg.Rules.EnableDev403 = !cfg.Rules.EnableDev403
		case 16:
			cfg.Rules.EnableAdBlock = !cfg.Rules.EnableAdBlock
		}
		_ = cfg.Save(cPath)
		RestartService()
	}
}

func interactiveDomainTLS(reader *bufio.Reader, cfg *config.Config, cPath string) {
	fmt.Print(Clear)
	fmt.Println(Cyan + Bold + "=== CUSTOM DOMAIN & SSL / HTTPS SETUP ===" + Reset)
	fmt.Println()
	fmt.Printf(" Current Domain: %s%s%s\n", Green, cfg.TLS.Domain, Reset)
	fmt.Printf(" Auto-SSL (Let's Encrypt): %v\n", cfg.TLS.AutoCert)
	fmt.Println()
	fmt.Print(" Enter Domain Name (e.g. dns.example.com or press Enter to cancel): ")
	dom, _ := reader.ReadString('\n')
	dom = strings.TrimSpace(dom)
	if dom != "" {
		cfg.TLS.Domain = dom
		cfg.TLS.AutoCert = true
		fmt.Print(" Enter Email for Let's Encrypt (optional): ")
		em, _ := reader.ReadString('\n')
		cfg.TLS.Email = strings.TrimSpace(em)
		_ = cfg.Save(cPath)
		RestartService()
		fmt.Println(Green + "\n✓ Domain configured and SSL activated!" + Reset)
	}
	time.Sleep(2 * time.Second)
}

func interactiveAdminCredentials(reader *bufio.Reader, cfg *config.Config, cPath string) {
	fmt.Print(Clear)
	fmt.Println(Cyan + Bold + "=== ADMIN WEB PANEL CREDENTIALS ===" + Reset)
	fmt.Println()
	fmt.Printf(" Current Username: %s%s%s\n", Yellow, cfg.Server.AdminUsername, Reset)
	fmt.Println()
	fmt.Print(" Enter new Username: ")
	u, _ := reader.ReadString('\n')
	u = strings.TrimSpace(u)
	fmt.Print(" Enter new Password: ")
	p, _ := reader.ReadString('\n')
	p = strings.TrimSpace(p)
	if u != "" && p != "" {
		cfg.Server.AdminUsername = u
		cfg.Server.AdminPassword = p
		_ = cfg.Save(cPath)
		RestartService()
		fmt.Println(Green + "\n✓ Admin credentials updated!" + Reset)
	} else {
		fmt.Println(Yellow + "\nCancelled (username/password cannot be empty)." + Reset)
	}
	time.Sleep(2 * time.Second)
}
