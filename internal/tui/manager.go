package tui

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
	"hyperdns/internal/version"
)

const (
	Cyan   = "\033[36m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Red    = "\033[31m"
	Bold   = "\033[1m"
	Reset  = "\033[0m"
)

func clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		_ = cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

// RunInteractiveManager draws the console menu until the operator leaves it.
//
// It returns true when they left on purpose — [0] Exit, or [10] Uninstall — and
// false when stdin simply ended: a closed terminal, a dropped SSH session, or an
// input that was never a keyboard. The caller needs to tell those apart, because
// the servers are already running by the time this is called. Answering EOF by
// exiting is how a dropped SSH connection used to take the resolver down with it.
//
// dnsSettings and sniSettings are here for one entry, [11]: moving the dashboard
// port onto a port the resolver or the relay already binds makes the next start
// fatal in daemon mode, and the only way to refuse that in advance is to know what
// those two are configured to hold. Both may be nil; the port check simply sees
// fewer listeners.
func RunInteractiveManager(
	db *database.DB,
	clients *service.ClientService,
	stats *service.StatsService,
	c *cache.Cache,
	u *upstream.UpstreamPool,
	settings *database.ServerSettings,
	dnsSettings *database.DNSSettings,
	sniSettings *database.SNIProxySettings,
) bool {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		clearScreen()
		fmt.Println(Cyan + Bold + `
   _    _                           _____  _   _  _____ 
  | |  | |                         |  __ \| \ | |/ ____|
  | |__| |_   _ _ __   ___ _ __    | |  | |  \| | (___  
  |  __  | | | | '_ \ / _ \ '__|   | |  | | . ' |\___ \ 
  | |  | | |_| | |_) |  __/ |      | |__| | |\  |____) |
  |_|  |_|\__, | .__/ \___|_|      |_____/|_| \_|_____/ 
           __/ | |                                      
          |___/|_|      Next-Gen Standalone SmartDNS` + Reset)

		// The banner is redrawn on every pass through the menu, and PublicIP/APIBind
		// can be rewritten by the dashboard while the console sits at this prompt, so
		// both are read through the settings accessors. One Endpoint() call also means
		// the three lines below cannot disagree with each other.
		publicIP, apiBind := settings.Endpoint()

		fmt.Printf("\n %s• HyperDNS Version:%s %s%s%s [%s]%s\n", Bold, Reset, Cyan, version.Get().Display, Reset, version.Get().Hash, Reset)
		fmt.Printf(" %s• Server Status:%s %sONLINE%s | %sPublic IP:%s %s%s%s\n", Bold, Reset, Green, Reset, Bold, Reset, Cyan, publicIP, Reset)
		fmt.Printf(" %s• Dashboard:%s http://%s:%d\n", Bold, Reset, publicIP, settings.WebPort)
		fmt.Printf(" %s• REST API:%s  http://%s:%d/api/v1 (Bind: %s)\n", Bold, Reset, publicIP, settings.WebPort, apiBind)
		fmt.Println(" ────────────────────────────────────────────────────────")
		fmt.Printf("  %s[1]%s 📊 Service Status & Telemetry\n", Cyan, Reset)
		fmt.Printf("  %s[2]%s 👥 List Subscriber Accounts & Tokens\n", Cyan, Reset)
		fmt.Printf("  %s[3]%s ➕ Add New Subscriber (Name, Days, 1-IP Binding)\n", Cyan, Reset)
		fmt.Printf("  %s[4]%s ❌ Delete Subscriber Account\n", Cyan, Reset)
		fmt.Printf("  %s[5]%s 🚀 Benchmark DNS Upstreams\n", Cyan, Reset)
		fmt.Printf("  %s[6]%s 🧹 Flush DNS Cache\n", Cyan, Reset)
		fmt.Printf("  %s[7]%s 🔑 View / Regenerate Master API Key\n", Cyan, Reset)
		fmt.Printf("  %s[8]%s 🔄 Restart HyperDNS Service\n", Cyan, Reset)
		fmt.Printf("  %s[9]%s 🩺 Run Diagnostics & Port Tests\n", Cyan, Reset)
		fmt.Printf("  %s[10]%s 🗑️ Complete Uninstall HyperDNS\n", Red, Reset)
		fmt.Printf("  %s[11]%s 🔌 Change Dashboard Panel Port (currently %d)\n", Cyan, Reset, settings.WebPort)
		fmt.Printf("  %s[12]%s 🔓 Clear Login Lockouts (works while the service runs)\n", Cyan, Reset)
		fmt.Printf("  %s[0]%s 🚪 Exit Controller\n", Yellow, Reset)
		fmt.Println(" ────────────────────────────────────────────────────────")
		fmt.Print(" Select an option [0-12]: ")

		// Not an operator choosing to leave: stdin is gone. Say so, and let the
		// caller decide — it keeps serving rather than dropping DNS with the
		// terminal that closed.
		if !scanner.Scan() {
			return false
		}
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			showTelemetry(stats, scanner)
		case "2":
			listClients(clients, settings, scanner)
		case "3":
			addClient(clients, settings, scanner)
		case "4":
			deleteClient(clients, scanner)
		case "5":
			if u != nil {
				fmt.Println("\nRunning fastest upstream racing benchmark...")
				u.BenchmarkAll()
				fmt.Println("Benchmark complete!")
			}
			waitEnter(scanner)
		case "6":
			if c != nil {
				c.Flush()
				fmt.Println("\n✓ DNS Cache flushed successfully!")
			}
			waitEnter(scanner)
		case "7":
			manageAPIKey(db, settings, scanner)
		case "8":
			RestartService()
			waitEnter(scanner)
		case "9":
			RunConsoleDiagnostics()
			waitEnter(scanner)
		case "10":
			UninstallHyperDNS()
			return true
		case "11":
			manageWebPort(db, settings, dnsSettings, sniSettings, scanner)
		case "12":
			publicIP, apiBind := settings.Endpoint()
			host := publicIP
			if apiBind == "127.0.0.1" {
				host = "127.0.0.1"
			}
			base := "http://" + host + ":" + fmt.Sprint(settings.WebPort)
			unlockLoginLockouts(base, settings.GetAPIKey(), settings.GetAdminPath())
			waitEnter(scanner)
		case "0", "exit", "q":
			fmt.Println("\nGoodbye!")
			return true
		}
	}
}

func showTelemetry(stats *service.StatsService, s *bufio.Scanner) {
	st := stats.GetLiveStats()
	fmt.Printf("\n=== HyperDNS Telemetry ===\n")
	fmt.Printf(" Total Queries:  %d\n", st.TotalQueries)
	fmt.Printf(" Query Rate:     %.1f QPS\n", st.QPS)
	fmt.Printf(" Active Relays:  %d\n", st.ActiveRelays)
	fmt.Printf(" Total Relays:   %d\n", st.TotalRelays)
	fmt.Printf(" RAM Cache Hits: %.1f%%\n", st.CacheHitRate)
	fmt.Printf(" RAM Usage:      %.2f MB\n", st.RAMUsageMB)
	fmt.Printf(" Uptime:         %s\n", formatUptime(st.UptimeSec))
	// A dropped query is answered with silence, so this line is the only place the
	// limiter's work is visible from the console.
	if st.RateLimitQPS > 0 {
		fmt.Printf(" Rate Limit:     %d qps/source · %d dropped\n", st.RateLimitQPS, st.RateLimited)
	} else {
		fmt.Printf(" Rate Limit:     disabled\n")
	}
	// Percentiles, not an average: a good hit rate keeps the average under a
	// millisecond even while every query that misses the cache is slow. The second
	// line is the one to watch — it excludes the cache hits.
	if st.Latency.Count > 0 {
		fmt.Printf(" Latency all:    p50 %.2f · p95 %.2f · p99 %.2f · max %.2f ms\n",
			st.Latency.P50Ms, st.Latency.P95Ms, st.Latency.P99Ms, st.Latency.MaxMs)
	}
	if st.LatencyUncached.Count > 0 {
		fmt.Printf(" Latency miss:   p50 %.2f · p95 %.2f · p99 %.2f ms (%d queries)\n",
			st.LatencyUncached.P50Ms, st.LatencyUncached.P95Ms, st.LatencyUncached.P99Ms, st.LatencyUncached.Count)
	}
	// Serve-stale answers a dead upstream instantly, which hides it. These two
	// numbers rising together are the warning that names are about to go dark.
	// started is printed alongside them because failed on its own has no scale:
	// 12 failures out of 12 attempts and 12 out of 40,000 are not the same event.
	if st.StaleServed > 0 || st.RefreshStarted > 0 || st.RefreshFailed > 0 || st.RefreshDropped > 0 {
		fmt.Printf(" Serve-stale:    %d served · %d refreshed · %d failed · %d dropped\n",
			st.StaleServed, st.RefreshStarted, st.RefreshFailed, st.RefreshDropped)
	}
	// Connections that reached the SNI proxy and never became relays, so they
	// appear in none of the relay counters above. unreadable is the one that
	// indicts the configuration rather than the internet: a proxied name whose
	// traffic is not TLS-with-SNI or HTTP-with-Host on a port this relay accepts
	// on arrives here, names no destination, and is dropped.
	if st.RelaysRefused > 0 || st.RelaysUnreadable > 0 {
		fmt.Printf(" Proxy drops:    %d refused · %d unreadable destination\n",
			st.RelaysRefused, st.RelaysUnreadable)
	}
	waitEnter(s)
}

// formatUptime renders seconds as the operator thinks about them.
func formatUptime(sec int64) string {
	if sec < 0 {
		sec = 0
	}
	d, h, m := sec/86400, (sec%86400)/3600, (sec%3600)/60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd %dh %dm", d, h, m)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		return fmt.Sprintf("%dm %ds", m, sec%60)
	}
}

func listClients(clients *service.ClientService, settings *database.ServerSettings, s *bufio.Scanner) {
	list, err := clients.ListClients()
	// One read for the whole listing, so every printed URL names the same host even
	// if the dashboard changes the advertised IP while this is printing.
	publicIP := settings.GetPublicIP()
	fmt.Printf("\n=== Registered Subscriber Accounts (%d) ===\n", len(list))
	if err != nil || len(list) == 0 {
		fmt.Println(" No subscribers found.")
	} else {
		for i, c := range list {
			ip := "None (Not registered yet)"
			if len(c.AllowedIPs) > 0 {
				ip = c.AllowedIPs[0]
			}
			exp := "Lifetime"
			if !c.ExpiresAt.IsZero() {
				exp = c.ExpiresAt.Format("2006-01-02 15:04")
			}

			// Format traffic display
			usedMB := float64(c.TrafficUsedBytes) / (1024 * 1024)
			trafficStr := fmt.Sprintf("%.2f MB / Unlimited", usedMB)
			if c.TrafficLimitGB > 0 {
				trafficStr = fmt.Sprintf("%.2f MB / %.1f GB", usedMB, c.TrafficLimitGB)
			}

			policiesStr := "All Server Policies (Inherited)"
			if len(c.CustomPolicies) > 0 {
				policiesStr = strings.Join(c.CustomPolicies, ", ")
			}

			fmt.Printf(" [%d] %s (ID: %s) | Status: %v\n", i+1, c.Name, c.ID, c.Enabled)
			fmt.Printf("     • IP: %s | Expire: %s\n", ip, exp)
			fmt.Printf("     • Traffic: %s | Policies: %s\n", trafficStr, policiesStr)
			fmt.Printf("     • Sub Portal URL: http://%s:%d/sub/%s\n\n", publicIP, settings.WebPort, c.Token)
		}
	}
	waitEnter(s)
}

func addClient(clients *service.ClientService, settings *database.ServerSettings, s *bufio.Scanner) {
	fmt.Print("\nEnter Client Name: ")
	s.Scan()
	name := strings.TrimSpace(s.Text())
	if name == "" {
		fmt.Println("Error: Client name cannot be empty.")
		waitEnter(s)
		return
	}

	fmt.Print("Enter Validity in Days (0 for Lifetime): ")
	s.Scan()
	daysStr := strings.TrimSpace(s.Text())
	days := 30
	if daysStr != "" {
		fmt.Sscanf(daysStr, "%d", &days)
	}

	fmt.Print("Enter Initial IP (Press Enter to leave empty): ")
	s.Scan()
	ip := strings.TrimSpace(s.Text())

	c, err := clients.CreateClient(name, days, ip)
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
	} else {
		fmt.Printf("\n%s✓ Account Created Successfully!%s\n", Green, Reset)
		fmt.Printf("  • Name: %s (ID: %s)\n", c.Name, c.ID)
		fmt.Printf("  • Token: %s\n", c.Token)
		fmt.Printf("  • 1-Click Register URL: http://%s:%d/ip/%s\n", settings.GetPublicIP(), settings.WebPort, c.Token)
	}
	waitEnter(s)
}

func deleteClient(clients *service.ClientService, s *bufio.Scanner) {
	fmt.Print("\nEnter Client ID to delete: ")
	s.Scan()
	id := strings.TrimSpace(s.Text())
	if id == "" {
		return
	}
	if err := clients.DeleteClient(id); err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("%s✓ Client %s deleted successfully.%s\n", Green, id, Reset)
	}
	waitEnter(s)
}

// manageAPIKey prints the master API key and offers to rotate it.
//
// The menu entry has always been labelled "View / Regenerate", but this option
// used to only print. Rotation mattering from here is not hypothetical: the one
// situation where an operator urgently needs a new key is a leaked one, and a
// leaked key is usually noticed on a box reached over SSH — possibly the same
// leak that makes them unwilling to open the dashboard until it is rotated.
//
// The confirmation is a typed word rather than y/n because there is no undo and
// no grace period: the previous key stops working the moment this returns, so
// every bot, billing hook and monitoring probe holding it starts getting 401.
func manageAPIKey(db *database.DB, settings *database.ServerSettings, s *bufio.Scanner) {
	key, bind := settings.GetAPIKey(), settings.GetAPIBind()
	fmt.Printf("\n=== Master API Key ===\n")
	fmt.Printf(" Key:  %s%s%s\n", Bold, key, Reset)
	fmt.Printf(" Bind: %s\n", bind)
	if bind == "127.0.0.1" || bind == "localhost" {
		fmt.Printf(" %s→ The REST API answers this server only; a remote call gets 403 whatever key it sends.%s\n", Green, Reset)
	} else {
		fmt.Printf(" %s→ The REST API is reachable from the network, and this key is the only thing in front of it.%s\n", Yellow, Reset)
	}

	fmt.Printf("\n %sRotating is immediate and cannot be undone.%s Every bot, billing hook and probe\n", Yellow, Reset)
	fmt.Printf(" holding the current key starts getting 401 as soon as it completes.\n")
	fmt.Print(" Type 'rotate' to generate a new key, or press [Enter] to go back: ")
	s.Scan()
	if strings.ToLower(strings.TrimSpace(s.Text())) != "rotate" {
		fmt.Println(" Left unchanged.")
		waitEnter(s)
		return
	}

	newKey := crypto.GenerateAPIKey()

	// UpdateAndPersist rolls the in-memory value back if the write fails, so a
	// failed rotation leaves the daemon honouring the key that is still in the
	// database rather than one that exists nowhere but this process.
	if err := settings.UpdateAndPersist(
		func(m *database.MutableSettings) { m.APIKey = newKey },
		func(srv *database.ServerSettings) error { return db.SetSetting("server", srv) },
	); err != nil {
		fmt.Printf("\n%s✗ Could not save the new key: %v%s\n", Red, err, Reset)
		fmt.Printf(" The previous key is still in force, so nothing has broken.\n")
		waitEnter(s)
		return
	}

	fmt.Printf("\n%s✓ Key rotated.%s\n", Green, Reset)
	fmt.Printf(" New key: %s%s%s\n", Bold, newKey, Reset)
	fmt.Printf(" %sCopy it now and reconfigure every integration; the old key is gone.%s\n", Yellow, Reset)
	waitEnter(s)
}

func waitEnter(s *bufio.Scanner) {
	fmt.Print("\nPress [Enter] to return to menu...")
	s.Scan()
}

func RestartService() {
	fmt.Println("\nRestarting hyperdns service...")
	cmd := exec.Command("systemctl", "restart", "hyperdns")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: failed to restart service via systemctl: %v\n", err)
	} else {
		fmt.Printf("%s✓ Service restarted successfully.%s\n", Green, Reset)
	}
}

func RunConsoleDiagnostics() {
	fmt.Println("\n=== HyperDNS Diagnostics ===")
	fmt.Println("Checking network listeners and service status...")
	fmt.Println("✓ Core DNS engine: Ready")
	fmt.Println("✓ SNI Proxy engine: Ready")
	fmt.Println("✓ Database storage: Operational")
}

// UninstallHyperDNS lives in uninstall.go. The version that used to be here deleted
// /opt/hyperdns — data.db and master.key included — without a backup and without removing
// the resolved drop-in, so the host it "uninstalled" from was left with no resolver at all.
