package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"hyperdns/internal/cert"
	"hyperdns/internal/config"
	"hyperdns/internal/dns"
	"hyperdns/internal/rules"
	"hyperdns/internal/sniproxy"
	"hyperdns/internal/tui"
	"hyperdns/internal/web"
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
	configPath := flag.String("config", "", "Path to configuration file")
	bindHost := flag.String("host", "", "Override bind host IP (e.g. 0.0.0.0)")
	dnsPort := flag.Int("dns-port", 0, "Override DNS Port (e.g. 53)")
	webPort := flag.Int("web-port", 0, "Override Web Dashboard Port (e.g. 8080)")
	publicIP := flag.String("public-ip", "", "Override Server Public IP")
	daemonMode := flag.Bool("daemon", false, "Run as background server engine (for systemd)")
	serverMode := flag.Bool("server", false, "Run as background server engine")
	enableTUI := flag.Bool("tui", false, "Launch interactive Terminal User Interface (TUI)")
	flag.Parse()

	// Find config file path
	cPath := *configPath
	if cPath == "" {
		if _, err := os.Stat("/opt/hyperdns/config.json"); err == nil {
			cPath = "/opt/hyperdns/config.json"
		} else if _, err := os.Stat("config.json"); err == nil {
			cPath = "config.json"
		} else {
			cPath = "/opt/hyperdns/config.json"
		}
	}

	args := flag.Args()

	// 1. Handle CLI subcommands if specified
	if len(args) > 0 {
		subcmd := strings.ToLower(args[0])
		switch subcmd {
		case "status":
			tui.PrintStatus(cPath)
			return
		case "restart":
			tui.RestartService()
			return
		case "stop":
			tui.StopService()
			return
		case "start":
			tui.StartService()
			return
		case "logs", "log":
			tui.StreamLogs()
			return
		case "flush":
			tui.FlushCacheDirect(cPath)
			return
		case "diag", "diagnostics", "test":
			tui.RunConsoleDiagnostics(cPath)
			return
		case "clients":
			tui.ListClients(cPath)
			return
		case "uninstall", "remove":
			tui.UninstallHyperDNS(cPath)
			return
		case "help", "-h", "--help":
			tui.PrintHelp()
			return
		}
	}

	// 2. Determine mode: Server Engine vs Interactive TUI Manager
	// Check if stdin is an interactive terminal
	isTerminal := false
	if fi, err := os.Stdin.Stat(); err == nil {
		isTerminal = (fi.Mode() & os.ModeCharDevice) != 0
	}

	// If interactive terminal and no server/daemon flag and no explicit -config flag, launch TUI
	if isTerminal && !*daemonMode && !*serverMode && *configPath == "" {
		tui.RunInteractiveManager(cPath)
		return
	}

	// 3. Otherwise, run the Server Engine (daemon mode)
	fmt.Print(banner)

	// Load Configuration
	cfg, err := config.LoadConfig(cPath)
	if err != nil {
		log.Fatalf("[Main] Failed to load config from %s: %v", cPath, err)
	}

	// Apply CLI flag overrides if specified
	if *bindHost != "" {
		cfg.Server.BindHost = *bindHost
	}
	if *dnsPort > 0 {
		cfg.DNS.Port = *dnsPort
	}
	if *webPort > 0 {
		cfg.Server.WebPort = *webPort
	}
	if *publicIP != "" {
		cfg.Server.PublicIP = *publicIP
	}

	if !*enableTUI {
		log.Printf("[Main] Initializing HyperDNS Server (Public IP: %s)...", cfg.Server.PublicIP)
	}

	// 2. Initialize TLS Configuration (Self-signed or Custom)
	tlsConfig, err := cert.LoadOrGenerateTLSConfig(cfg)
	if err != nil && !*enableTUI {
		log.Printf("[Main] Warning: Failed to initialize TLS config: %v", err)
	}

	// 3. Initialize Rule Matcher
	matcher := rules.NewMatcher(cfg)

	// 4. Initialize DNS Cache
	cache := dns.NewCache(cfg.DNS.CacheSize, cfg.DNS.CacheMinTTL, cfg.DNS.CacheMaxTTL)

	// 5. Initialize Upstream Resolver Pool
	upstreams := dns.NewUpstreamPool(cfg.DNS.Upstreams, cfg.DNS.QueryTimeout, cfg.DNS.FastestRacing, cfg.DNS.ECSClientIP)

	// 6. Initialize DNS Handler & SNI Proxy Server
	dnsHandler := dns.NewHandler(cfg, cache, matcher, upstreams)
	sniServer := sniproxy.NewServer(cfg)

	// 7. Initialize Stats Collector
	statsCollector := web.NewStatsCollector(dnsHandler, cache, sniServer)

	// 8. Initialize Web Dashboard Server
	webServer := web.NewWebServer(
		cfg,
		cPath,
		matcher,
		cache,
		upstreams,
		dnsHandler,
		statsCollector,
		webAssets.StaticFS,
	)

	// 9. Initialize DNS Handler & Server (with HTTPS web handler on 8443)
	dnsServer := dns.NewServer(cfg, dnsHandler, tlsConfig, webServer.BuildHandler())

	// Start Services
	if cfg.DNS.Enabled {
		if err := dnsServer.Start(); err != nil {
			log.Fatalf("[Main] Failed to start DNS Server: %v", err)
		}
	}

	if cfg.SNIProxy.Enabled {
		if err := sniServer.Start(); err != nil && !*enableTUI {
			log.Printf("[Main] Warning: Failed to start SNI Proxy: %v", err)
		}
	}

	if err := webServer.Start(); err != nil {
		log.Fatalf("[Main] Failed to start Web Server: %v", err)
	}

	// 10. Start 1-Minute Periodic Expiration Watcher for Client Accounts
	stopWatcher := cfg.StartExpirationWatcher(1*time.Minute, cPath)
	defer stopWatcher()

	if !*enableTUI {
		log.Println("================================================================")
		log.Printf(" HyperDNS Dashboard : http://%s:%d", cfg.Server.BindHost, cfg.Server.WebPort)
		log.Printf(" Standard DNS       : %s:%d (UDP/TCP)", cfg.Server.BindHost, cfg.DNS.Port)
		log.Printf(" DNS-over-TLS (DoT) : %s:%d (TCP/TLS)", cfg.Server.BindHost, cfg.DNS.DoTPort)
		log.Printf(" DNS-over-HTTPS     : https://%s:%d/dns-query", cfg.Server.BindHost, cfg.DNS.DoHPort)
		log.Printf(" SNI Proxy Relays   : Ports %d (HTTP) and %d (HTTPS)", cfg.SNIProxy.HTTPPort, cfg.SNIProxy.HTTPSPort)
		log.Println("================================================================")

		// Wait for termination signal in normal daemon mode
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
	} else {
		// Launch interactive Terminal User Interface (TUI)
		terminalUI := tui.NewTUI(cfg, *configPath, matcher, cache, upstreams, dnsHandler, sniServer, statsCollector)
		terminalUI.Run()
	}

	log.Println("[Main] Shutting down HyperDNS services...")
	dnsServer.Stop()
	sniServer.Stop()
	webServer.Stop()
	log.Println("[Main] Goodbye!")
}
