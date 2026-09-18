package dns

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/config"
)

type Server struct {
	cfg        *config.Config
	handler    *Handler
	dohHandler *DoHHandler
	webHandler http.Handler
	udpServer  *dns.Server
	tcpServer  *dns.Server
	dotServer  *dns.Server
	dohServer  *http.Server
	tlsConfig  *tls.Config
	mu         sync.Mutex
	running    bool
}

func NewServer(cfg *config.Config, handler *Handler, tlsCfg *tls.Config, webHandler http.Handler) *Server {
	return &Server{
		cfg:        cfg,
		handler:    handler,
		dohHandler: NewDoHHandler(handler),
		webHandler: webHandler,
		tlsConfig:  tlsCfg,
	}
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	host := s.cfg.Server.BindHost
	if host == "" {
		host = "0.0.0.0"
	}

	dnsAddr := fmt.Sprintf("%s:%d", host, s.cfg.DNS.Port)

	// 1. Start UDP Listener
	s.udpServer = &dns.Server{
		Addr:    dnsAddr,
		Net:     "udp",
		Handler: s.handler,
		UDPSize: 4096,
	}
	go func() {
		log.Printf("[DNS] Starting UDP listener on %s", dnsAddr)
		if err := s.udpServer.ListenAndServe(); err != nil {
			log.Printf("[DNS] UDP listener stopped: %v", err)
		}
	}()

	// 2. Start TCP Listener
	s.tcpServer = &dns.Server{
		Addr:    dnsAddr,
		Net:     "tcp",
		Handler: s.handler,
	}
	go func() {
		log.Printf("[DNS] Starting TCP listener on %s", dnsAddr)
		if err := s.tcpServer.ListenAndServe(); err != nil {
			log.Printf("[DNS] TCP listener stopped: %v", err)
		}
	}()

	// 3. Start DoT (DNS-over-TLS) Listener if TLS config is available
	if s.tlsConfig != nil && s.cfg.DNS.DoTPort > 0 {
		dotAddr := fmt.Sprintf("%s:%d", host, s.cfg.DNS.DoTPort)
		s.dotServer = &dns.Server{
			Addr:      dotAddr,
			Net:       "tcp-tls",
			Handler:   s.handler,
			TLSConfig: s.tlsConfig,
		}
		go func() {
			log.Printf("[DNS] Starting DoT (DNS-over-TLS) on %s", dotAddr)
			if err := s.dotServer.ListenAndServe(); err != nil {
				log.Printf("[DNS] DoT listener stopped: %v", err)
			}
		}()
	}

	// 4. Start Standalone DoH & HTTPS Web Listener (Port 8443)
	if s.cfg.DNS.DoHPort > 0 {
		dohAddr := fmt.Sprintf("%s:%d", host, s.cfg.DNS.DoHPort)
		
		handlerToUse := s.webHandler
		if handlerToUse == nil {
			mux := http.NewServeMux()
			mux.Handle("/dns-query", s.dohHandler)
			handlerToUse = mux
		}

		s.dohServer = &http.Server{
			Addr:         dohAddr,
			Handler:      handlerToUse,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig:    s.tlsConfig,
		}

		go func() {
			if s.tlsConfig != nil {
				log.Printf("[DNS] Starting HTTPS Web & DoH on https://%s/dashboard (and /dns-query)", dohAddr)
				if err := s.dohServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					log.Printf("[DNS] HTTPS/DoH TLS server stopped: %v", err)
				}
			} else {
				log.Printf("[DNS] Starting DoH (HTTP) on http://%s/dns-query", dohAddr)
				if err := s.dohServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("[DNS] DoH HTTP server stopped: %v", err)
				}
			}
		}()
	}

	s.running = true
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	if s.udpServer != nil {
		_ = s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		_ = s.tcpServer.Shutdown()
	}
	if s.dotServer != nil {
		_ = s.dotServer.Shutdown()
	}
	if s.dohServer != nil {
		_ = s.dohServer.Close()
	}

	s.running = false
	log.Println("[DNS] All DNS services stopped.")
}
