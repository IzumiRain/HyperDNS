package sniproxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperdns/internal/config"
)

type ProxyStats struct {
	ActiveConns uint64 `json:"active_conns"`
	TotalConns  uint64 `json:"total_conns"`
	BytesIn     uint64 `json:"bytes_in"`
	BytesOut    uint64 `json:"bytes_out"`
}

type Server struct {
	cfg         *config.Config
	listeners   []net.Listener
	activeConns int64
	totalConns  uint64
	bytesIn     uint64
	bytesOut    uint64
	mu          sync.Mutex
	running     bool
}

func NewServer(cfg *config.Config) *Server {
	return &Server{
		cfg:       cfg,
		listeners: make([]net.Listener, 0),
	}
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running || !s.cfg.SNIProxy.Enabled {
		return nil
	}

	host := s.cfg.Server.BindHost
	if host == "" {
		host = "0.0.0.0"
	}

	// 1. Standard HTTPS Listener (Port 443)
	if s.cfg.SNIProxy.HTTPSPort > 0 {
		s.startListener(fmt.Sprintf("%s:%d", host, s.cfg.SNIProxy.HTTPSPort), true, s.cfg.SNIProxy.HTTPSPort, "HTTPS SNI Proxy")
	}

	// 2. Standard HTTP Listener (Port 80)
	if s.cfg.SNIProxy.HTTPPort > 0 {
		s.startListener(fmt.Sprintf("%s:%d", host, s.cfg.SNIProxy.HTTPPort), false, s.cfg.SNIProxy.HTTPPort, "HTTP Proxy")
	}

	// 3. Gaming Chat & Presence TLS (Port 5223 - Riot/Blizzard/Valorant XMPP TLS)
	s.startListener(fmt.Sprintf("%s:5223", host), true, 5223, "Gaming Chat TLS (5223)")

	// 4. Gaming Chat XMPP (Port 5222)
	s.startListener(fmt.Sprintf("%s:5222", host), true, 5222, "Gaming Chat XMPP (5222)")

	// 5. Riot Games PVP.net RTM (Port 2099)
	s.startListener(fmt.Sprintf("%s:2099", host), true, 2099, "Riot PVP.net RTM (2099)")

	// 6. Riot Games PVP.net Patcher/Assets (Port 8393)
	s.startListener(fmt.Sprintf("%s:8393", host), true, 8393, "Riot Patcher (8393)")

	s.running = true
	return nil
}

func (s *Server) startListener(addr string, isTLS bool, defaultPort int, name string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[SNI Proxy] Warning: Failed to bind %s on %s: %v", name, addr, err)
		return
	}
	s.listeners = append(s.listeners, ln)
	log.Printf("[SNI Proxy] Started %s on %s", name, addr)
	go s.acceptLoop(ln, isTLS, defaultPort)
}

func (s *Server) acceptLoop(ln net.Listener, isTLS bool, defaultPort int) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			if !s.running {
				return
			}
			continue
		}

		atomic.AddInt64(&s.activeConns, 1)
		atomic.AddUint64(&s.totalConns, 1)

		go s.handleConnection(clientConn, isTLS, defaultPort)
	}
}

func (s *Server) handleConnection(clientConn net.Conn, isTLS bool, defaultPort int) {
	defer func() {
		_ = clientConn.Close()
		atomic.AddInt64(&s.activeConns, -1)
	}()

	// 1. Client Access Whitelist Check
	remoteHost, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err == nil && !s.cfg.IsIPAllowed(remoteHost) {
		return
	}

	if tc, ok := clientConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 16384)
	n, err := clientConn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	data := buf[:n]
	var targetHost string

	if isTLS {
		// If TLS record header is present and we haven't received the full record, read remainder
		if len(data) >= 5 && data[0] == 0x16 {
			recordLen := int(data[3])<<8 | int(data[4])
			expected := 5 + recordLen
			if expected > len(buf) {
				expected = len(buf)
			}
			for len(data) < expected {
				more := make([]byte, expected-len(data))
				nr, err := clientConn.Read(more)
				if err != nil || nr == 0 {
					break
				}
				data = append(data, more[:nr]...)
			}
		}

		targetHost, err = ExtractSNI(data)
		if err != nil {
			return
		}
	} else {
		targetHost, err = ExtractHTTPHost(data)
		if err != nil {
			return
		}
	}

	// Reset read deadline to infinite for long-lived WebSockets, chats & streams
	_ = clientConn.SetReadDeadline(time.Time{})

	targetPort := defaultPort
	if targetPort <= 0 {
		if isTLS {
			targetPort = 443
		} else {
			targetPort = 80
		}
	}

	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

	// If the requested host is the server's own domain or IP, route locally to the Web Dashboard!
	if s.cfg.TLS.Domain != "" && strings.EqualFold(targetHost, s.cfg.TLS.Domain) {
		if isTLS {
			targetAddr = fmt.Sprintf("127.0.0.1:%d", s.cfg.DNS.DoHPort)
		} else {
			targetAddr = fmt.Sprintf("127.0.0.1:%d", s.cfg.Server.WebPort)
		}
	} else if (s.cfg.Server.PublicIP != "" && targetHost == s.cfg.Server.PublicIP) || targetHost == "localhost" {
		if isTLS {
			targetAddr = fmt.Sprintf("127.0.0.1:%d", s.cfg.DNS.DoHPort)
		} else {
			targetAddr = fmt.Sprintf("127.0.0.1:%d", s.cfg.Server.WebPort)
		}
	}

	// Dial target host with KeepAlive
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	remoteConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	if tc, ok := remoteConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// Send initial buffer to remote server (with optional anti-DPI fragmentation)
	if isTLS && s.cfg.SNIProxy.EnableFragmentation {
		err = SendFragmented(remoteConn, data, s.cfg.SNIProxy.FragmentSize, s.cfg.SNIProxy.FragmentDelayMs)
	} else {
		_, err = remoteConn.Write(data)
	}
	if err != nil {
		return
	}

	atomic.AddUint64(&s.bytesOut, uint64(len(data)))

	// Bidirectional stream relay with 32KB buffer for maximum throughput
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		copied, _ := io.CopyBuffer(remoteConn, clientConn, buf)
		atomic.AddUint64(&s.bytesOut, uint64(copied))
		if tc, ok := remoteConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		copied, _ := io.CopyBuffer(clientConn, remoteConn, buf)
		atomic.AddUint64(&s.bytesIn, uint64(copied))
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	for _, ln := range s.listeners {
		if ln != nil {
			_ = ln.Close()
		}
	}
	s.listeners = nil
	log.Println("[SNI Proxy] Stopped.")
}

func (s *Server) GetStats() ProxyStats {
	return ProxyStats{
		ActiveConns: uint64(atomic.LoadInt64(&s.activeConns)),
		TotalConns:  atomic.LoadUint64(&s.totalConns),
		BytesIn:     atomic.LoadUint64(&s.bytesIn),
		BytesOut:    atomic.LoadUint64(&s.bytesOut),
	}
}
