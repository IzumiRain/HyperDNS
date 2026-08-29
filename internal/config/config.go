package config

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	mu sync.RWMutex `json:"-"`

	Server   ServerConfig   `json:"server"`
	DNS      DNSConfig      `json:"dns"`
	SNIProxy SNIProxyConfig `json:"sniproxy"`
	Rules    RulesConfig    `json:"rules"`
	Access   AccessConfig   `json:"access"`
	TLS      TLSConfig      `json:"tls"`
}

type ServerConfig struct {
	PublicIP      string `json:"public_ip"`
	BindHost      string `json:"bind_host"`
	WebPort       int    `json:"web_port"`
	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`
	JWTSecret     string `json:"jwt_secret"`
}

type DNSConfig struct {
	Enabled       bool          `json:"enabled"`
	Port          int           `json:"port"`
	DoTPort       int           `json:"dot_port"`
	DoHPort       int           `json:"doh_port"`
	Upstreams     []string      `json:"upstreams"`
	CacheSize     int           `json:"cache_size"`
	CacheMinTTL   uint32        `json:"cache_min_ttl"`
	CacheMaxTTL   uint32        `json:"cache_max_ttl"`
	QueryTimeout  time.Duration `json:"query_timeout"`
	FastestRacing bool          `json:"fastest_racing"`
	ECSClientIP   string        `json:"ecs_client_ip"`
}

type SNIProxyConfig struct {
	Enabled             bool          `json:"enabled"`
	HTTPPort            int           `json:"http_port"`
	HTTPSPort           int           `json:"https_port"`
	Timeout             time.Duration `json:"timeout"`
	EnableFragmentation bool          `json:"enable_fragmentation"`
	FragmentSize        int           `json:"fragment_size"`
	FragmentDelayMs     int           `json:"fragment_delay_ms"`
}

type RulesConfig struct {
	EnableRiot        bool              `json:"enable_riot"`
	EnableEpic        bool              `json:"enable_epic"`
	EnableSteam       bool              `json:"enable_steam"`
	EnablePUBG        bool              `json:"enable_pubg"`
	EnableCallOfDuty  bool              `json:"enable_call_of_duty"`
	EnableSupercell   bool              `json:"enable_supercell"`
	EnableDiscord     bool              `json:"enable_discord"`
	EnableEA          bool              `json:"enable_ea"`
	EnableBlizzard    bool              `json:"enable_blizzard"`
	EnableUbisoft     bool              `json:"enable_ubisoft"`
	EnableRockstar    bool              `json:"enable_rockstar"`
	EnableXbox        bool              `json:"enable_xbox"`
	EnablePlayStation bool              `json:"enable_playstation"`
	EnableRoblox      bool              `json:"enable_roblox"`
	EnableSpotify     bool              `json:"enable_spotify"`
	EnableTwitch      bool              `json:"enable_twitch"`
	EnableKick        bool              `json:"enable_kick"`
	EnableDev403      bool              `json:"enable_dev403"`
	EnableAdBlock     bool              `json:"enable_adblock"`
	EnableFamilySafe  bool              `json:"enable_familysafe"`
	CustomProxied     []string          `json:"custom_proxied"`
	CustomBlocked     []string          `json:"custom_blocked"`
	CustomDirect      []string          `json:"custom_direct"`
	CustomRecords     map[string]string `json:"custom_records"`
}

type Client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Token        string    `json:"token"`
	AllowedIPs   []string  `json:"allowed_ips"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastSeen     time.Time `json:"last_seen"`
	TotalQueries uint64    `json:"total_queries"`
	Enabled      bool      `json:"enabled"`
}

type AccessConfig struct {
	AllowAll     bool     `json:"allow_all"`
	AllowedIPs   []string `json:"allowed_ips"`
	BlockedIPs   []string `json:"blocked_ips"`
	Clients      []Client `json:"clients"`
	DoHTokens    []string `json:"doh_tokens"`
	RateLimitQPS int      `json:"rate_limit_qps"`
}

type TLSConfig struct {
	AutoCert bool   `json:"auto_cert"`
	Domain   string `json:"domain"`
	Email    string `json:"email"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			PublicIP:      "",
			BindHost:      "0.0.0.0",
			WebPort:       8080,
			AdminUsername: "admin",
			AdminPassword: "admin", // Default is admin / admin
			JWTSecret:     "hyperdns-super-secret-key-change-me",
		},
		DNS: DNSConfig{
			Enabled:       true,
			Port:          53,
			DoTPort:       853,
			DoHPort:       8443,
			Upstreams:     []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53", "1.0.0.1:53"},
			CacheSize:     20000,
			CacheMinTTL:   60,
			CacheMaxTTL:   86400,
			QueryTimeout:  2500 * time.Millisecond,
			FastestRacing: true,
		},
		SNIProxy: SNIProxyConfig{
			Enabled:             true,
			HTTPPort:            80,
			HTTPSPort:           443,
			Timeout:             120 * time.Second,
			EnableFragmentation: false,
			FragmentSize:        2,
			FragmentDelayMs:     5,
		},
		Rules: RulesConfig{
			EnableRiot:        true,
			EnableEpic:        true,
			EnableSteam:       true,
			EnablePUBG:        true,
			EnableCallOfDuty:  true,
			EnableSupercell:   true,
			EnableDiscord:     true,
			EnableEA:          true,
			EnableBlizzard:    true,
			EnableUbisoft:     true,
			EnableRockstar:    true,
			EnableXbox:        true,
			EnablePlayStation: true,
			EnableRoblox:      true,
			EnableSpotify:     true,
			EnableTwitch:      true,
			EnableKick:        true,
			EnableDev403:      true,
			EnableAdBlock:     false,
			EnableFamilySafe:  false,
			CustomProxied:     []string{},
			CustomBlocked:     []string{},
			CustomDirect:      []string{},
			CustomRecords:     make(map[string]string),
		},
		Access: AccessConfig{
			AllowAll:     true,
			AllowedIPs:   []string{},
			BlockedIPs:   []string{},
			DoHTokens:    []string{},
			RateLimitQPS: 200,
		},
		TLS: TLSConfig{
			AutoCert: false,
			Domain:   "",
			Email:    "",
			CertFile: "certs/cert.pem",
			KeyFile:  "certs/key.pem",
		},
	}
}

func LoadConfig(filePath string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			_ = cfg.AutoDetectPublicIP()
			_ = cfg.Save(filePath)
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Server.PublicIP == "" {
		_ = cfg.AutoDetectPublicIP()
	}

	return cfg, nil
}

func (c *Config) Save(filePath string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}

func (c *Config) AutoDetectPublicIP() error {
	client := http.Client{Timeout: 3 * time.Second}
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://ipinfo.io/ip",
	}

	for _, ep := range endpoints {
		resp, err := client.Get(ep)
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ip := strings.TrimSpace(string(body))
			if ip != "" {
				c.mu.Lock()
				c.Server.PublicIP = ip
				c.mu.Unlock()
				return nil
			}
		}
	}
	return nil
}

func (c *Config) IsDefaultPassword() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Server.AdminPassword == "admin" || c.Server.AdminPassword == "hyperdnsadmin"
}

// IsIPAllowed checks if an IP is authorized to query DNS / SNI Proxy
func (c *Config) IsIPAllowed(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return false
	}

	// 1. Explicitly Blocked IPs
	for _, b := range c.Access.BlockedIPs {
		if strings.TrimSpace(b) == cleanIP {
			return false
		}
	}

	// 2. Open Public Mode
	if c.Access.AllowAll {
		return true
	}

	// 3. Global Allowed IPs
	for _, a := range c.Access.AllowedIPs {
		if strings.TrimSpace(a) == cleanIP {
			return true
		}
	}

	// 4. Client Whitelisted IPs
	now := time.Now()
	for _, cl := range c.Access.Clients {
		if !cl.Enabled {
			continue
		}
		if !cl.ExpiresAt.IsZero() && now.After(cl.ExpiresAt) {
			continue
		}
		for _, clientIP := range cl.AllowedIPs {
			if strings.TrimSpace(clientIP) == cleanIP {
				return true
			}
		}
	}

	return false
}

// IncrementClientQuery increments query counter for the matching client
func (c *Config) IncrementClientQuery(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cleanIP := strings.TrimSpace(ip)
	for i := range c.Access.Clients {
		for _, clientIP := range c.Access.Clients[i].AllowedIPs {
			if strings.TrimSpace(clientIP) == cleanIP {
				c.Access.Clients[i].TotalQueries++
				c.Access.Clients[i].LastSeen = time.Now()
				return
			}
		}
	}
}

// RegisterClientIP adds or updates a client's IP via auto registration token
func (c *Config) RegisterClientIP(token, ip string) (*Client, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cleanToken := strings.TrimSpace(token)
	cleanIP := strings.TrimSpace(ip)
	if cleanToken == "" || cleanIP == "" {
		return nil, false, os.ErrInvalid
	}

	now := time.Now()
	for i := range c.Access.Clients {
		if c.Access.Clients[i].Token == cleanToken {
			if !c.Access.Clients[i].ExpiresAt.IsZero() && now.After(c.Access.Clients[i].ExpiresAt) {
				return &c.Access.Clients[i], false, os.ErrDeadlineExceeded
			}

			// Add IP if not already present
			alreadyPresent := false
			for _, existingIP := range c.Access.Clients[i].AllowedIPs {
				if strings.TrimSpace(existingIP) == cleanIP {
					alreadyPresent = true
					break
				}
			}

			if !alreadyPresent {
				c.Access.Clients[i].AllowedIPs = append(c.Access.Clients[i].AllowedIPs, cleanIP)
			}
			c.Access.Clients[i].LastSeen = now
			return &c.Access.Clients[i], alreadyPresent, nil
		}
	}

	return nil, false, os.ErrNotExist
}

// GetClients returns a copy of all clients
func (c *Config) GetClients() []Client {
	c.mu.RLock()
	defer c.mu.RUnlock()

	res := make([]Client, len(c.Access.Clients))
	copy(res, c.Access.Clients)
	return res
}

// AddClient adds a new client
func (c *Config) AddClient(client Client) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Access.Clients = append(c.Access.Clients, client)
}

// DeleteClient removes a client by ID
func (c *Config) DeleteClient(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	initialLen := len(c.Access.Clients)
	newClients := make([]Client, 0, initialLen)
	for _, cl := range c.Access.Clients {
		if cl.ID != id {
			newClients = append(newClients, cl)
		}
	}
	c.Access.Clients = newClients
	return len(c.Access.Clients) < initialLen
}

// ToggleClient toggles client enabled status
func (c *Config) ToggleClient(id string, enabled bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.Access.Clients {
		if c.Access.Clients[i].ID == id {
			c.Access.Clients[i].Enabled = enabled
			return true
		}
	}
	return false
}

// AddClientIP adds an IP manually to a client
func (c *Config) AddClientIP(id, ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return false
	}

	for i := range c.Access.Clients {
		if c.Access.Clients[i].ID == id {
			for _, existingIP := range c.Access.Clients[i].AllowedIPs {
				if strings.TrimSpace(existingIP) == cleanIP {
					return true
				}
			}
			c.Access.Clients[i].AllowedIPs = append(c.Access.Clients[i].AllowedIPs, cleanIP)
			return true
		}
	}
	return false
}

// RemoveClientIP removes an IP from a client
func (c *Config) RemoveClientIP(id, ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	cleanIP := strings.TrimSpace(ip)
	for i := range c.Access.Clients {
		if c.Access.Clients[i].ID == id {
			newIPs := make([]string, 0, len(c.Access.Clients[i].AllowedIPs))
			for _, existingIP := range c.Access.Clients[i].AllowedIPs {
				if strings.TrimSpace(existingIP) != cleanIP {
					newIPs = append(newIPs, existingIP)
				}
			}
			c.Access.Clients[i].AllowedIPs = newIPs
			return true
		}
	}
	return false
}

// RenewClient extends client expiration
func (c *Config) RenewClient(id string, extendDays int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.Access.Clients {
		if c.Access.Clients[i].ID == id {
			if extendDays <= 0 {
				c.Access.Clients[i].ExpiresAt = time.Time{} // Unlimited
			} else {
				baseTime := time.Now()
				if !c.Access.Clients[i].ExpiresAt.IsZero() && c.Access.Clients[i].ExpiresAt.After(baseTime) {
					baseTime = c.Access.Clients[i].ExpiresAt
				}
				c.Access.Clients[i].ExpiresAt = baseTime.Add(time.Duration(extendDays) * 24 * time.Hour)
			}
			return true
		}
	}
	return false
}
