// Command-line configuration file support.
//
// The installers pass "-config /opt/hyperdns/config.json" to the daemon.
// The file mirrors config.example.json and supplies the *default* values that
// are used when the BoltDB has no persisted value yet (fresh install).
// Any value already stored in the database always wins over the file.
package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"hyperdns/internal/core/matcher"
	"hyperdns/internal/database"
)

// sniProxyFile mirrors the SNI proxy block of config.json.
type sniProxyFile struct {
	Enabled             *bool  `json:"enabled"`
	HTTPPort            *int   `json:"http_port"`
	HTTPSPort           *int   `json:"https_port"`
	GameChatTLSPort     *int   `json:"game_chat_tls_port"`
	GameChatXMPPPort    *int   `json:"game_chat_xmpp_port"`
	RiotRTMPort         *int   `json:"riot_rtm_port"`
	RiotPatcherPort     *int   `json:"riot_patcher_port"`
	Timeout             *int64 `json:"timeout"`
	EnableFragmentation *bool  `json:"enable_fragmentation"`
	FragmentSize        *int   `json:"fragment_size"`
	FragmentDelayMs     *int   `json:"fragment_delay_ms"`
}

// accessFile mirrors the "access" block of config.json.
type accessFile struct {
	AllowAll     *bool     `json:"allow_all"`
	AllowedIPs   *[]string `json:"allowed_ips"`
	BlockedIPs   *[]string `json:"blocked_ips"`
	DoHTokens    *[]string `json:"doh_tokens"`
	RateLimitQPS *int      `json:"rate_limit_qps"`
}

// AccessConfig is the resolved access-control block handed back to main so it
// can seed first-run defaults. Present* flags distinguish "absent from file"
// from "explicitly set to the zero value".
type AccessConfig struct {
	AllowAll        bool
	PresentAllowAll bool
	AllowedIPs      []string
	BlockedIPs      []string
	DoHTokens       []string
	// RateLimitQPS is the per-source query cap. PresentRateLimit distinguishes an
	// explicit 0 — the operator turning limiting off — from the key being absent,
	// which leaves the built-in default in place.
	RateLimitQPS     int
	PresentRateLimit bool
}

// fileConfig mirrors the on-disk config.json schema. The SNI proxy block is
// accepted under both "sniproxy" (what every shipped config and installer
// writes) and the legacy "sni_proxy" spelling.
type fileConfig struct {
	Server *struct {
		PublicIP      *string `json:"public_ip"`
		BindHost      *string `json:"bind_host"`
		WebPort       *int    `json:"web_port"`
		AdminUsername *string `json:"admin_username"`
		AdminPassword *string `json:"admin_password"`
		APIKey        *string `json:"api_key"`
		APIBind       *string `json:"api_bind"`
	} `json:"server"`
	DNS *struct {
		Enabled       *bool     `json:"enabled"`
		Port          *int      `json:"port"`
		DoTPort       *int      `json:"dot_port"`
		DoHPort       *int      `json:"doh_port"`
		Upstreams     *[]string `json:"upstreams"`
		CacheSize     *int      `json:"cache_size"`
		CacheMinTTL   *uint32   `json:"cache_min_ttl"`
		CacheMaxTTL   *uint32   `json:"cache_max_ttl"`
		QueryTimeout  *int64    `json:"query_timeout"`
		FastestRacing *bool     `json:"fastest_racing"`
		ECSClientIP   *string   `json:"ecs_client_ip"`
		// Pointer, like every other key here, so that an explicit 0 turns
		// serve-stale off while an absent key keeps the built-in default.
		ServeStaleSeconds *uint32 `json:"serve_stale_seconds"`
	} `json:"dns"`
	SNIProxy       *sniProxyFile `json:"sniproxy"`
	SNIProxyLegacy *sniProxyFile `json:"sni_proxy"`
	Access         *accessFile   `json:"access"`
	TLS            *struct {
		AutoCert *bool   `json:"auto_cert"`
		Domain   *string `json:"domain"`
		Email    *string `json:"email"`
		CertFile *string `json:"cert_file"`
		KeyFile  *string `json:"key_file"`
	} `json:"tls"`
	Rules map[string]any `json:"rules"`
}

// applyConfigFile loads and merges a config.json file into the given settings
// structures. Only fields present in the file are applied. The returned
// AccessConfig is nil when the file has no "access" block.
func applyConfigFile(path string, server *database.ServerSettings, dns *database.DNSSettings, sni *database.SNIProxySettings, tls *database.TLSSettings) *AccessConfig {
	if path == "" || server == nil || dns == nil || sni == nil || tls == nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // file absent is fine — defaults & DB govern
	}
	var cfg fileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[Main] Warning: could not parse config file %s: %v", path, err)
		return nil
	}

	if s := cfg.Server; s != nil {
		if s.PublicIP != nil {
			server.PublicIP = *s.PublicIP
		}
		if s.BindHost != nil {
			server.BindHost = *s.BindHost
		}
		if s.WebPort != nil {
			server.WebPort = *s.WebPort
		}
		if s.AdminUsername != nil {
			server.AdminUsername = *s.AdminUsername
		}
		if s.AdminPassword != nil {
			server.AdminPassword = *s.AdminPassword
		}
		if s.APIKey != nil {
			server.APIKey = *s.APIKey
		}
		if s.APIBind != nil {
			server.APIBind = *s.APIBind
		}
	}

	if d := cfg.DNS; d != nil {
		if d.Enabled != nil {
			dns.Enabled = *d.Enabled
		}
		if d.Port != nil {
			dns.Port = *d.Port
		}
		if d.DoTPort != nil {
			dns.DoTPort = *d.DoTPort
		}
		if d.DoHPort != nil {
			dns.DoHPort = *d.DoHPort
		}
		if d.Upstreams != nil {
			dns.Upstreams = *d.Upstreams
		}
		if d.CacheSize != nil {
			dns.CacheSize = *d.CacheSize
		}
		if d.CacheMinTTL != nil {
			dns.CacheMinTTL = *d.CacheMinTTL
		}
		if d.CacheMaxTTL != nil {
			dns.CacheMaxTTL = *d.CacheMaxTTL
		}
		if d.QueryTimeout != nil {
			dns.QueryTimeout = time.Duration(*d.QueryTimeout)
		}
		if d.FastestRacing != nil {
			dns.FastestRacing = *d.FastestRacing
		}
		if d.ECSClientIP != nil {
			dns.ECSClientIP = *d.ECSClientIP
		}
		if d.ServeStaleSeconds != nil {
			dns.ServeStaleSeconds = *d.ServeStaleSeconds
		}
	}

	if s := cfg.SNIProxy; s != nil || cfg.SNIProxyLegacy != nil {
		if s == nil {
			s = cfg.SNIProxyLegacy
		}
		if s.Enabled != nil {
			sni.Enabled = *s.Enabled
		}
		if s.HTTPPort != nil {
			sni.HTTPPort = *s.HTTPPort
		}
		if s.HTTPSPort != nil {
			sni.HTTPSPort = *s.HTTPSPort
		}
		// The four extra game listeners. A file that predates v2.2.0 names none
		// of them, and the historical defaults set in main stand.
		if s.GameChatTLSPort != nil {
			sni.GameChatTLSPort = *s.GameChatTLSPort
		}
		if s.GameChatXMPPPort != nil {
			sni.GameChatXMPPPort = *s.GameChatXMPPPort
		}
		if s.RiotRTMPort != nil {
			sni.RiotRTMPort = *s.RiotRTMPort
		}
		if s.RiotPatcherPort != nil {
			sni.RiotPatcherPort = *s.RiotPatcherPort
		}
		if s.Timeout != nil {
			sni.Timeout = time.Duration(*s.Timeout)
		}
		if s.EnableFragmentation != nil {
			sni.EnableFragmentation = *s.EnableFragmentation
		}
		if s.FragmentSize != nil {
			sni.FragmentSize = *s.FragmentSize
		}
		if s.FragmentDelayMs != nil {
			sni.FragmentDelayMs = *s.FragmentDelayMs
		}
	}

	if t := cfg.TLS; t != nil {
		if t.AutoCert != nil {
			tls.AutoRenewACME = *t.AutoCert
		}
		if t.Domain != nil {
			tls.Domain = *t.Domain
			// A non-empty domain implies the panel serves TLS (v2.1.0 installer
			// contract). An explicitly empty domain is the supported loopback-only
			// development/recovery mode and must remain HTTP; otherwise startup tries
			// to validate a CA certificate for no hostname and fails closed.
			tls.PanelHTTPS = strings.TrimSpace(*t.Domain) != ""
		}
		if t.Email != nil {
			tls.Email = *t.Email
		}
		if t.CertFile != nil {
			tls.CertPath = *t.CertFile
		}
		if t.KeyFile != nil {
			tls.KeyPath = *t.KeyFile
		}
	}

	var access *AccessConfig
	if a := cfg.Access; a != nil {
		access = &AccessConfig{RateLimitQPS: 0}
		if a.AllowAll != nil {
			access.AllowAll = *a.AllowAll
			access.PresentAllowAll = true
		}
		if a.AllowedIPs != nil {
			access.AllowedIPs = *a.AllowedIPs
		}
		if a.BlockedIPs != nil {
			access.BlockedIPs = *a.BlockedIPs
		}
		if a.DoHTokens != nil {
			access.DoHTokens = *a.DoHTokens
		}
		if a.RateLimitQPS != nil {
			access.RateLimitQPS = *a.RateLimitQPS
			access.PresentRateLimit = true
		}
	}

	log.Printf("[Main] Loaded config overrides from %s", path)
	return access
}

// applyRulesFromConfig applies rule toggles from a config file's "rules" block
// into the matcher. Only keys we understand are applied (e.g. enable_riot).
func applyRulesFromConfig(path string, m *matcher.Matcher) {
	if path == "" || m == nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg fileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}
	applied := 0
	for key, val := range cfg.Rules {
		presetName, ok := matcher.PresetRuleKeys[key]
		if !ok {
			continue
		}
		enabled, isBool := val.(bool)
		if !isBool {
			continue
		}
		m.SetRuleEnabled(presetName, enabled)
		applied++
	}
	if applied > 0 {
		log.Printf("[Main] Applied %d rule toggles from config file %s", applied, path)
	}
}
