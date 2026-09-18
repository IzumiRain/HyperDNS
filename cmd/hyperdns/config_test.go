package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// applyConfigFile is the layer between an operator's config.json and a live
// resolver, and every field in it is a pointer for one reason: a key that is
// absent must leave whatever was already there alone, while a key set to the zero
// value must be honoured as a deliberate choice. That distinction is the whole
// migration story for this project — a config file written for v1.2.0 has to keep
// working against a v1.5.0 binary without an operator editing anything — so it is
// worth pinning per block rather than trusting the pattern to hold.

// writeConfig drops a config.json into a temp dir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	// A malformed fixture would make every assertion below meaningless in a way
	// that reads like a code failure, so reject it before it is ever parsed.
	if !json.Valid([]byte(body)) {
		t.Fatalf("the test fixture is not valid JSON")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the test config: %v", err)
	}
	return path
}

// defaults mirrors the shape main() builds before any file or database is
// consulted. The values are deliberately distinctive so an overwrite is obvious.
func defaults() (*database.ServerSettings, *database.DNSSettings, *database.SNIProxySettings, *database.TLSSettings) {
	server := &database.ServerSettings{
		PublicIP:      "127.0.0.1",
		BindHost:      "0.0.0.0",
		WebPort:       8080,
		AdminUsername: "admin",
		APIBind:       "127.0.0.1",
	}
	dns := &database.DNSSettings{
		Enabled:           true,
		Port:              53,
		DoTPort:           853,
		DoHPort:           8443,
		Upstreams:         []string{"1.1.1.1:53"},
		CacheSize:         20000,
		CacheMinTTL:       60,
		CacheMaxTTL:       86400,
		QueryTimeout:      2 * time.Second,
		FastestRacing:     true,
		ServeStaleSeconds: 30,
	}
	sni := &database.SNIProxySettings{
		Enabled:             true,
		HTTPPort:            80,
		HTTPSPort:           443,
		Timeout:             120 * time.Second,
		EnableFragmentation: true,
		FragmentSize:        2,
		FragmentDelayMs:     5,
	}
	tls := &database.TLSSettings{
		CertPath: "certs/cert.pem",
		KeyPath:  "certs/key.pem",
	}
	return server, dns, sni, tls
}

// TestConfigFileAbsentLeavesDefaults is the upgrade path: an operator who never
// touches config.json must get the same resolver they had before.
func TestConfigFileAbsentLeavesDefaults(t *testing.T) {
	server, dns, sni, tls := defaults()
	if access := applyConfigFile(filepath.Join(t.TempDir(), "nope.json"), server, dns, sni, tls); access != nil {
		t.Error("a missing config file produced an access block")
	}
	if dns.Port != 53 || dns.CacheSize != 20000 || dns.ServeStaleSeconds != 30 {
		t.Errorf("a missing config file overwrote DNS defaults: %+v", dns)
	}
	if server.WebPort != 8080 || sni.HTTPSPort != 443 || tls.CertPath != "certs/cert.pem" {
		t.Error("a missing config file overwrote defaults outside the DNS block")
	}
}

// TestConfigFileMalformedLeavesDefaults pins that a typo in config.json degrades
// to "use the defaults" rather than to a resolver with half a configuration.
func TestConfigFileMalformedLeavesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"dns": {"port": 5353,`), 0o600); err != nil {
		t.Fatalf("writing the test config: %v", err)
	}

	server, dns, sni, tls := defaults()
	if access := applyConfigFile(path, server, dns, sni, tls); access != nil {
		t.Error("a malformed config file produced an access block")
	}
	if dns.Port != 53 {
		t.Errorf("dns.port = %d, want the default 53 — a truncated file was partly applied", dns.Port)
	}
}

// TestConfigServeStaleAbsentKeepsDefault is the v1.2.0-config-against-a-v1.5.0-
// binary case for the key added in this release. Nothing on disk mentions
// serve_stale_seconds, and the feature must still come up at its default.
func TestConfigServeStaleAbsentKeepsDefault(t *testing.T) {
	path := writeConfig(t, `{
	  "dns": {
	    "port": 5353,
	    "cache_min_ttl": 30
	  }
	}`)

	server, dns, sni, tls := defaults()
	applyConfigFile(path, server, dns, sni, tls)

	if dns.Port != 5353 || dns.CacheMinTTL != 30 {
		t.Errorf("the keys that were present were not applied: %+v", dns)
	}
	if dns.ServeStaleSeconds != 30 {
		t.Errorf("serve_stale_seconds = %d, want the default 30 — an absent key was read as zero", dns.ServeStaleSeconds)
	}
	if dns.CacheMaxTTL != 86400 || !dns.FastestRacing {
		t.Errorf("absent DNS keys were overwritten: %+v", dns)
	}
}

// TestConfigServeStaleZeroDisables is the other half: an explicit 0 is an
// operator turning serve-stale off, and must not be mistaken for an absent key.
func TestConfigServeStaleZeroDisables(t *testing.T) {
	path := writeConfig(t, `{"dns": {"serve_stale_seconds": 0}}`)

	server, dns, sni, tls := defaults()
	applyConfigFile(path, server, dns, sni, tls)

	if dns.ServeStaleSeconds != 0 {
		t.Errorf("serve_stale_seconds = %d, want 0 — an explicit off switch was ignored", dns.ServeStaleSeconds)
	}
}

func TestConfigServeStaleValueApplied(t *testing.T) {
	path := writeConfig(t, `{"dns": {"serve_stale_seconds": 120}}`)

	server, dns, sni, tls := defaults()
	applyConfigFile(path, server, dns, sni, tls)

	if dns.ServeStaleSeconds != 120 {
		t.Errorf("serve_stale_seconds = %d, want 120", dns.ServeStaleSeconds)
	}
}

// TestConfigSNIProxyBlock covers the shipped spelling. Timeout is nanoseconds in
// the file — the same units database.SNIProxySettings stores — so a plain integer
// has to survive the round trip unscaled.
func TestConfigSNIProxyBlock(t *testing.T) {
	path := writeConfig(t, `{
	  "sniproxy": {
	    "https_port": 8443,
	    "timeout": 30000000000,
	    "enable_fragmentation": false
	  }
	}`)

	server, dns, sni, tls := defaults()
	applyConfigFile(path, server, dns, sni, tls)

	if sni.HTTPSPort != 8443 {
		t.Errorf("https_port = %d, want 8443", sni.HTTPSPort)
	}
	if sni.Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", sni.Timeout)
	}
	if sni.EnableFragmentation {
		t.Error("enable_fragmentation: false was ignored — a zero-valued bool must be honoured")
	}
	if sni.HTTPPort != 80 || sni.FragmentSize != 2 {
		t.Errorf("absent SNI keys were overwritten: %+v", sni)
	}
}

// TestConfigSNIProxyLegacySpelling pins the compatibility alias. Installs made
// before the key was renamed still have "sni_proxy" on disk, and silently
// ignoring it would drop the proxy back to defaults on upgrade — including
// re-enabling fragmentation on a host where it was deliberately turned off.
func TestConfigSNIProxyLegacySpelling(t *testing.T) {
	path := writeConfig(t, `{"sni_proxy": {"https_port": 9443, "fragment_size": 4}}`)

	server, dns, sni, tls := defaults()
	applyConfigFile(path, server, dns, sni, tls)

	if sni.HTTPSPort != 9443 || sni.FragmentSize != 4 {
		t.Errorf("the legacy sni_proxy block was ignored: %+v", sni)
	}
}

// TestConfigSNIProxyModernSpellingWins pins the precedence when a file somehow
// carries both, which is what a hand-merged upgrade produces.
func TestConfigSNIProxyModernSpellingWins(t *testing.T) {
	path := writeConfig(t, `{
	  "sniproxy":  {"https_port": 1111},
	  "sni_proxy": {"https_port": 2222}
	}`)

	server, dns, sni, tls := defaults()
	applyConfigFile(path, server, dns, sni, tls)

	if sni.HTTPSPort != 1111 {
		t.Errorf("https_port = %d, want 1111 — the legacy block outranked the modern one", sni.HTTPSPort)
	}
}

// TestConfigAccessBlock covers the Present* flags, which exist precisely because
// both of these keys have a meaningful zero: allow_all=false locks the resolver
// to a list, and rate_limit_qps=0 turns limiting off.
func TestConfigAccessBlock(t *testing.T) {
	path := writeConfig(t, `{
	  "access": {
	    "allow_all": false,
	    "allowed_ips": ["10.0.0.1", "10.0.0.2"],
	    "blocked_ips": ["203.0.113.9"],
	    "doh_tokens": ["tok-a"],
	    "rate_limit_qps": 0
	  }
	}`)

	server, dns, sni, tls := defaults()
	access := applyConfigFile(path, server, dns, sni, tls)

	if access == nil {
		t.Fatal("the access block was not parsed")
	}
	if access.AllowAll || !access.PresentAllowAll {
		t.Errorf("allow_all: got %v present=%v, want false/true", access.AllowAll, access.PresentAllowAll)
	}
	if len(access.AllowedIPs) != 2 || access.AllowedIPs[0] != "10.0.0.1" {
		t.Errorf("allowed_ips = %v", access.AllowedIPs)
	}
	if len(access.BlockedIPs) != 1 || len(access.DoHTokens) != 1 {
		t.Errorf("blocked_ips = %v, doh_tokens = %v", access.BlockedIPs, access.DoHTokens)
	}
	if access.RateLimitQPS != 0 || !access.PresentRateLimit {
		t.Errorf("rate_limit_qps: got %d present=%v, want 0/true — an explicit 0 must disable limiting", access.RateLimitQPS, access.PresentRateLimit)
	}
}

// TestConfigAccessBlockOmittedKeysAreNotPresent is the mirror image: without the
// Present* flags an absent rate_limit_qps would read as 0 and silently disable
// the rate limiter on every install whose config predates the key.
func TestConfigAccessBlockOmittedKeysAreNotPresent(t *testing.T) {
	path := writeConfig(t, `{"access": {"allowed_ips": ["10.0.0.1"]}}`)

	server, dns, sni, tls := defaults()
	access := applyConfigFile(path, server, dns, sni, tls)

	if access == nil {
		t.Fatal("the access block was not parsed")
	}
	if access.PresentAllowAll {
		t.Error("allow_all was reported present although the key is absent")
	}
	if access.PresentRateLimit {
		t.Error("rate_limit_qps was reported present although the key is absent — the limiter would be disabled on upgrade")
	}
}

// TestConfigNoAccessBlockYieldsNil is what main() branches on to decide whether
// the file has an opinion about access control at all.
func TestConfigNoAccessBlockYieldsNil(t *testing.T) {
	path := writeConfig(t, `{"dns": {"port": 53}}`)

	server, dns, sni, tls := defaults()
	if access := applyConfigFile(path, server, dns, sni, tls); access != nil {
		t.Errorf("a file with no access block produced %+v, want nil", access)
	}
}

// TestConfigTLSBlock pins the two key names that differ between the file and the
// struct: cert_file → CertPath and auto_cert → AutoRenewACME.
func TestConfigEmptyTLSDomainKeepsNoDomainPanelHTTP(t *testing.T) {
	path := writeConfig(t, `{"tls": {"domain": ""}}`)

	server, dns, sni, tls := defaults()
	applyConfigFile(path, server, dns, sni, tls)

	if tls.Domain != "" {
		t.Fatalf("tls domain = %q, want empty", tls.Domain)
	}
	if tls.PanelHTTPS {
		t.Fatal("an explicitly empty domain enabled panel HTTPS")
	}
}

func TestConfigTLSBlock(t *testing.T) {
	path := writeConfig(t, `{
	  "tls": {
	    "auto_cert": true,
	    "domain": "dns.example",
	    "email": "ops@example",
	    "cert_file": "/etc/ssl/x.pem",
	    "key_file": "/etc/ssl/x.key"
	  }
	}`)

	server, dns, sni, tls := defaults()
	applyConfigFile(path, server, dns, sni, tls)

	if !tls.AutoRenewACME {
		t.Error("auto_cert was not mapped onto AutoRenewACME")
	}
	if tls.Domain != "dns.example" || tls.Email != "ops@example" {
		t.Errorf("tls domain/email = %q/%q", tls.Domain, tls.Email)
	}
	if tls.CertPath != "/etc/ssl/x.pem" || tls.KeyPath != "/etc/ssl/x.key" {
		t.Errorf("cert/key path = %q/%q", tls.CertPath, tls.KeyPath)
	}
}

// TestConfigNilTargetsAreRejected pins the guard that keeps a partly-initialised
// caller from panicking inside the parser.
func TestConfigNilTargetsAreRejected(t *testing.T) {
	path := writeConfig(t, `{"dns": {"port": 5353}}`)
	if access := applyConfigFile(path, nil, nil, nil, nil); access != nil {
		t.Error("nil targets produced an access block")
	}
	if access := applyConfigFile("", &database.ServerSettings{}, &database.DNSSettings{}, &database.SNIProxySettings{}, &database.TLSSettings{}); access != nil {
		t.Error("an empty path produced an access block")
	}
}
