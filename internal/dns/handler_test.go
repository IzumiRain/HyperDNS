package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/config"
	"hyperdns/internal/rules"
)

func TestExampleComResolutionTest(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.PublicIP = "45.63.42.29"
	cfg.Access.Clients = []config.Client{
		{
			ID:         "2001",
			Name:       "Registered Gamer",
			Token:      "tok-2001",
			AllowedIPs: []string{"10.0.0.1"},
			ExpiresAt:  time.Now().Add(48 * time.Hour),
			Enabled:    true,
		},
		{
			ID:         "2002",
			Name:       "Expired Gamer",
			Token:      "tok-2002",
			AllowedIPs: []string{"10.0.0.2"},
			ExpiresAt:  time.Now().Add(-2 * time.Hour),
			Enabled:    true,
		},
	}

	cache := NewCache(1000, 60, 3600)
	matcher := rules.NewMatcher(cfg)
	upstreams := NewUpstreamPool([]string{"1.1.1.1:53", "8.8.8.8:53"}, 2*time.Second, true, "")
	handler := NewHandler(cfg, cache, matcher, upstreams)

	// Helper to create query
	makeQuery := func(domain string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		return m
	}

	// 1. Registered & Valid Client -> Resolves to Server Public IP
	req1 := makeQuery("example.com")
	resp1 := handler.ProcessQuery(req1, "10.0.0.1", "UDP")
	if resp1 == nil || len(resp1.Answer) == 0 {
		t.Fatalf("expected answer for registered client, got none")
	}
	aRec1, ok := resp1.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp1.Answer[0])
	}
	if aRec1.A.String() != "45.63.42.29" {
		t.Errorf("expected example.com to resolve to server IP 45.63.42.29, got %s", aRec1.A.String())
	}

	// 2. Unregistered Client -> Resolves to Real Upstream IP (NOT 45.63.42.29)
	req2 := makeQuery("example.com")
	resp2 := handler.ProcessQuery(req2, "10.0.0.99", "UDP")
	if resp2 == nil || len(resp2.Answer) == 0 {
		t.Fatalf("expected upstream answer for unregistered client, got none")
	}
	aRec2, ok := resp2.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp2.Answer[0])
	}
	if aRec2.A.String() == "45.63.42.29" {
		t.Errorf("expected unregistered client to NOT receive server IP for example.com, got %s", aRec2.A.String())
	}

	// 3. Expired Client -> Resolves to Real Upstream IP (NOT 45.63.42.29)
	req3 := makeQuery("example.com")
	resp3 := handler.ProcessQuery(req3, "10.0.0.2", "UDP")
	if resp3 == nil || len(resp3.Answer) == 0 {
		t.Fatalf("expected upstream answer for expired client, got none")
	}
	aRec3, ok := resp3.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp3.Answer[0])
	}
	if aRec3.A.String() == "45.63.42.29" {
		t.Errorf("expected expired client to NOT receive server IP for example.com, got %s", aRec3.A.String())
	}
}
