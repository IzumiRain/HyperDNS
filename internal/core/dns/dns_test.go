package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/database"
)

type dummyAccess struct{}

func (d *dummyAccess) IsIPAllowed(ip string) (*database.Client, bool) {
	return &database.Client{Name: "VIP Gamer"}, true
}
func (d *dummyAccess) IsAllowAll() bool { return true }

func TestDNSHandler_ProcessQuery(t *testing.T) {
	c := cache.NewCache(1000, 60, 3600)
	defer c.Close()
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool([]string{"1.1.1.1:53", "8.8.8.8:53"}, 2*time.Second, true, "")

	handler := NewHandler(&dummyAccess{}, c, m, u, nil, "198.51.100.1")

	req := new(dns.Msg)
	req.SetQuestion("playvalorant.com.", dns.TypeA)

	resp := handler.ProcessQuery(req, "127.0.0.1")
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}

	if len(resp.Answer) == 0 {
		t.Fatalf("expected answer for playvalorant.com")
	}

	aRecord, ok := resp.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != "198.51.100.1" {
		t.Errorf("expected A record to rewrite to 198.51.100.1, got %v", resp.Answer[0])
	}
}
