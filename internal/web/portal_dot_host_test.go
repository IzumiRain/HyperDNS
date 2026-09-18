package web

// The subscriber portal has to advertise two different addresses for one server,
// and rendering the wrong one in the wrong place is silent: the page looks
// finished, the value is copyable, and it simply does not work on the device it
// was copied into.
//
// Plain DNS on port 53 takes an IP. A hostname in a router's DNS field, or in a
// PS5's network settings, resolves nowhere — resolving names is what the address
// is being set for.
//
// DoT is the mirror image. Android's Private DNS field accepts a hostname only
// and refuses an IP outright, and the TLS handshake needs a name to check the
// certificate against. This is the whole reason a domain became mandatory at
// install time in v2.0.0, so a portal that then prints an IP under "Private DNS
// provider hostname" undoes the requirement at the last step.
//
// These tests pin both halves.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// portalBodyFor stands up a subscription, fetches its portal page and returns the
// HTML. domain is written to TLS settings first, so "" exercises the no-domain
// fallback path. lang picks the rendered language: the portal negotiates Persian
// by default, so a test asserting on English copy has to ask for it.
func portalBodyFor(t *testing.T, domain, lang string) string {
	t.Helper()

	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	if domain != "" {
		ws.tlsSettings.Domain = domain
	}
	// The public IP the plain-DNS rows should keep showing, distinct from the
	// domain so a test can tell which one reached which row.
	ws.settings.PublicIP = "203.0.113.9"

	client, err := ws.clients.CreateClient("portal-dot-test", 30, "")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	url := "/sub/" + client.Token
	if lang != "" {
		url += "?lang=" + lang
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.RemoteAddr = "198.51.100.7:5555"
	rec := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("portal returned %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// TestPortalAdvertisesTheDomainForDoTAndDoH is the Android case: with a domain
// configured, the encrypted endpoints must carry the name and not the address.
func TestPortalAdvertisesTheDomainForDoTAndDoH(t *testing.T) {
	const domain = "dns.example.com"
	body := portalBodyFor(t, domain, "en")

	for _, want := range []string{
		domain + ":853",                         // DoT endpoint card
		"https://" + domain + ":8443/dns-query", // DoH endpoint card
	} {
		if !strings.Contains(body, want) {
			t.Errorf("portal does not offer %q; a subscriber cannot reach DoT/DoH by name", want)
		}
	}

	// The Private DNS row is the one Android reads. An IP here is the bug.
	if !strings.Contains(body, "Private DNS provider hostname: <b>"+domain+"</b>") {
		t.Errorf("Private DNS row does not name %q", domain)
	}
	for _, bad := range []string{
		"Private DNS provider hostname: <b>203.0.113.9</b>",
		"203.0.113.9:853",
		"https://203.0.113.9:8443/dns-query",
	} {
		if strings.Contains(body, bad) {
			t.Errorf("portal still advertises %q; Android's Private DNS field rejects an IP", bad)
		}
	}

	// Plain DNS must NOT switch to the hostname: that half still needs an address.
	if !strings.Contains(body, "203.0.113.9") {
		t.Error("portal no longer shows the plain-DNS IP; a router or console cannot use a hostname there")
	}
}

// TestPortalWithoutADomainSaysPrivateDNSIsUnavailable covers the honest-fallback
// path. A server with no domain cannot serve Private DNS at all, and printing an
// IP under a field that rejects IPs is an instruction that cannot be followed.
func TestPortalWithoutADomainSaysPrivateDNSIsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		lang string
		// says is a fragment of the "Private DNS is unavailable" copy in that
		// language. Both bundles are checked because the Persian page is what most
		// subscribers of this project actually read.
		says string
	}{
		{"en", "no domain and TLS certificate"},
		{"fa", "دامنه و گواهی TLS ندارد"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			body := portalBodyFor(t, "", tc.lang)

			if strings.Contains(body, "Private DNS provider hostname: <b>203.0.113.9</b>") {
				t.Error("with no domain the portal still prints an IP as the Private DNS hostname")
			}
			if !strings.Contains(body, tc.says) {
				t.Errorf("with no domain the %s portal does not explain that Private DNS is unavailable", tc.lang)
			}
			// The static-Wi-Fi fallback is what such a subscriber is meant to use, so
			// it has to still be there with the address in it.
			if !strings.Contains(body, "DNS 1: <b>203.0.113.9</b>") {
				t.Error("the static Wi-Fi fallback lost the server address")
			}
		})
	}
}

// TestSubDataAPIReportsHostAndAddressSeparately pins the same distinction on the
// JSON endpoint, which is what a reseller's own frontend builds its instructions
// from. server_dns stayed the address for compatibility; server_host is new.
func TestSubDataAPIReportsHostAndAddressSeparately(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	ws.tlsSettings.Domain = "dns.example.com"
	ws.settings.PublicIP = "203.0.113.9"

	client, err := ws.clients.CreateClient("portal-json-test", 30, "")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+client.Token, nil)
	req.RemoteAddr = "198.51.100.7:5555"
	rec := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("api returned %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, `"server_host":"dns.example.com"`) {
		t.Errorf("server_host is not the domain: %s", body)
	}
	if !strings.Contains(body, `"server_dns":"203.0.113.9"`) {
		t.Errorf("server_dns is no longer the plain-DNS address: %s", body)
	}
	if !strings.Contains(body, `"has_domain":true`) {
		t.Errorf("has_domain is not set with a domain configured: %s", body)
	}
}
