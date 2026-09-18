package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdns/internal/service"
)

// Opening a /sub/ link re-binds the subscription's one allowed address. These tests
// hold the line between the two kinds of GET that arrive at that URL: the subscriber
// asking to be bound, and everything that fetches the link on their behalf.

func TestIsLinkPreviewFetch(t *testing.T) {
	browser := "Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"

	cases := []struct {
		name    string
		ua      string
		headers map[string]string
		want    bool
	}{
		{"a phone browser", browser, nil, false},
		{"an iOS browser", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Safari/604.1", nil, false},
		// The two callers most likely to be mistaken for a crawler, and the reason the
		// agent list names no HTTP client: a router or a cron job binding a new address
		// is asking for exactly the write this suppresses.
		{"a router script", "curl/8.7.1", nil, false},
		{"wget from a NAS", "Wget/1.21.4", nil, false},
		{"no agent at all", "", nil, false},

		{"telegram unfurling the link", "TelegramBot (like TwitterBot)", nil, true},
		{"whatsapp", "WhatsApp/2.23.20.0", nil, true},
		{"facebook", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", nil, true},
		{"discord", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)", nil, true},
		{"a search crawler", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", nil, true},

		// A browser prefetching a link the subscriber only hovered: the agent is a real
		// browser's, and the intent header is the only thing that says otherwise.
		{"chrome prefetch", browser, map[string]string{"Sec-Purpose": "prefetch;anonymous-client-ip"}, true},
		{"chrome prerender", browser, map[string]string{"Sec-Purpose": "prerender"}, true},
		{"legacy chrome", browser, map[string]string{"Purpose": "prefetch"}, true},
		{"safari top hit", browser, map[string]string{"X-Purpose": "preview"}, true},
		{"firefox", browser, map[string]string{"X-Moz": "prefetch"}, true},
		{"a real navigation", browser, map[string]string{"Sec-Fetch-Mode": "navigate"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sub/abc123", nil)
			if tc.ua != "" {
				req.Header.Set("User-Agent", tc.ua)
			} else {
				req.Header.Del("User-Agent")
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if got := isLinkPreviewFetch(req); got != tc.want {
				t.Errorf("isLinkPreviewFetch = %v, want %v", got, tc.want)
			}
		})
	}
}

// Phase B (Mantis C-03): the page is a pure overview — no GET at this address
// may ever write. A telegram unfurler and a real subscriber now see the same
// document, and neither visit moves the account's binding. The write lives in
// the secret-gated POST /ip/<token>, which is what the register card drives.
func TestPortalPageNeverBindsForAnyVisitor(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()

	client, err := ws.clients.CreateClient("Home Subscriber", 30, "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	visits := []struct {
		name    string
		ua      string
		headers map[string]string
	}{
		{"a telegram unfurler", "TelegramBot (like TwitterBot)", nil},
		{"a real phone browser", "Mozilla/5.0 (Linux; Android 14) Chrome/126.0.0.0 Mobile Safari/537.36", nil},
		{"chrome prefetch", "Mozilla/5.0 (Linux; Android 14) Chrome/126.0.0.0 Mobile", map[string]string{"Sec-Purpose": "prefetch"}},
	}
	for _, v := range visits {
		req := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
		req.Header.Set("User-Agent", v.ua)
		for k, val := range v.headers {
			req.Header.Set(k, val)
		}
		req.RemoteAddr = "203.0.113.50:44321"
		w := httptest.NewRecorder()
		ws.buildAdminHandler().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", v.name, w.Code)
		}
		stored, err := db.GetClient(client.ID)
		if err != nil {
			t.Fatalf("%s: GetClient: %v", v.name, err)
		}
		if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "10.0.0.5" {
			t.Fatalf("%s took the subscription: allowed IPs are %v, want [10.0.0.5]", v.name, stored.AllowedIPs)
		}
	}
}

// The one write left to the subscriber is the registration API: POST with the
// out-of-band secret binds the caller's address; POST without (or with a wrong)
// secret is refused with exactly the answer an unknown token gets (C-03), and
// a GET on the API address explains the change instead of writing.
func TestRegisterIPAPIWritesOnlyWithTheSecret(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()

	client, err := ws.clients.CreateClient("Button Presser", 30, "10.0.0.6")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	post := func(secret, ip string) *httptest.ResponseRecorder {
		body := `{"secret":"` + secret + `"`
		if ip != "" {
			body += `,"ip":"` + ip + `"`
		}
		body += `}`
		req := httptest.NewRequest(http.MethodPost, "/ip/"+client.Token, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.51:44322"
		w := httptest.NewRecorder()
		ws.buildAdminHandler().ServeHTTP(w, req)
		return w
	}

	// Wrong secret: refused, same answer as an unknown token, nothing written.
	if w := post("wrong-secret-entirely", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("POST with a wrong secret = %d (%s), want 401", w.Code, w.Body.String())
	}
	stored, _ := db.GetClient(client.ID)
	if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "10.0.0.6" {
		t.Fatalf("a refused POST still moved the binding: %v", stored.AllowedIPs)
	}

	// The real secret, explicit IP: bound.
	if w := post(client.RegisterSecret, "203.0.113.51"); w.Code != http.StatusOK {
		t.Fatalf("POST with the real secret = %d (%s), want 200", w.Code, w.Body.String())
	}
	stored, _ = db.GetClient(client.ID)
	if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "203.0.113.51" {
		t.Fatalf("allowed IPs are %v, want [203.0.113.51]", stored.AllowedIPs)
	}

	// Secret without an explicit IP binds the CALLER's address (the 1-click flow).
	req := httptest.NewRequest(http.MethodPost, "/ip/"+client.Token, strings.NewReader(`{"secret":"`+client.RegisterSecret+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.77:9999"
	w := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST with the secret and no IP = %d (%s), want 200", w.Code, w.Body.String())
	}
	stored, _ = db.GetClient(client.ID)
	if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "198.51.100.77" {
		t.Fatalf("allowed IPs are %v, want [198.51.100.77]", stored.AllowedIPs)
	}

	// GET on the API address explains itself instead of writing.
	req = httptest.NewRequest(http.MethodGet, "/ip/"+client.Token, nil)
	w = httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /ip/<token> = %d, want 200 (the explainer page)", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "API") {
		t.Error("GET on the registration API does not explain that it is an API")
	}
	stored, _ = db.GetClient(client.ID)
	if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "198.51.100.77" {
		t.Fatalf("a GET on the API address moved the binding: %v", stored.AllowedIPs)
	}
}

// Phase B: the JSON overview is read-only — nothing any agent sends to it can
// move a binding any more, which is the point of moving the write to the
// secret-gated POST /ip/.
func TestSubDataAPIIsReadOnlyForEveryAgent(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()

	client, err := ws.clients.CreateClient("Pressed The Button", 30, "10.0.0.7")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+client.Token+"/sync", nil)
	req.Header.Set("User-Agent", "TelegramBot (like TwitterBot)")
	req.Header.Set("Sec-Purpose", "prefetch")
	req.RemoteAddr = "203.0.113.52:44323"
	w := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	stored, err := db.GetClient(client.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "10.0.0.7" {
		t.Fatalf("the JSON overview moved the binding: %v", stored.AllowedIPs)
	}
}

// The preview guard sits in front of the expiry check, so an unfurler fetching a
// lapsed subscriber's link still reaches the expiry page the subscriber would see.
// What it must not do on the way is what RegisterIP does with an expired account:
// disable it on disk.
func TestPortalPreviewOfAnExpiredAccountDoesNotRetireIt(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()

	client, err := ws.clients.CreateClient("Lapsed Subscriber", 30, "10.0.0.8")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := ws.clients.UpdateClient(client.ID, service.UpdateClientRequest{ExpiresAt: &past}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.Token, nil)
	req.Header.Set("User-Agent", "WhatsApp/2.23.20.0")
	req.RemoteAddr = "203.0.113.53:44324"
	w := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(w, req)

	// The T3MP3ST external-attacker pass flagged the friendly error page
	// carrying 200: an expired plan is a gone resource, so the body stays and
	// the status tells the truth (410).
	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410 Gone for an expired plan", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "به پایان رسیده") {
		t.Error("the expiry page did not render for an expired account")
	}

	stored, err := db.GetClient(client.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	// An operator renewing the plan should not also have to re-enable the account
	// because a preview crawler looked at it while it was lapsed.
	if !stored.Enabled {
		t.Error("the unfurler's fetch disabled the account")
	}
	if len(stored.AllowedIPs) != 1 || stored.AllowedIPs[0] != "10.0.0.8" {
		t.Errorf("allowed IPs are %v, want [10.0.0.8]", stored.AllowedIPs)
	}
}

// The public JSON overview must not hand out the write credential. GET
// /api/sub/<token> is unauthenticated and reached by anyone holding the portal
// link; the registration secret is the out-of-band half of the binding
// credential (Mantis C-03), so its presence in this response would make a
// leaked link write-capable again with a single fetch. The operator's private
// note is not display data either. The authenticated dashboard API keeps both.
func TestPublicSubAPIDoesNotLeakTheRegisterSecret(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()

	client, err := ws.clients.CreateClient("Leak Probe", 30, "10.0.0.9")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if client.RegisterSecret == "" {
		t.Fatal("fixture account has no register secret; the test cannot prove the redaction")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+client.Token, nil)
	req.RemoteAddr = "203.0.113.99:5555"
	w := httptest.NewRecorder()
	ws.buildAdminHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/sub/<token> = %d (%s), want 200", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, client.RegisterSecret) {
		t.Error("the public subscription JSON contains the register secret — the " +
			"out-of-band credential is one fetch away for anyone holding the portal " +
			"link, which is exactly the collapse C-03 was designed to prevent")
	}
	if strings.Contains(body, `"register_secret":"`+client.RegisterSecret) {
		t.Error("the secret leaked in a non-empty form")
	}
	var decoded struct {
		Client struct {
			RegisterSecret string `json:"register_secret"`
			Note           string `json:"note"`
			Token          string `json:"token"`
		} `json:"client"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Client.RegisterSecret != "" {
		t.Errorf("client.register_secret = %q, want empty", decoded.Client.RegisterSecret)
	}

	// The operator's own view keeps the secret: the edit modal and the Telegram
	// provisioning card are built on it, and that surface is authenticated.
	h := ws.buildAdminHandler()
	tok := bearerFor(t, h)
	req2 := httptest.NewRequest(http.MethodGet, "/api/clients", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if !strings.Contains(w2.Body.String(), client.RegisterSecret) {
		t.Error("the authenticated /api/clients no longer carries the register secret — " +
			"the operator's edit modal and provisioning card read it from there")
	}
}
