package web

import (
	"net/http"
	"slices"
	"testing"

	"hyperdns/internal/core/matcher"
)

// rulesFullSave is a save of the shape the dashboard sends: every key present.
const rulesFullSave = `{
	"enable_riot": true,
	"custom_proxied": ["Proxy.example.com"],
	"custom_blocked": ["ads.example.com"],
	"custom_direct": ["intranet.example.test"],
	"custom_records": {"pin.example.com": "203.0.113.9", "old.example.com": "203.0.113.10"}
}`

func TestToStringSliceAcceptsBothShapes(t *testing.T) {
	want := []string{"valorant.com", "ea.com"}
	// []any is what a decoded request body yields; []string is what
	// loadRulesConfig hands back. Both are real callers, and asserting only the
	// first is the bug the handler test below pins.
	for _, in := range []any{
		[]any{"Valorant.com", " EA.com ", ""},
		[]string{"Valorant.com", " EA.com ", ""},
	} {
		if got := toStringSlice(in); !slices.Equal(got, want) {
			t.Errorf("toStringSlice(%T) = %v, want %v", in, got, want)
		}
	}
	// Anything that is not a list carries no domains, and nil is how the caller
	// learns that, so it can keep whatever it already had.
	for _, in := range []any{nil, "riot.com", 42, map[string]any{"a": "b"}} {
		if got := toStringSlice(in); got != nil {
			t.Errorf("toStringSlice(%#v) = %v, want nil", in, got)
		}
	}
}

// rulesFromConfig reads the effective rule state back the way the dashboard does.
func rulesFromConfig(t *testing.T, h http.Handler, tok string) map[string]any {
	t.Helper()
	w := authedGet(t, h, "/api/config", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/config = %d — %s", w.Code, w.Body.String())
	}
	rules, ok := decodeBody(t, w)["rules"].(map[string]any)
	if !ok {
		t.Fatal("/api/config carries no rules object")
	}
	return rules
}

// domainsAt pulls one custom domain list out of a decoded /api/config document.
// It decodes by hand rather than through toStringSlice, because the function
// under test must not also be the assertion.
func domainsAt(t *testing.T, rules map[string]any, key string) []string {
	t.Helper()
	raw, ok := rules[key].([]any)
	if !ok {
		t.Fatalf("rules[%q] = %#v, want a JSON list", key, rules[key])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, isStr := v.(string)
		if !isStr {
			t.Fatalf("rules[%q] contains %#v, want strings only", key, v)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// TestConfigRulesPartialSaveKeepsCustomLists covers the whole point of the
// "start from the persisted state" fallback: a payload that carries only a
// preset toggle must not touch the custom domain lists. Before toStringSlice
// accepted []string it silently returned nil for all three, and this save wrote
// three empty lists over the operator's domains — in the database and in the
// live matcher.
func TestConfigRulesPartialSaveKeepsCustomLists(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	if w := postJSON(t, h, "/api/config/rules", rulesFullSave, tok); w.Code != http.StatusOK {
		t.Fatalf("full save = %d — %s", w.Code, w.Body.String())
	}

	// A body with nothing but a preset toggle: any non-dashboard API client, or
	// the dashboard before currentConfig has loaded.
	if w := postJSON(t, h, "/api/config/rules", `{"enable_riot":false}`, tok); w.Code != http.StatusOK {
		t.Fatalf("preset-only save = %d — %s", w.Code, w.Body.String())
	}

	rules := rulesFromConfig(t, h, tok)
	for key, want := range map[string]string{
		"custom_proxied": "proxy.example.com",
		"custom_blocked": "ads.example.com",
		"custom_direct":  "intranet.example.test",
	} {
		if got := domainsAt(t, rules, key); !slices.Equal(got, []string{want}) {
			t.Errorf("after a preset-only save, rules[%q] = %v, want [%s]", key, got, want)
		}
	}
	recs, _ := rules["custom_records"].(map[string]any)
	if recs["pin.example.com"] != "203.0.113.9" {
		t.Errorf("custom_records = %#v, want pin.example.com preserved", rules["custom_records"])
	}

	// The toggle in that payload still has to have landed, or every assertion
	// above would also pass on a handler that ignored the request outright.
	if enabled, _ := rules["enable_riot"].(bool); enabled {
		t.Error("enable_riot survived a save that set it to false")
	}
	if ws.matcher.IsRuleEnabled("enable_riot") {
		t.Error("the live matcher still has the Riot preset enabled")
	}

	// The matcher has to agree with what was persisted; the wipe hit both.
	if action, rule := ws.matcher.Match("proxy.example.com"); action != matcher.ActionProxy {
		t.Errorf("Match(proxy.example.com) = %v/%s, want ActionProxy", action, rule)
	}
	if action, rule := ws.matcher.Match("ads.example.com"); action != matcher.ActionBlock {
		t.Errorf("Match(ads.example.com) = %v/%s, want ActionBlock", action, rule)
	}
	if ip, ok := ws.matcher.GetCustomRecord("pin.example.com"); !ok || ip != "203.0.113.9" {
		t.Errorf("GetCustomRecord(pin.example.com) = %q,%v, want 203.0.113.9,true", ip, ok)
	}
}

// TestConfigRulesExplicitEmptyClears is the other half of the contract. Keeping
// absent keys must not become keeping everything: a list the operator emptied has
// to come back empty, and a record they deleted has to disappear rather than be
// merged back in from the persisted state.
func TestConfigRulesExplicitEmptyClears(t *testing.T) {
	ws, h, tok, cleanup := authedServer(t)
	defer cleanup()

	if w := postJSON(t, h, "/api/config/rules", rulesFullSave, tok); w.Code != http.StatusOK {
		t.Fatalf("full save = %d — %s", w.Code, w.Body.String())
	}
	body := `{"custom_proxied":[],"custom_records":{"pin.example.com":"203.0.113.9"}}`
	if w := postJSON(t, h, "/api/config/rules", body, tok); w.Code != http.StatusOK {
		t.Fatalf("clearing save = %d — %s", w.Code, w.Body.String())
	}

	rules := rulesFromConfig(t, h, tok)
	if got := domainsAt(t, rules, "custom_proxied"); len(got) != 0 {
		t.Errorf("custom_proxied = %v, want empty after an explicit []", got)
	}
	if got := domainsAt(t, rules, "custom_blocked"); !slices.Equal(got, []string{"ads.example.com"}) {
		t.Errorf("custom_blocked = %v, want it untouched by an unrelated save", got)
	}
	recs, _ := rules["custom_records"].(map[string]any)
	if _, still := recs["old.example.com"]; still {
		t.Error("a custom record left out of the payload survived the save")
	}
	if recs["pin.example.com"] != "203.0.113.9" {
		t.Errorf("custom_records = %#v, want pin.example.com kept", recs)
	}
	if action, rule := ws.matcher.Match("proxy.example.com"); action == matcher.ActionProxy {
		t.Errorf("the live matcher still proxies a cleared domain (%v/%s)", action, rule)
	}
	if ip, ok := ws.matcher.GetCustomRecord("old.example.com"); ok {
		t.Errorf("the live matcher kept a deleted custom record (%q)", ip)
	}
}

func TestConfigRulesGuards(t *testing.T) {
	_, h, tok, cleanup := authedServer(t)
	defer cleanup()

	if w := authedGet(t, h, "/api/config/rules", tok); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/config/rules = %d, want 405", w.Code)
	}
	if w := postJSON(t, h, "/api/config/rules", rulesFullSave, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated save = %d, want 401", w.Code)
	}
	if w := postJSON(t, h, "/api/config/rules", `{"custom_proxied":`, tok); w.Code != http.StatusBadRequest {
		t.Errorf("truncated JSON = %d, want 400", w.Code)
	}
}
