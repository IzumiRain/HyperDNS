package matcher

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The matcher decides, for every query the daemon answers, whether the client
// reaches the real host, the operator's proxy, or nothing at all. A defect here is
// not a slow path — it is traffic routed somewhere the operator did not intend.
// These tests pin the properties the rest of the daemon relies on: a preset resolves
// to the action its name promises, the operator's own lists outrank presets and
// apply to every client, a rule a client did not select is walked past rather than
// allowed to stop the search, and the most specific rule indexed for a name wins.
//
// On the race detector: it is unavailable in this environment (no C compiler), so
// TestConcurrentMatchDuringReload is a stress substitute. It can surface a panic or
// a torn read; it cannot certify the matcher race-free.

// mustMatch asserts the action for a domain and returns the rule name, so a test
// can go on to check attribution without repeating the call.
func mustMatch(t *testing.T, m *Matcher, domain string, want Action) string {
	t.Helper()
	got, rule := m.Match(domain)
	if got != want {
		t.Errorf("Match(%q) = %v (%s), want %v", domain, got, rule, want)
	}
	return rule
}

func mustMatchClient(t *testing.T, m *Matcher, domain string, policies []string, want Action) string {
	t.Helper()
	got, rule := m.MatchForClient(domain, policies)
	if got != want {
		t.Errorf("MatchForClient(%q, %v) = %v (%s), want %v", domain, policies, got, rule, want)
	}
	return rule
}

func TestPresetDomainsResolveToProxy(t *testing.T) {
	m := NewMatcher()

	for _, d := range []string{
		"riotgames.com",
		"auth.riotgames.com", // covered by the wildcard entry, not the plain one
		"epicgames.com",
		"steamcommunity.com",
		"discord.gg",
		"xboxlive.com",
		"soundcloud.com",
	} {
		t.Run(d, func(t *testing.T) { mustMatch(t, m, d, ActionProxy) })
	}

	// A name no rule covers is forwarded, not captured. The rule label matters as
	// well: the query log distinguishes "matched nothing" from "matched a rule
	// whose action happens to be DIRECT".
	for _, d := range []string{"example.com", "random-unblocked-site.org", "a.b.internal.example.org"} {
		t.Run(d, func(t *testing.T) {
			if rule := mustMatch(t, m, d, ActionDirect); rule != "Direct" {
				t.Errorf("rule = %q, want %q", rule, "Direct")
			}
		})
	}
}

// TestGoogleAISocialPresetsResolveToProxy: the v2.2.0 major-service categories
// proxy their own domains and — the part that makes them safe to default on —
// deliberately do NOT capture the shared-infrastructure zones that would drag
// unrelated traffic onto the proxy with them.
func TestGoogleAISocialPresetsResolveToProxy(t *testing.T) {
	m := NewMatcher()

	for _, d := range []string{
		// Google: consumer platforms
		"google.com",
		"accounts.google.com", // wildcard entry, not the plain one
		"mail.google.com",
		"youtube.com",
		"www.youtube.com",
		"i.ytimg.com",
		"rr1---sn-xyz.googlevideo.com",
		"youtu.be",
		// AI assistants
		"copilot.microsoft.com",
		"www.bing.com",
		"www.perplexity.ai",
		"x.ai",
		"grok.com",
		"chat.deepseek.com",
		"openrouter.ai",
		// Social
		"x.com",
		"pbs.twimg.com",
		"www.instagram.com",
		"scontent.cdninstagram.com",
		"web.telegram.org",
		"www.reddit.com",
		"old.reddit.com",
		"i.redd.it",
	} {
		t.Run(d, func(t *testing.T) { mustMatch(t, m, d, ActionProxy) })
	}

	// The shared-CDN exclusion is the safety property of the Google preset:
	// these names serve half the web, and capturing them would route unrelated
	// sites' traffic the moment Google is toggled on. The googleapis/gstatic/
	// googleusercontent zones are simply not listed by any preset (Direct,
	// "matched nothing"); the update CDNs ARE under *.google.com, so they are
	// excluded the stronger way — forced direct, which outranks every proxy
	// rule. Both directions must hold: no proxy verdict, ever.
	for _, d := range []string{
		"ajax.googleapis.com",
		"fonts.googleapis.com",
		"www.gstatic.com",
		"lh3.googleusercontent.com",
		"dl.google.com",
		"redirector.gvt1.com",
		"gvt2.com",
	} {
		t.Run(d, func(t *testing.T) {
			rule := mustMatch(t, m, d, ActionDirect)
			if strings.Contains(rule, "Google") {
				t.Errorf("shared-infrastructure name %q matched rule %q — the Google preset must not capture it", d, rule)
			}
		})
	}
}

// A PROXY verdict answers A with the VPS address, and the SNI proxy listens on TCP
// 80/443/2099/5222/5223/8393 and nothing else. So proxying a name whose traffic is
// UDP does not slow it down, it removes it: the client connects to an address where
// nothing is listening, and cannot tell that the name it resolved was substituted.
// Discord voice and Vivox were both in the proxy presets — voice would sit at
// "connecting", and latency.discord.media made every voice region measure as the
// distance to the VPS, so the client picked the wrong one.
func TestRealtimePlaneIsForcedDirect(t *testing.T) {
	m := NewMatcher()

	for _, d := range []string{
		"discord.media",
		"voice.discord.media",
		"latency.discord.media", // the region probe
		"vivox.com",
		"bop.vivox.com",
		"v5.vivox.com",
		"bd8-usw2.vivox.com",
	} {
		t.Run(d, func(t *testing.T) {
			if rule := mustMatch(t, m, d, ActionDirect); rule != RuleRealtimeDirect {
				t.Errorf("rule = %q, want %q", rule, RuleRealtimeDirect)
			}
			// A client that selected the very preset the name used to belong to must
			// get the same answer: the guard is not an opt-in category.
			mustMatchClient(t, m, d, []string{"enable_discord", "enable_riot"}, ActionDirect)
		})
	}

	// The guard is narrow. Everything else in those presets is still proxied.
	mustMatch(t, m, "discord.gg", ActionProxy)
	mustMatch(t, m, "riotgames.com", ActionProxy)
	mustMatch(t, m, "auth.riotgames.com", ActionProxy)

	// It is not a switch. SetRuleEnabled takes a preset name or a policy key, and
	// neither resolves to this rule — but a caller passing the literal name must not
	// be able to turn a game's voice off either.
	m.SetRuleEnabled(RuleRealtimeDirect, false)
	mustMatch(t, m, "voice.discord.media", ActionDirect)

	// And it survives the path the dashboard takes on every save.
	m.SetCustomRules(nil, nil, nil, nil)
	mustMatch(t, m, "vivox.com", ActionDirect)
}

// The guard corrects the presets, not the operator. Someone who types one of these
// names into their own list has said so deliberately, and the rule that a custom
// entry beats a preset applies here too.
func TestOperatorOverridesRealtimePlane(t *testing.T) {
	m := NewMatcher()

	m.SetCustomRules([]string{"discord.media"}, nil, nil, nil)
	if rule := mustMatch(t, m, "discord.media", ActionProxy); rule != RuleCustomProxy {
		t.Errorf("rule = %q, want %q", rule, RuleCustomProxy)
	}
	// Naming the parent lifts the zone with it, the same way indexing it would cover
	// the zone.
	mustMatch(t, m, "voice.discord.media", ActionProxy)

	// Only the pattern they named is lifted, though. An entry for a name *under* a
	// guarded domain does not reach the guard's own key, so it stays direct — the
	// narrow case fails toward the behaviour that works.
	m.SetCustomRules([]string{"voice.discord.media"}, nil, nil, nil)
	if rule := mustMatch(t, m, "voice.discord.media", ActionDirect); rule != RuleRealtimeDirect {
		t.Errorf("rule = %q, want %q", rule, RuleRealtimeDirect)
	}

	// A block outranks the guard: "stop resolving this" is a stronger instruction
	// than "do not proxy this".
	m.SetCustomRules(nil, []string{"vivox.com"}, nil, nil)
	if rule := mustMatch(t, m, "vivox.com", ActionBlock); rule != RuleCustomBlock {
		t.Errorf("rule = %q, want %q", rule, RuleCustomBlock)
	}
	// Cleared again, the guard is back — it is rebuilt with the presets.
	m.SetCustomRules(nil, nil, nil, nil)
	mustMatch(t, m, "vivox.com", ActionDirect)
}

// The other half of the forced-direct plane: a name whose transport is TCP but whose
// port is not one the proxy binds. cm.steampowered.com is the case, and it differs
// from the Discord and Vivox names in a way that matters — it is not listed in any
// preset and cannot be removed from one, because PresetSteam claims the whole
// steampowered.com zone with a wildcard. So TestNoPresetListsARealtimeDomain can
// never catch this shape, and the guard has to be asserted directly.
//
// What must not regress is the split: the store, API, community and CDN are the
// reason the Steam preset exists, they are HTTPS with SNI, and they stay proxied. A
// current client also logs in over api.steampowered.com and a WebSocket connection
// manager under *.steamserver.net, both of which are on that proxied side — so
// forcing the one unproxyable name direct does not put Steam login back behind the
// censor.
func TestSteamConnectionManagerIsForcedDirect(t *testing.T) {
	m := NewMatcher()

	if rule := mustMatch(t, m, "cm.steampowered.com", ActionDirect); rule != RuleUnproxyableDirect {
		t.Errorf("rule = %q, want %q", rule, RuleUnproxyableDirect)
	}
	// A subscriber who selected the very preset that claims the zone gets the same
	// answer: this is not an opt-in category.
	mustMatchClient(t, m, "cm.steampowered.com", []string{"enable_steam"}, ActionDirect)

	// Everything the preset is actually for stays proxied.
	//
	// steamcontent.com used to stand for "the CDN" here and no longer can: it is the
	// depot plane, which downloads.go vetoes by default. The storefront's own asset
	// host took its place, which is the half of the CDN this preset exists to unblock
	// and the half the veto deliberately leaves alone — see
	// TestDownloadVetoLeavesTheStorefrontAlone.
	for _, d := range []string{
		"steampowered.com",
		"store.steampowered.com",
		"api.steampowered.com", // where a current client fetches its CM list
		"steamcommunity.com",
		"cdn.cloudflare.steamstatic.com",
		"ext1-fra1.steamserver.net", // the WebSocket CM it then connects to, TLS on 443
	} {
		t.Run(d, func(t *testing.T) { mustMatch(t, m, d, ActionProxy) })
	}

	// Not a switch, and it survives the path the dashboard takes on every save.
	m.SetRuleEnabled(RuleUnproxyableDirect, false)
	mustMatch(t, m, "cm.steampowered.com", ActionDirect)
	m.SetCustomRules(nil, nil, nil, nil)
	mustMatch(t, m, "cm.steampowered.com", ActionDirect)

	// But an operator who names it themselves has overridden the guard, exactly as
	// with the real-time set.
	m.SetCustomRules([]string{"cm.steampowered.com"}, nil, nil, nil)
	if rule := mustMatch(t, m, "cm.steampowered.com", ActionProxy); rule != RuleCustomProxy {
		t.Errorf("rule = %q, want %q", rule, RuleCustomProxy)
	}
}

// One domain, one home. The guard would keep working if a preset re-listed a
// real-time name, so nothing would break — which is exactly why this needs a test:
// the preset would claim to proxy something that never resolves to the proxy, and
// the next reader would believe it.
func TestNoPresetListsARealtimeDomain(t *testing.T) {
	m := NewMatcher()

	for name, domains := range GetAllPresets() {
		for _, d := range domains {
			probe := strings.TrimPrefix(normalizeDomain(d), "*.")
			if probe == "" {
				continue
			}
			if _, rule := m.Match(probe); isForcedDirect(rule) {
				t.Errorf("preset %q lists %q, which is covered by forcedDirectGroups; "+
					"remove it from the preset rather than relying on rule precedence", name, d)
			}
		}
	}
}

// Two presets can list the same domain — "rainbow6.com" is in both the Ubisoft and
// the tactical-shooters category, "ea.com" in both the EA and the sports one — and
// the index attributes it to whichever preset name sorts first. That attribution must
// not become the only claim honored: a subscriber sold the sports plan needs
// "ea.com", and an operator who switches the shooters category off must not lose
// Rainbow Six for their Ubisoft users.
func TestCoOwnedPresetDomainHonorsEveryClaim(t *testing.T) {
	for _, c := range []struct {
		domain string
		keys   [2]string
	}{
		{"rainbow6.com", [2]string{"enable_ubisoft", "enable_shooters_extra"}},
		{"ea.com", [2]string{"enable_ea", "enable_sports_racing"}},
	} {
		t.Run(c.domain, func(t *testing.T) {
			m := NewMatcher()

			// Both spellings, so each side of the index is exercised: the bare name
			// probes the exact map, a subdomain walks the parents.
			for _, probe := range []string{c.domain, "sub." + c.domain} {
				for _, key := range c.keys {
					want := PresetRuleKeys[key]
					if rule := mustMatchClient(t, m, probe, []string{key}, ActionProxy); rule != want {
						t.Errorf("MatchForClient(%q, [%s]) attributed to %q, want %q", probe, key, rule, want)
					}
				}
				// No false positives: a client holding neither policy is still walked past.
				mustMatchClient(t, m, probe, []string{"enable_spotify"}, ActionDirect)
			}

			// The operator's disable switches behave the same way. Turning one owner off
			// leaves the other's claim standing; only turning both off makes the domain
			// direct.
			m.SetRuleEnabled(c.keys[0], false)
			if want := PresetRuleKeys[c.keys[1]]; mustMatch(t, m, c.domain, ActionProxy) != want {
				t.Errorf("with %s off, %q is not attributed to %q", c.keys[0], c.domain, want)
			}
			m.SetRuleEnabled(c.keys[1], false)
			mustMatch(t, m, c.domain, ActionDirect)
			m.SetRuleEnabled(c.keys[0], true)
			if want := PresetRuleKeys[c.keys[0]]; mustMatch(t, m, c.domain, ActionProxy) != want {
				t.Errorf("with only %s on, %q is not attributed to %q", c.keys[0], c.domain, want)
			}
		})
	}
}

// A preset with no policy key cannot be toggled from config.json or the dashboard
// and cannot be selected as a per-client policy: applyRulesFromConfig and
// loadPersistedRules both look the key up in PresetRuleKeys and skip on a miss. That
// is how enable_soundcloud became a config key that was read and silently
// discarded, so the mapping is asserted in both directions.
func TestEveryPresetHasExactlyOnePolicyKey(t *testing.T) {
	presets := GetAllPresets()

	for name := range presets {
		if _, ok := presetKeyByName[name]; !ok {
			t.Errorf("preset %q has no enable_* key in PresetRuleKeys", name)
		}
	}
	for key, name := range PresetRuleKeys {
		if _, ok := presets[name]; !ok {
			t.Errorf("PresetRuleKeys[%q] names %q, which GetAllPresets does not define", key, name)
		}
	}
	if len(presetKeyByName) != len(PresetRuleKeys) {
		t.Errorf("two keys map to one preset name: %d names for %d keys",
			len(presetKeyByName), len(PresetRuleKeys))
	}
}

// The catalogue both front-ends now fill their policy pickers from. The order is a
// hand-written slice beside a map, which is exactly the shape that rots: a preset
// added to PresetRuleKeys and not to policyCatalogOrder is simply missing from every
// picker, and nothing in the UI says the list is short.
func TestPolicyCatalog(t *testing.T) {
	catalog := PolicyCatalog()
	if len(catalog) != len(PresetRuleKeys) {
		t.Errorf("PolicyCatalog lists %d presets, PresetRuleKeys defines %d",
			len(catalog), len(PresetRuleKeys))
	}

	seen := map[string]bool{}
	for _, e := range catalog {
		if seen[e.Key] {
			t.Errorf("%q is listed twice, so the picker shows it twice", e.Key)
		}
		seen[e.Key] = true

		name, ok := PresetRuleKeys[e.Key]
		if !ok {
			t.Errorf("catalogue entry %q names no preset", e.Key)
			continue
		}
		// The label is the whole point of serving this: the JS copy had four labels
		// shorter than these, so the panel and the resolver named one category two ways.
		if e.Label != name {
			t.Errorf("%q is labelled %q, but PresetRuleKeys says %q", e.Key, e.Label, name)
		}
		if e.Blocking != IsBlockingRule(e.Key) {
			t.Errorf("%q reports blocking=%v, IsBlockingRule says %v", e.Key, e.Blocking, IsBlockingRule(e.Key))
		}
	}
	for key := range PresetRuleKeys {
		if !seen[key] {
			t.Errorf("%q is in PresetRuleKeys but not in policyCatalogOrder, so no picker "+
				"can offer it and no client can be given that policy", key)
		}
	}

	// Two sinkholing categories exist and both must be flagged, or an operator
	// attaching "FamilySafe Protection" to a subscriber reads it as one more game.
	blocking := 0
	for _, e := range catalog {
		if e.Blocking {
			blocking++
		}
	}
	if blocking == 0 {
		t.Error("no entry is flagged blocking, so the picker cannot tell a sinkhole from a game")
	}
}

// AdBlock and FamilySafe name themselves a sinkhole and a protection filter. Every
// preset used to be loaded into the proxy index, so switching either on answered
// those names with the VPS address and relayed the traffic through the operator's own
// SNI proxy — paying bandwidth to deliver the ads the feature exists to remove, and
// giving the adult-site filter no blocking effect at all.
func TestBlockPresetsSinkholeRatherThanProxy(t *testing.T) {
	tests := []struct {
		key    string
		domain string
	}{
		{"enable_adblock", "doubleclick.net"},
		{"enable_adblock", "ads.doubleclick.net"},
		{"enable_adblock", "google-analytics.com"},
		{"enable_familysafe", "pornhub.com"},
		{"enable_familysafe", "www.xvideos.com"},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			m := NewMatcher()
			m.SetRuleEnabled(tc.key, true)
			mustMatch(t, m, tc.domain, ActionBlock)
		})
	}
}

// A resolver that starts sinkholing names because a config key was absent is worse
// than one that forwards them, so the blocking categories are off until the operator
// asks for them. The dashboard defaults and config.example.json ship them disabled;
// this pins the in-memory default to agree.
func TestBlockPresetsAreDisabledByDefault(t *testing.T) {
	m := NewMatcher()

	for _, key := range []string{"enable_adblock", "enable_familysafe"} {
		if m.IsRuleEnabled(key) {
			t.Errorf("IsRuleEnabled(%q) = true, want false on a fresh matcher", key)
		}
	}
	for _, d := range []string{"doubleclick.net", "ads.doubleclick.net", "pornhub.com"} {
		mustMatch(t, m, d, ActionDirect)
	}
	// Every other preset is on, so the default deployment proxies games without
	// the operator touching a switch.
	if !m.IsRuleEnabled("enable_riot") {
		t.Error("IsRuleEnabled(\"enable_riot\") = false, want true on a fresh matcher")
	}
}

// Callers reach SetRuleEnabled with whichever identifier they happen to hold: the
// config file and the dashboard send enable_* keys, while loadPersistedRules and the
// TUI have display names. Accepting only one form silently toggled a rule that never
// matched anything.
func TestRuleTogglesAcceptKeyOrDisplayName(t *testing.T) {
	for _, id := range []string{"enable_adblock", "AdBlock & Tracker Sinkhole"} {
		t.Run(id, func(t *testing.T) {
			m := NewMatcher()

			m.SetRuleEnabled(id, true)
			if !m.IsRuleEnabled(id) {
				t.Fatalf("IsRuleEnabled(%q) = false after enabling", id)
			}
			mustMatch(t, m, "doubleclick.net", ActionBlock)

			m.SetRuleEnabled(id, false)
			if m.IsRuleEnabled(id) {
				t.Fatalf("IsRuleEnabled(%q) = true after disabling", id)
			}
			mustMatch(t, m, "doubleclick.net", ActionDirect)
		})
	}
	// An identifier that names nothing must not create a phantom disable entry
	// that a real rule could later collide with.
	m := NewMatcher()
	m.SetRuleEnabled("   ", false)
	mustMatch(t, m, "riotgames.com", ActionProxy)
}

// A subscriber's policy selection is the product the reseller sells: the categories
// on their plan are proxied, everything else is forwarded. An empty selection means
// "no plan of your own", which inherits the operator's global rules rather than
// disabling every rule.
func TestClientPolicySelection(t *testing.T) {
	m := NewMatcher()
	riotOnly := []string{"enable_riot"}

	mustMatchClient(t, m, "auth.riotgames.com", riotOnly, ActionProxy)
	mustMatchClient(t, m, "epicgames.com", riotOnly, ActionDirect)

	for _, empty := range [][]string{nil, {}, {"", "   "}} {
		mustMatchClient(t, m, "epicgames.com", empty, ActionProxy)
	}

	// Display names are accepted alongside keys: policies persisted before the
	// dashboard settled on enable_* keys are stored as names.
	mustMatchClient(t, m, "epicgames.com", []string{"Epic Games & Fortnite"}, ActionProxy)
}

// enable_soundcloud had no entry in PresetRuleKeys, so policyAllows could never
// authorize the preset for a subscriber no matter what their plan said. This is the
// end-to-end regression test for that key.
func TestSoundCloudPolicyIsSelectable(t *testing.T) {
	m := NewMatcher()

	mustMatchClient(t, m, "soundcloud.com", []string{"enable_soundcloud"}, ActionProxy)
	mustMatchClient(t, m, "api.sndcdn.com", []string{"enable_soundcloud"}, ActionProxy)
	mustMatchClient(t, m, "soundcloud.com", []string{"enable_spotify"}, ActionDirect)

	// The key also has to survive the toggle path, which is where it was dropped.
	m.SetRuleEnabled("enable_soundcloud", false)
	mustMatch(t, m, "soundcloud.com", ActionDirect)
	mustMatchClient(t, m, "soundcloud.com", []string{"enable_soundcloud"}, ActionDirect)
}

// A rule the operator switched off must be walked past, not treated as the end of the
// search: it may sit above a shorter rule that does apply. The filter is exercised
// directly here because two overlapping rules with distinct names cannot be built out
// of the operator's custom lists, which carry one name per list.
func TestDisabledRuleDoesNotShadowShorterRule(t *testing.T) {
	rs := newRuleSet()
	rs.index("example.com", "Short", false)
	rs.index("*.deep.example.com", "Long", false)

	f := policyFilter{disabled: map[string]bool{"Long": true}}
	name, ok := rs.lookup("host.deep.example.com", f)
	if !ok || name != "Short" {
		t.Errorf("lookup = (%q, %v), want (\"Short\", true) — the disabled rule shadowed it", name, ok)
	}
}

// The operator's three lists are admin-wide. The per-client policy picker offers only
// enable_* preset keys, so gating the custom lists on a client's selection — as the
// previous version did — meant a domain the operator had explicitly blocked stayed
// resolvable for every subscriber that carried a plan, and an explicit proxy or
// whitelist entry never applied to them either.
func TestCustomListsApplyToClientsWithPolicies(t *testing.T) {
	m := NewMatcher()
	m.SetCustomRules(
		[]string{"relay.example"},
		[]string{"malware.example", "*.ads.example"},
		[]string{"bank.example"},
		nil,
	)
	riotOnly := []string{"enable_riot"}

	tests := []struct {
		domain string
		want   Action
		rule   string
	}{
		{"malware.example", ActionBlock, RuleCustomBlock},
		{"tracker.ads.example", ActionBlock, RuleCustomBlock},
		{"relay.example", ActionProxy, RuleCustomProxy},
		{"bank.example", ActionDirect, RuleCustomDirect},
		{"sub.bank.example", ActionDirect, RuleCustomDirect},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			if rule := mustMatchClient(t, m, tc.domain, riotOnly, tc.want); rule != tc.rule {
				t.Errorf("rule = %q, want %q", rule, tc.rule)
			}
			// The global view must agree; both entry points share one path.
			if rule := mustMatch(t, m, tc.domain, tc.want); rule != tc.rule {
				t.Errorf("global rule = %q, want %q", rule, tc.rule)
			}
		})
	}
}

// The operator typed these in by hand, so they win over a preset covering the same
// name — including a preset that is currently switched off, which is the case that
// used to lose because the preset owned the index entry.
func TestCustomRuleOverridesPreset(t *testing.T) {
	m := NewMatcher()
	// doubleclick.net belongs to AdBlock, which is disabled by default.
	m.SetCustomRules(nil, []string{"doubleclick.net"}, []string{"riotgames.com"}, nil)

	if rule := mustMatch(t, m, "doubleclick.net", ActionBlock); rule != RuleCustomBlock {
		t.Errorf("rule = %q, want %q", rule, RuleCustomBlock)
	}
	if rule := mustMatch(t, m, "riotgames.com", ActionDirect); rule != RuleCustomDirect {
		t.Errorf("rule = %q, want %q", rule, RuleCustomDirect)
	}
}

// Precedence inside one rule set is longest-suffix-wins. The previous linear scan
// returned whichever overlapping rule happened to be indexed first, which for the
// presets was map-iteration order and therefore differed between restarts.
func TestLongestSuffixWins(t *testing.T) {
	rs := newRuleSet()
	rs.index("example.com", "Short", false)
	rs.index("*.deep.example.com", "Long", false)

	tests := []struct {
		domain string
		want   string
	}{
		{"host.deep.example.com", "Long"},
		{"a.b.host.deep.example.com", "Long"},
		{"deep.example.com", "Short"}, // the wildcard does not match its own parent
		{"other.example.com", "Short"},
		{"example.com", "Short"},
		{"notexample.com", ""},
		{"com", ""},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			name, ok := rs.lookup(tc.domain, policyFilter{})
			if ok != (tc.want != "") || name != tc.want {
				t.Errorf("lookup(%q) = (%q, %v), want %q", tc.domain, name, ok, tc.want)
			}
		})
	}
}

// A plain rule matches the name itself and every subdomain; a *. rule matches only
// strict subdomains. Keeping the two distinct is what lets an operator proxy a CDN's
// hosts without capturing the apex, and it is the semantics the old leading-dot
// suffix encoding had.
func TestWildcardAndPlainRuleScope(t *testing.T) {
	m := NewMatcher()
	m.SetCustomRules([]string{"*.cdn.example", "plain.example"}, nil, nil, nil)

	mustMatch(t, m, "asset.cdn.example", ActionProxy)
	mustMatch(t, m, "a.b.cdn.example", ActionProxy)
	mustMatch(t, m, "cdn.example", ActionDirect)

	mustMatch(t, m, "plain.example", ActionProxy)
	mustMatch(t, m, "www.plain.example", ActionProxy)

	// A shared suffix is not a label boundary: "notplain.example" must not match a
	// rule for "plain.example".
	mustMatch(t, m, "notplain.example", ActionDirect)
	mustMatch(t, m, "xcdn.example", ActionDirect)
}

// A pattern the label index cannot honor is dropped rather than stored under a
// literal "*" label, where it would sit in the map looking like a rule and never
// match anything.
func TestIndexRejectsUnsupportedPatterns(t *testing.T) {
	rs := newRuleSet()
	for _, pattern := range []string{"", "   ", ".", "*", "*.", "**", "foo.*.com", "*.foo.*", "a*b.com"} {
		rs.index(pattern, "Rejected", false)
	}
	if n := rs.size(); n != 0 {
		t.Errorf("indexed %d of the unsupported patterns, want 0", n)
	}

	// The forms that are supported, including a trailing root dot and mixed case.
	rs.index("Foo.COM.", "Kept", false)
	rs.index("*.Bar.Example.", "Kept", false)
	if n := rs.size(); n != 2 {
		t.Fatalf("index size = %d, want 2", n)
	}
	if name, ok := rs.lookup("host.bar.example", policyFilter{}); !ok || name != "Kept" {
		t.Errorf("lookup of a normalized wildcard = (%q, %v), want (\"Kept\", true)", name, ok)
	}
	if name, ok := rs.lookup("foo.com", policyFilter{}); !ok || name != "Kept" {
		t.Errorf("lookup of a normalized plain rule = (%q, %v), want (\"Kept\", true)", name, ok)
	}
}

// Queries arrive as wire-format names: case-preserved as the client typed them and
// carrying the root label. The index is keyed without either.
func TestQueryNormalization(t *testing.T) {
	m := NewMatcher()

	for _, spelling := range []string{
		"riotgames.com",
		"riotgames.com.",
		"RIOTGAMES.COM",
		"RiotGames.Com.",
		"  riotgames.com.  ",
	} {
		t.Run(spelling, func(t *testing.T) { mustMatch(t, m, spelling, ActionProxy) })
	}

	// A name that normalizes to nothing must not panic or match a rule.
	for _, empty := range []string{"", ".", "   ", "  .  "} {
		if action, rule := m.Match(empty); action != ActionDirect || rule != "Direct" {
			t.Errorf("Match(%q) = %v (%s), want DIRECT (Direct)", empty, action, rule)
		}
	}
}

// SetCustomRules replaces the operator's lists; it does not accumulate. Calling it
// twice with the same input must leave the same index, and a domain dropped from the
// list must stop matching — this is the path the dashboard takes on every save.
func TestSetCustomRulesReplacesRatherThanAccumulates(t *testing.T) {
	m := NewMatcher()
	// The direct baseline is not zero: the forced-direct real-time set is counted
	// there too, and it is rebuilt with the presets on every save.
	presetDirect, presetBlocked, presetProxied := m.RuleCounts()

	m.SetCustomRules([]string{"a.example", "b.example"}, []string{"bad.example"}, []string{"ok.example"}, nil)
	direct, blocked, proxied := m.RuleCounts()
	if direct != presetDirect+1 {
		t.Errorf("direct count = %d, want %d", direct, presetDirect+1)
	}
	if blocked != presetBlocked+1 {
		t.Errorf("blocked count = %d, want %d", blocked, presetBlocked+1)
	}
	if proxied != presetProxied+2 {
		t.Errorf("proxied count = %d, want %d", proxied, presetProxied+2)
	}

	m.SetCustomRules([]string{"a.example", "b.example"}, []string{"bad.example"}, []string{"ok.example"}, nil)
	if d, b, p := m.RuleCounts(); d != direct || b != blocked || p != proxied {
		t.Errorf("counts after an identical reload = (%d, %d, %d), want (%d, %d, %d)", d, b, p, direct, blocked, proxied)
	}

	m.SetCustomRules(nil, nil, nil, nil)
	if d, b, p := m.RuleCounts(); d != presetDirect || b != presetBlocked || p != presetProxied {
		t.Errorf("counts after clearing = (%d, %d, %d), want (%d, %d, %d)", d, b, p, presetDirect, presetBlocked, presetProxied)
	}
	mustMatch(t, m, "bad.example", ActionDirect)
	// Presets are rebuilt alongside the custom lists, so a reload must not leave
	// the daemon with no rules at all.
	mustMatch(t, m, "riotgames.com", ActionProxy)
}

// A custom A record is keyed by the normalized name, because GetCustomRecord
// normalizes the queried name before probing: a configured "pin.example." never
// matched anything.
func TestCustomRecordNormalization(t *testing.T) {
	m := NewMatcher()
	m.SetCustomRules(nil, nil, nil, map[string]string{
		"Pin.Example.":  "10.0.0.1",
		"  spaced.io ":  " 10.0.0.2 ",
		"blank.example": "   ",
		"":              "10.0.0.3",
	})

	for _, probe := range []string{"pin.example", "PIN.EXAMPLE.", "Pin.Example"} {
		if ip, ok := m.GetCustomRecord(probe); !ok || ip != "10.0.0.1" {
			t.Errorf("GetCustomRecord(%q) = (%q, %v), want (\"10.0.0.1\", true)", probe, ip, ok)
		}
	}
	if ip, ok := m.GetCustomRecord("spaced.io"); !ok || ip != "10.0.0.2" {
		t.Errorf("GetCustomRecord(\"spaced.io\") = (%q, %v), want (\"10.0.0.2\", true)", ip, ok)
	}
	// An entry with no address would answer the query with an empty A record.
	if _, ok := m.GetCustomRecord("blank.example"); ok {
		t.Error("an entry with a blank address was kept")
	}
}

// A domain listed by two presets can only be attributed to one of them. Which one is
// arbitrary, but it must be the same one on every start: presets are indexed in
// sorted display-name order with first-writer-wins, because map iteration order made
// the rule label in the query log change between restarts.
func TestPresetAttributionIsDeterministic(t *testing.T) {
	owners := map[string]map[string]bool{}
	for name, domains := range GetAllPresets() {
		for _, d := range domains {
			// Both spellings of a domain land on the same index key, so they are
			// folded together — otherwise a preset that lists "foo.com" and
			// "*.foo.com" would look like two presets claiming one domain.
			d = strings.TrimPrefix(normalizeDomain(d), "*.")
			if owners[d] == nil {
				owners[d] = map[string]bool{}
			}
			owners[d][name] = true
		}
	}

	var shared []string
	for d, names := range owners {
		if len(names) > 1 {
			shared = append(shared, d)
		}
	}
	if len(shared) == 0 {
		t.Skip("no domain is listed by more than one preset")
	}

	first := NewMatcher()
	want := make(map[string]string, len(shared))
	for _, d := range shared {
		_, rule := first.Match(d)
		want[d] = rule
	}
	for i := range 8 {
		m := NewMatcher()
		for _, d := range shared {
			if _, rule := m.Match(d); rule != want[d] {
				t.Fatalf("matcher %d attributes %q to %q, the first attributes it to %q", i, d, rule, want[d])
			}
		}
	}
	t.Logf("%d domain(s) are listed by more than one preset", len(shared))
}

// The index is replaced wholesale on every dashboard save while queries are being
// served, so readers must never observe a half-built rule set. The race detector is
// unavailable in this environment (no C compiler), so this is a stress substitute: it
// can surface a panic or a torn read, but it cannot certify the matcher race-free.
func TestConcurrentMatchDuringReload(t *testing.T) {
	const (
		readers = 24
		rounds  = 500
	)
	m := NewMatcher()
	policies := []string{"enable_riot", "enable_steam", "enable_discord"}

	names := make([]string, 32)
	for i := range names {
		names[i] = fmt.Sprintf("host%d.auth.riotgames.com", i)
	}

	var wg sync.WaitGroup
	for w := range readers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := range rounds {
				d := names[(w*rounds+r)%len(names)]
				switch r % 4 {
				case 0:
					// Riot is a preset, so this must hold whatever the writer is
					// doing to the custom lists.
					if action, rule := m.Match(d); action != ActionProxy {
						t.Errorf("Match(%q) = %v (%s) during a reload, want PROXY", d, action, rule)
						return
					}
				case 1:
					m.MatchForClient(d, policies)
				case 2:
					m.GetCustomRecord(d)
				default:
					m.RuleCounts()
				}
			}
		}(w)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			m.SetCustomRules(
				[]string{fmt.Sprintf("relay%d.example", i), "*.cdn.example"},
				[]string{fmt.Sprintf("bad%d.example", i)},
				[]string{fmt.Sprintf("ok%d.example", i)},
				map[string]string{fmt.Sprintf("pin%d.example", i): "10.0.0.1"},
			)
			m.SetRuleEnabled("enable_adblock", i%2 == 0)
		}
	}()

	wg.Wait()
}
