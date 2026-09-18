package matcher

import (
	"strings"
	"testing"
)

// The download veto is the only rule set whose *disabled* state changes an answer,
// so every test below is written against the state that ships: off. The failure it
// guards against is not a wrong verdict on one name — it is the switch quietly
// doing nothing, or doing more than it was asked, on a subscriber's game library.

// The default. An operator who installs this daemon and switches on Steam gets the
// store proxied and the depot direct, without touching anything.
func TestDownloadVetoIsOffByDefault(t *testing.T) {
	m := NewMatcher()

	if DefaultRuleEnabled("enable_downloads") {
		t.Error("DefaultRuleEnabled(enable_downloads) = true; the dashboard would offer the " +
			"switch ON while NewMatcher holds it OFF, and the first unrelated save would " +
			"post that back and start relaying installs")
	}
	if m.IsRuleEnabled(RuleDownloads) {
		t.Error("NewMatcher enabled the download veto")
	}
	// And it is not a blocking rule, so nothing derived from IsBlockingRule treats it
	// as a sinkhole.
	if IsBlockingRule(RuleDownloads) {
		t.Error("IsBlockingRule(RuleDownloads) = true; it proxies nothing and sinkholes nothing")
	}

	rule := mustMatch(t, m, "steamcontent.com", ActionDirect)
	if rule != RuleDownloads {
		t.Errorf("rule = %q, want %q — the query log has to name the reason a depot went "+
			"direct, or an operator debugging a slow install has nothing to look at", rule, RuleDownloads)
	}
}

// Switched on, the veto stops firing and the game preset proxies its CDN as before.
// This is the assertion that the layer is subtractive: turning it on must not be
// able to change anything else.
func TestDownloadVetoEnabledRestoresTheProxyPath(t *testing.T) {
	m := NewMatcher()
	m.SetRuleEnabled("enable_downloads", true)

	rule := mustMatch(t, m, "steamcontent.com", ActionProxy)
	if rule != "Steam & Valve (CS2, Dota 2)" {
		t.Errorf("rule = %q, want the Steam preset — with the veto lifted the name must be "+
			"attributed to whoever actually proxies it", rule)
	}
}

// Every domain in the set must be proxied by some enabled-by-default preset when the
// veto is lifted. A name that is DIRECT in both states is not a veto, it is dead
// configuration: the switch appears to control it and does not, and the operator who
// turns downloads on to rescue a subscriber whose line cannot reach a CDN gets no
// change and no error.
func TestEveryDownloadDomainIsProxiedWhenEnabled(t *testing.T) {
	m := NewMatcher()
	m.SetRuleEnabled("enable_downloads", true)

	for _, d := range PresetDownloads {
		probe := strings.TrimPrefix(normalizeDomain(d), "*.")
		t.Run(probe, func(t *testing.T) {
			action, rule := m.Match(probe)
			if action != ActionProxy {
				t.Fatalf("Match(%q) = %v (%s), want PROXY. Nothing in PresetDownloads may be "+
					"the only rule covering a name — add it to the game preset that owns it, "+
					"or drop it from here.", probe, action, rule)
			}
			if rule == RuleDownloads {
				t.Fatalf("Match(%q) attributed the name to %q, so the download set is indexed "+
					"as a proxy rule of its own. It must only ever subtract.", probe, rule)
			}
		})
	}
}

// A wildcard entry has to cover the hosts a launcher actually resolves, not just the
// zone apex. These are the names that appear in a real install.
func TestDownloadVetoCoversSubdomains(t *testing.T) {
	m := NewMatcher()

	for _, d := range []string{
		"valve.cs.download.steamcontent.com",
		"gs2.ww.prod.dl.playstation.net",
		"blzddist1.cdn.blizzard.com",
		"cdn.gog.com",
		"patches.rockstargames.com",
	} {
		t.Run(d, func(t *testing.T) {
			if rule := mustMatch(t, m, d, ActionDirect); rule != RuleDownloads {
				t.Errorf("rule = %q, want %q", rule, RuleDownloads)
			}
		})
	}
}

// The curation rule, asserted rather than left in a comment: the veto must not touch
// anything a subscriber needs in order to reach a store, sign in, or launch a client.
// Each of these is inside a zone the veto also draws from, so an over-broad entry —
// steamstatic.com instead of steamcontent.com, rbxcdn.com instead of setup. — lands
// here first.
func TestDownloadVetoLeavesTheStorefrontAlone(t *testing.T) {
	m := NewMatcher()

	for _, d := range []string{
		"cdn.cloudflare.steamstatic.com",      // store art and library images
		"store.steampowered.com",              // the store itself
		"account.epicgames.com",               // Epic sign-in
		"ol.epicgames.com",                    // Epic entitlements
		"eaassets-a.akamaihd.net",             // EA storefront art
		"prod.ros.rockstargames.com",          // Rockstar entitlement service
		"static-asset-delivery.cloud.ubi.com", // Ubisoft Connect's own UI content
		"assetgame.roblox.com",                // per-play asset streaming
		"blzstatic.com",                       // Battle.net launcher art
	} {
		t.Run(d, func(t *testing.T) { mustMatch(t, m, d, ActionProxy) })
	}
}

// Per-client scope. The four states the operator asked for, in one place, because the
// interaction between a global switch and a plan is where a reseller loses money or a
// subscriber loses a download.
func TestDownloadVetoPerClientMatrix(t *testing.T) {
	const depot = "steamcontent.com"

	t.Run("global off beats a plan that selected it", func(t *testing.T) {
		m := NewMatcher() // veto off
		// The subscriber's plan names the download category, but the operator pays for
		// the bandwidth, so the operator's OFF wins.
		mustMatchClient(t, m, depot, []string{"enable_steam", "enable_downloads"}, ActionDirect)
	})

	t.Run("global on, plan selected it", func(t *testing.T) {
		m := NewMatcher()
		m.SetRuleEnabled("enable_downloads", true)
		mustMatchClient(t, m, depot, []string{"enable_steam", "enable_downloads"}, ActionProxy)
	})

	t.Run("global on, plan did not select it", func(t *testing.T) {
		m := NewMatcher()
		m.SetRuleEnabled("enable_downloads", true)
		// A cheaper plan: Steam is proxied, the depot is not. This is the shape a
		// reseller sells, and it is why the category is per-client at all.
		if rule := mustMatchClient(t, m, depot, []string{"enable_steam"}, ActionDirect); rule != RuleDownloads {
			t.Errorf("rule = %q, want %q", rule, RuleDownloads)
		}
		mustMatchClient(t, m, "store.steampowered.com", []string{"enable_steam"}, ActionProxy)
	})

	t.Run("a client with no plan inherits the global state", func(t *testing.T) {
		m := NewMatcher()
		m.SetRuleEnabled("enable_downloads", true)
		mustMatchClient(t, m, depot, nil, ActionProxy)
		m.SetRuleEnabled("enable_downloads", false)
		mustMatchClient(t, m, depot, nil, ActionDirect)
	})
}

// With the game preset off there is nothing to subtract, so the veto's state must not
// matter. This is the property that made a fifth rule set the right shape instead of
// indexing these names as a proxy rule: the alternative proxied a Steam depot for an
// operator who had switched Steam off.
func TestDownloadVetoCannotProxyWhatThePresetDoesNot(t *testing.T) {
	for _, vetoOn := range []bool{false, true} {
		m := NewMatcher()
		m.SetRuleEnabled("enable_steam", false)
		m.SetRuleEnabled("enable_downloads", vetoOn)
		if action, rule := m.Match("steamcontent.com"); action != ActionDirect {
			t.Errorf("with Steam off and the veto=%v, Match = %v (%s), want DIRECT", vetoOn, action, rule)
		}
	}
}

// Custom Proxy is the operator's override for one host, and it has to reach past the
// veto — the veto is consulted first, so without the unindex in SetCustomRules the
// entry saved cleanly and changed nothing.
func TestCustomProxyOverridesTheDownloadVeto(t *testing.T) {
	m := NewMatcher()
	m.SetCustomRules([]string{"steamcontent.com"}, nil, nil, nil)

	if rule := mustMatch(t, m, "steamcontent.com", ActionProxy); rule != RuleCustomProxy {
		t.Errorf("rule = %q, want %q", rule, RuleCustomProxy)
	}
	// The whole zone, not just the label typed: a bare domain is indexed as both an
	// exact and a wildcard entry everywhere in this package, so the unindex lifts the
	// veto from the depot hosts a launcher actually resolves. Anything narrower would
	// be a trap — the operator overrides "steamcontent.com" and the install still goes
	// direct, because no launcher ever queries the apex.
	if rule := mustMatch(t, m, "valve.cs.download.steamcontent.com", ActionProxy); rule != RuleCustomProxy {
		t.Errorf("subdomain rule = %q, want %q", rule, RuleCustomProxy)
	}
	// One zone only. The rest of the veto is untouched, which is the point of doing
	// this per-domain instead of switching the category on.
	if rule := mustMatch(t, m, "cdn.gog.com", ActionDirect); rule != RuleDownloads {
		t.Errorf("unrelated depot rule = %q, want %q", rule, RuleDownloads)
	}
	// And clearing the list restores the veto, because the presets are rebuilt with it.
	m.SetCustomRules(nil, nil, nil, nil)
	if rule := mustMatch(t, m, "steamcontent.com", ActionDirect); rule != RuleDownloads {
		t.Errorf("after clearing, rule = %q, want %q", rule, RuleDownloads)
	}
	if rule := mustMatch(t, m, "valve.cs.download.steamcontent.com", ActionDirect); rule != RuleDownloads {
		t.Errorf("after clearing, subdomain rule = %q, want %q", rule, RuleDownloads)
	}
}

// Custom Block still outranks everything: the veto answers DIRECT, and an operator who
// asked for a name to stop resolving must not get a direct answer instead.
func TestCustomBlockOutranksTheDownloadVeto(t *testing.T) {
	m := NewMatcher()
	m.SetCustomRules(nil, []string{"steamcontent.com"}, nil, nil)

	if rule := mustMatch(t, m, "steamcontent.com", ActionBlock); rule != RuleCustomBlock {
		t.Errorf("rule = %q, want %q", rule, RuleCustomBlock)
	}
}

// The veto set is not counted as an action index. If it ever is, the dashboard's
// "proxied domains" figure double-counts every CDN and the number stops meaning
// anything an operator can check.
func TestDownloadVetoDoesNotChangeRuleCounts(t *testing.T) {
	m := NewMatcher()
	directOff, blockedOff, proxiedOff := m.RuleCounts()

	m.SetRuleEnabled("enable_downloads", true)
	directOn, blockedOn, proxiedOn := m.RuleCounts()

	if directOff != directOn || blockedOff != blockedOn || proxiedOff != proxiedOn {
		t.Errorf("RuleCounts changed with the veto: (%d,%d,%d) -> (%d,%d,%d)",
			directOff, blockedOff, proxiedOff, directOn, blockedOn, proxiedOn)
	}
	if proxiedOff == 0 {
		t.Fatal("proxied count is 0, so this test proved nothing")
	}
}

// A forced-direct name must stay direct and keep its own label. The veto is consulted
// after the real-time plane precisely so a name in both is attributed to the reason
// that cannot be switched off.
func TestForcedDirectOutranksTheDownloadVeto(t *testing.T) {
	m := NewMatcher()
	m.SetRuleEnabled("enable_downloads", true)

	if rule := mustMatch(t, m, "cm.steampowered.com", ActionDirect); rule != RuleUnproxyableDirect {
		t.Errorf("rule = %q, want %q", rule, RuleUnproxyableDirect)
	}
}
