package matcher

import "testing"

// TestCustomGroupProxyBeatsPresetAndSurvivesCatalogSwap covers the two
// properties a named custom group has to hold: it resolves to its action, and it
// is still there after a preset-channel catalog swap — the swap rebuilds the
// preset indexes, and a group that vanished on update would silently stop
// routing.
func TestCustomGroupProxyBeatsPresetAndSurvivesCatalogSwap(t *testing.T) {
	m := NewMatcher()
	m.SetCustomGroups([]CustomGroup{{
		Name:    "My Bundle",
		Action:  ActionProxy,
		Domains: []string{"example-game.test", "*.example-game.test"},
		Enabled: true,
	}})

	if action, rule := m.Match("cdn.example-game.test"); action != ActionProxy || rule != "Custom Group: My Bundle" {
		t.Fatalf("group proxy = (%v, %q), want (PROXY, Custom Group: My Bundle)", action, rule)
	}

	// A catalog swap (what the preset channel does) must not drop the group.
	m.SetCatalog(map[string][]string{"Riot Games & Valorant": {"riotgames.com"}})
	if action, _ := m.Match("cdn.example-game.test"); action != ActionProxy {
		t.Fatalf("custom group did not survive a catalog swap")
	}
}

func TestCustomGroupBlockAndDirectActions(t *testing.T) {
	m := NewMatcher()
	m.SetCustomGroups([]CustomGroup{
		{Name: "Sink", Action: ActionBlock, Domains: []string{"ads.test"}, Enabled: true},
		{Name: "Passthrough", Action: ActionDirect, Domains: []string{"bank.test"}, Enabled: true},
	})
	if action, _ := m.Match("ads.test"); action != ActionBlock {
		t.Errorf("block group did not block")
	}
	if action, _ := m.Match("bank.test"); action != ActionDirect {
		t.Errorf("direct group did not resolve direct")
	}
}

func TestDisabledCustomGroupDoesNothing(t *testing.T) {
	m := NewMatcher()
	m.SetCustomGroups([]CustomGroup{{
		Name:    "Off",
		Action:  ActionBlock,
		Domains: []string{"nothing.test"},
		Enabled: false,
	}})
	if action, _ := m.Match("nothing.test"); action != ActionDirect {
		t.Errorf("a disabled group still affected resolution: got %v", action)
	}
}

// TestCustomGroupsCoexistWithFlatCustomLists proves a SetCustomRules call after
// SetCustomGroups keeps both — the flat lists used to be the only custom state
// and must not wipe the groups, and vice versa.
func TestCustomGroupsCoexistWithFlatCustomLists(t *testing.T) {
	m := NewMatcher()
	m.SetCustomGroups([]CustomGroup{{
		Name: "Group", Action: ActionProxy, Domains: []string{"g.test"}, Enabled: true,
	}})
	m.SetCustomRules([]string{"flat.test"}, nil, nil, nil)

	if action, _ := m.Match("g.test"); action != ActionProxy {
		t.Errorf("group lost after SetCustomRules")
	}
	if action, rule := m.Match("flat.test"); action != ActionProxy || rule != RuleCustomProxy {
		t.Errorf("flat custom proxied lost: (%v, %q)", action, rule)
	}
}
