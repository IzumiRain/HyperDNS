package rules

import (
	"strings"
	"sync"

	"hyperdns/internal/config"
)

type Action int

const (
	ActionDirect Action = iota
	ActionProxy
	ActionBlock
	ActionCustom
)

func (a Action) String() string {
	switch a {
	case ActionDirect:
		return "DIRECT"
	case ActionProxy:
		return "PROXY"
	case ActionBlock:
		return "BLOCK"
	case ActionCustom:
		return "CUSTOM"
	default:
		return "UNKNOWN"
	}
}

type RuleMatchResult struct {
	Action    Action
	CustomIP  string
	MatchedBy string
}

type Matcher struct {
	mu            sync.RWMutex
	exactProxied  map[string]string // domain -> category
	suffixProxied map[string]string // suffix (without leading .) -> category
	exactBlocked  map[string]string // domain -> reason
	suffixBlocked map[string]string // suffix -> reason
	exactDirect   map[string]struct{}
	suffixDirect  map[string]struct{}
	customRecords map[string]string // domain -> custom ip
}

func NewMatcher(cfg *config.Config) *Matcher {
	m := &Matcher{
		exactProxied:  make(map[string]string),
		suffixProxied: make(map[string]string),
		exactBlocked:  make(map[string]string),
		suffixBlocked: make(map[string]string),
		exactDirect:   make(map[string]struct{}),
		suffixDirect:  make(map[string]struct{}),
		customRecords: make(map[string]string),
	}
	m.Rebuild(cfg)
	return m
}

func (m *Matcher) Rebuild(cfg *config.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.exactProxied = make(map[string]string)
	m.suffixProxied = make(map[string]string)
	m.exactBlocked = make(map[string]string)
	m.suffixBlocked = make(map[string]string)
	m.exactDirect = make(map[string]struct{})
	m.suffixDirect = make(map[string]struct{})
	m.customRecords = make(map[string]string)

	addProxyRules := func(list []string, category string) {
		for _, raw := range list {
			d := strings.ToLower(strings.TrimSpace(raw))
			if d == "" {
				continue
			}
			if strings.HasPrefix(d, "*.") {
				suffix := strings.TrimPrefix(d, "*.")
				m.suffixProxied[suffix] = category
			} else if strings.HasPrefix(d, ".") {
				suffix := strings.TrimPrefix(d, ".")
				m.suffixProxied[suffix] = category
			} else {
				m.exactProxied[d] = category
				m.suffixProxied[d] = category
			}
		}
	}

	addBlockRules := func(list []string, reason string) {
		for _, raw := range list {
			d := strings.ToLower(strings.TrimSpace(raw))
			if d == "" {
				continue
			}
			if strings.HasPrefix(d, "*.") {
				suffix := strings.TrimPrefix(d, "*.")
				m.suffixBlocked[suffix] = reason
			} else if strings.HasPrefix(d, ".") {
				suffix := strings.TrimPrefix(d, ".")
				m.suffixBlocked[suffix] = reason
			} else {
				m.exactBlocked[d] = reason
				m.suffixBlocked[d] = reason
			}
		}
	}

	// 1. Proxied Gaming & 403 Presets
	if cfg.Rules.EnableRiot {
		addProxyRules(PresetRiot, "Riot Games")
	}
	if cfg.Rules.EnableEpic {
		addProxyRules(PresetEpic, "Epic Games")
	}
	if cfg.Rules.EnableSteam {
		addProxyRules(PresetSteam, "Steam")
	}
	if cfg.Rules.EnablePUBG {
		addProxyRules(PresetPUBG, "PUBG Mobile & PC")
	}
	if cfg.Rules.EnableCallOfDuty {
		addProxyRules(PresetCallOfDuty, "Call of Duty")
	}
	if cfg.Rules.EnableSupercell {
		addProxyRules(PresetSupercell, "Supercell")
	}
	if cfg.Rules.EnableDiscord {
		addProxyRules(PresetDiscord, "Discord")
	}
	if cfg.Rules.EnableEA {
		addProxyRules(PresetEA, "EA / Origin")
	}
	if cfg.Rules.EnableBlizzard {
		addProxyRules(PresetBlizzard, "Blizzard / Battle.net")
	}
	if cfg.Rules.EnableUbisoft {
		addProxyRules(PresetUbisoft, "Ubisoft Connect")
	}
	if cfg.Rules.EnableRockstar {
		addProxyRules(PresetRockstar, "Rockstar Games")
	}
	if cfg.Rules.EnableXbox {
		addProxyRules(PresetXbox, "Xbox Live")
	}
	if cfg.Rules.EnablePlayStation {
		addProxyRules(PresetPlayStation, "PlayStation Network")
	}
	if cfg.Rules.EnableRoblox {
		addProxyRules(PresetRoblox, "Roblox")
	}
	if cfg.Rules.EnableSpotify {
		addProxyRules(PresetSpotify, "Spotify")
	}
	if cfg.Rules.EnableTwitch {
		addProxyRules(PresetTwitch, "Twitch")
	}
	if cfg.Rules.EnableKick {
		addProxyRules(PresetKick, "Kick")
	}
	if cfg.Rules.EnableDev403 {
		addProxyRules(PresetDev403, "Developer 403")
	}

	// 2. Blocked Presets (AdGuard & Family Safe)
	if cfg.Rules.EnableAdBlock {
		addBlockRules(PresetAdBlock, "AdBlock & Telemetry")
	}
	if cfg.Rules.EnableFamilySafe {
		addBlockRules(PresetFamilySafe, "Family Safe Filter")
	}

	// 3. Custom Proxied
	for _, d := range cfg.Rules.CustomProxied {
		addProxyRules([]string{d}, "Custom Proxy")
	}

	// 4. Custom Blocked
	for _, d := range cfg.Rules.CustomBlocked {
		addBlockRules([]string{d}, "Custom Blocklist")
	}

	// 5. Custom Direct
	for _, d := range cfg.Rules.CustomDirect {
		norm := strings.ToLower(strings.TrimSpace(d))
		if strings.HasPrefix(norm, "*.") {
			m.suffixDirect[strings.TrimPrefix(norm, "*.")] = struct{}{}
		} else {
			m.exactDirect[norm] = struct{}{}
			m.suffixDirect[norm] = struct{}{}
		}
	}

	// 6. Custom Static Records
	for d, ip := range cfg.Rules.CustomRecords {
		m.customRecords[strings.ToLower(strings.TrimSpace(d))] = strings.TrimSpace(ip)
	}
}

// Match evaluates a domain name and determines the routing action
func (m *Matcher) Match(domain string) RuleMatchResult {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))

	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. Check Custom Defined Records (highest priority)
	if ip, ok := m.customRecords[d]; ok {
		return RuleMatchResult{
			Action:    ActionCustom,
			CustomIP:  ip,
			MatchedBy: "Custom Record",
		}
	}

	// 2. Check Custom & Preset Blocked
	if reason, ok := m.exactBlocked[d]; ok {
		return RuleMatchResult{
			Action:    ActionBlock,
			MatchedBy: reason,
		}
	}
	for suffix, reason := range m.suffixBlocked {
		if strings.HasSuffix(d, "."+suffix) {
			return RuleMatchResult{
				Action:    ActionBlock,
				MatchedBy: reason + " (*." + suffix + ")",
			}
		}
	}

	// 3. Check Custom Direct Override
	if _, ok := m.exactDirect[d]; ok {
		return RuleMatchResult{
			Action:    ActionDirect,
			MatchedBy: "Custom Direct",
		}
	}
	for suffix := range m.suffixDirect {
		if strings.HasSuffix(d, "."+suffix) {
			return RuleMatchResult{
				Action:    ActionDirect,
				MatchedBy: "Custom Direct (*." + suffix + ")",
			}
		}
	}

	// 4. Check Proxied (Presets & Custom)
	if cat, ok := m.exactProxied[d]; ok {
		return RuleMatchResult{
			Action:    ActionProxy,
			MatchedBy: cat,
		}
	}
	for suffix, cat := range m.suffixProxied {
		if strings.HasSuffix(d, "."+suffix) {
			return RuleMatchResult{
				Action:    ActionProxy,
				MatchedBy: cat + " (*." + suffix + ")",
			}
		}
	}

	// 5. Default action: Direct upstream resolution
	return RuleMatchResult{
		Action:    ActionDirect,
		MatchedBy: "Default Upstream",
	}
}
