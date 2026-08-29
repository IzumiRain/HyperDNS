package rules

import (
	"testing"

	"hyperdns/internal/config"
)

func TestMatcher(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Rules.EnableDiscord = true
	cfg.Rules.EnableEpic = true
	cfg.Rules.EnableRiot = true
	cfg.Rules.CustomBlocked = []string{"ads.example.com", "*.tracker.org"}
	cfg.Rules.CustomRecords = map[string]string{
		"myhome.lan": "192.168.1.100",
	}

	m := NewMatcher(cfg)

	tests := []struct {
		domain       string
		expectAction Action
	}{
		{"discord.com", ActionProxy},
		{"gateway.discord.gg", ActionProxy},
		{"cdn.discordapp.com", ActionProxy},
		{"epicgames.com", ActionProxy},
		{"api.epicgames.dev", ActionProxy},
		{"playvalorant.com", ActionProxy},
		{"wr.pvp.net", ActionProxy},
		{"ads.example.com", ActionBlock},
		{"user.tracker.org", ActionBlock},
		{"myhome.lan", ActionCustom},
		{"google.com", ActionDirect},
		{"wikipedia.org", ActionDirect},
	}

	for _, tt := range tests {
		res := m.Match(tt.domain)
		if res.Action != tt.expectAction {
			t.Errorf("Match(%q) = %v (rule: %s), want %v", tt.domain, res.Action, res.MatchedBy, tt.expectAction)
		}
	}
}
