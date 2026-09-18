package matcher

import (
	"fmt"
	"testing"
)

// Every DNS query that reaches the resolver pays a Match. A clean domain — the
// common case for a gaming client, since only auth/store/CDN names are proxied —
// is the worst case for the matcher: it can only return DIRECT after every rule
// has been ruled out. These benchmarks measure that path specifically, because it
// is the one that sits between the client's packet and the upstream race.

// clientPolicies is a realistic per-client policy list: a reseller's customer with
// a handful of game categories enabled.
var clientPolicies = []string{
	"enable_riot",
	"enable_steam",
	"enable_discord",
	"enable_call_of_duty",
	"enable_epic",
}

func BenchmarkMatchDirect(b *testing.B) {
	m := NewMatcher()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.Match("telemetry.internal.example.org")
	}
}

func BenchmarkMatchExactHit(b *testing.B) {
	m := NewMatcher()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.Match("riotgames.com")
	}
}

func BenchmarkMatchSuffixHit(b *testing.B) {
	m := NewMatcher()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.Match("auth.eu.riotgames.com")
	}
}

// A deep name costs one probe per label, so it bounds the label-walk cost.
func BenchmarkMatchDeepDirect(b *testing.B) {
	m := NewMatcher()
	name := "a.b.c.d.e.f.g.h.notarule.example.org"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.Match(name)
	}
}

func BenchmarkMatchForClientDirect(b *testing.B) {
	m := NewMatcher()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.MatchForClient("telemetry.internal.example.org", clientPolicies)
	}
}

func BenchmarkMatchForClientSuffixHit(b *testing.B) {
	m := NewMatcher()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.MatchForClient("auth.eu.riotgames.com", clientPolicies)
	}
}

// A rule the client has NOT enabled must be walked past, not returned — the
// path a mixed-policy deployment takes most often.
func BenchmarkMatchForClientNotAllowed(b *testing.B) {
	m := NewMatcher()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.MatchForClient("api.twitch.tv", clientPolicies)
	}
}

func BenchmarkMatchParallel(b *testing.B) {
	m := NewMatcher()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Match("telemetry.internal.example.org")
		}
	})
}

// With custom lists loaded the matcher carries three populated rule sets rather
// than one, so this is the shape an actual deployment runs.
func BenchmarkMatchWithCustomRules(b *testing.B) {
	m := NewMatcher()
	var blocked, direct, proxied []string
	for i := range 200 {
		blocked = append(blocked, fmt.Sprintf("ads%d.tracker.example", i))
		direct = append(direct, fmt.Sprintf("bank%d.example", i))
		proxied = append(proxied, fmt.Sprintf("*.cdn%d.example", i))
	}
	m.SetCustomRules(proxied, blocked, direct, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.Match("telemetry.internal.example.org")
	}
}

func BenchmarkGetCustomRecord(b *testing.B) {
	m := NewMatcher()
	m.SetCustomRules(nil, nil, nil, map[string]string{"pin.example": "10.0.0.1"})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.GetCustomRecord("pin.example")
	}
}
