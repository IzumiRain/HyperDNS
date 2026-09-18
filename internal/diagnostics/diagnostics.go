package diagnostics

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

type TargetTest struct {
	Category    string `json:"category"`
	Name        string `json:"name"`
	Target      string `json:"target"`
	Port        int    `json:"port"`
	TestType    string `json:"test_type"` // "tcp", "tls", "http"
	HTTPURL     string `json:"http_url,omitempty"`
}

type TestResult struct {
	Name        string        `json:"name"`
	Category    string        `json:"category"`
	Target      string        `json:"target"`
	Status      string        `json:"status"` // "EXCELLENT", "GOOD", "BLOCKED", "TIMEOUT"
	Latency     time.Duration `json:"latency"`
	LatencyMs   float64       `json:"latency_ms"`
	HTTPStatus  int           `json:"http_status,omitempty"`
	Message     string        `json:"message"`
	Success     bool          `json:"success"`
}

type DiagnosticReport struct {
	Timestamp      time.Time    `json:"timestamp"`
	OverallScore   int          `json:"overall_score"` // 0 to 100
	OverallQuality string       `json:"overall_quality"`
	PassedCount    int          `json:"passed_count"`
	TotalCount     int          `json:"total_count"`
	Results        []TestResult `json:"results"`
}

var defaultTargets = []TargetTest{
	{Category: "Gaming", Name: "Riot Games (Valorant / LoL)", Target: "auth.riotgames.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Epic Games (Fortnite / EAC)", Target: "epicgames.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Steam & Valve (CS2 / Dota 2)", Target: "steampowered.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "PUBG Mobile & PC (Krafton)", Target: "pubgmobile.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Call of Duty Mobile (Activision)", Target: "callofduty.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Supercell (Brawl Stars / Clash)", Target: "supercell.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Electronic Arts (Apex / EA App)", Target: "ea.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Blizzard (Battle.net)", Target: "battle.net", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Ubisoft Connect (Rainbow Six)", Target: "ubisoft.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Rockstar Games (GTA Online)", Target: "rockstargames.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "Xbox Live & Microsoft", Target: "xbox.com", Port: 443, TestType: "tls"},
	{Category: "Gaming", Name: "PlayStation Network (PSN)", Target: "playstation.com", Port: 443, TestType: "tls"},
	{Category: "Streaming", Name: "Discord (Updates & Voice)", Target: "gateway.discord.gg", Port: 443, TestType: "tls"},
	{Category: "Streaming", Name: "Twitch Live Streams", Target: "twitch.tv", Port: 443, TestType: "tls"},
	{Category: "Streaming", Name: "Kick.com Streaming", Target: "kick.com", Port: 443, TestType: "tls"},
	{Category: "Streaming", Name: "Spotify Music", Target: "spotify.com", Port: 443, TestType: "tls"},
	{Category: "Developer", Name: "Docker Hub Registry (403)", Target: "registry-1.docker.io", Port: 443, TestType: "tls"},
	{Category: "Developer", Name: "OpenAI / ChatGPT API", Target: "api.openai.com", Port: 443, TestType: "tls"},
}

func RunDiagnostics() DiagnosticReport {
	results := make([]TestResult, len(defaultTargets))
	var wg sync.WaitGroup

	passed := 0

	for i, t := range defaultTargets {
		wg.Add(1)
		go func(idx int, target TargetTest) {
			defer wg.Done()
			res := runSingleTest(target)
			results[idx] = res
		}(i, t)
	}

	wg.Wait()

	total := len(results)
	totalScore := 0

	for _, r := range results {
		if r.Success {
			passed++
			if r.LatencyMs < 40 {
				totalScore += 100
			} else if r.LatencyMs < 80 {
				totalScore += 90
			} else {
				totalScore += 75
			}
		}
	}

	avgScore := 0
	if total > 0 {
		avgScore = totalScore / total
	}

	quality := "POOR"
	if avgScore >= 90 {
		quality = "PERFECT FOR GAMING & ANTI-SANCTION"
	} else if avgScore >= 75 {
		quality = "EXCELLENT"
	} else if avgScore >= 50 {
		quality = "MODERATE"
	}

	return DiagnosticReport{
		Timestamp:      time.Now(),
		OverallScore:   avgScore,
		OverallQuality: quality,
		PassedCount:    passed,
		TotalCount:     total,
		Results:        results,
	}
}

func runSingleTest(t TargetTest) TestResult {
	addr := fmt.Sprintf("%s:%d", t.Target, t.Port)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         t.Target,
		InsecureSkipVerify: true,
	})
	dur := time.Since(start)

	if err != nil {
		return TestResult{
			Name:       t.Name,
			Category:   t.Category,
			Target:     t.Target,
			Status:     "TIMEOUT / BLOCKED",
			Latency:    dur,
			LatencyMs:  float64(dur.Microseconds()) / 1000.0,
			Message:    err.Error(),
			Success:    false,
		}
	}
	defer conn.Close()

	status := "EXCELLENT"
	latMs := float64(dur.Microseconds()) / 1000.0
	if latMs > 70 {
		status = "GOOD"
	}

	return TestResult{
		Name:      t.Name,
		Category:  t.Category,
		Target:    t.Target,
		Status:    status,
		Latency:   dur,
		LatencyMs: latMs,
		Message:   "Reachability Verified (TLS Handshake Clean)",
		Success:   true,
	}
}
