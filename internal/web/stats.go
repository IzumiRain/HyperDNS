package web

import (
	"runtime"
	"sync"
	"time"

	"hyperdns/internal/dns"
	"hyperdns/internal/sniproxy"
)

type SystemStats struct {
	TotalQueries     uint64  `json:"total_queries"`
	QPS              float64 `json:"qps"`
	CacheHitRatio    float64 `json:"cache_hit_ratio"`
	CachedQueries    uint64  `json:"cached_queries"`
	ActiveProxyConns uint64  `json:"active_proxy_conns"`
	TotalProxyConns  uint64  `json:"total_proxy_conns"`
	BytesIn          uint64  `json:"bytes_in"`
	BytesOut         uint64  `json:"bytes_out"`
	SpeedInKBps           float64            `json:"speed_in_kbps"`
	SpeedOutKBps          float64            `json:"speed_out_kbps"`
	TotalBytesTransferred uint64             `json:"total_bytes_transferred"`
	CPUUsagePercent       float64            `json:"cpu_usage_percent"`
	AllocMemoryMB         float64            `json:"alloc_memory_mb"`
	TotalAllocMB          float64            `json:"total_alloc_mb"`
	SysMemoryMB           float64            `json:"sys_memory_mb"`
	NumGoroutines         int                `json:"num_goroutines"`
	NumCPU                int                `json:"num_cpu"`
	CacheEntries          int                `json:"cache_entries"`
	UptimeSeconds         int64              `json:"uptime_seconds"`
	Upstreams             []dns.UpstreamStat `json:"upstreams"`
}

type StatsCollector struct {
	dnsHandler   *dns.Handler
	dnsCache     *dns.Cache
	sniProxy     *sniproxy.Server
	startTime    time.Time
	mu           sync.Mutex
	lastHits     uint64
	lastBytesIn  uint64
	lastBytesOut uint64
	lastTime     time.Time
	currentQPS   float64
	currentInKB  float64
	currentOutKB float64
	cpuPercent   float64
}

func NewStatsCollector(dnsHandler *dns.Handler, dnsCache *dns.Cache, sniProxy *sniproxy.Server) *StatsCollector {
	sc := &StatsCollector{
		dnsHandler: dnsHandler,
		dnsCache:   dnsCache,
		sniProxy:   sniProxy,
		startTime:  time.Now(),
		lastTime:   time.Now(),
	}

	go sc.telemetryLoop()
	return sc
}

func (sc *StatsCollector) telemetryLoop() {
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		sc.mu.Lock()
		_, totalHits, _ := sc.dnsHandler.GetCounters()
		proxyStats := sc.sniProxy.GetStats()
		now := time.Now()
		diffTime := now.Sub(sc.lastTime).Seconds()

		if diffTime > 0 {
			diffHits := totalHits - sc.lastHits
			sc.currentQPS = float64(diffHits) / diffTime

			diffIn := proxyStats.BytesIn - sc.lastBytesIn
			diffOut := proxyStats.BytesOut - sc.lastBytesOut

			sc.currentInKB = (float64(diffIn) / 1024.0) / diffTime
			sc.currentOutKB = (float64(diffOut) / 1024.0) / diffTime
		}

		// Estimate CPU load based on active Goroutines & QPS
		goroutines := runtime.NumGoroutine()
		loadEstimate := float64(goroutines-10)*0.15 + (sc.currentQPS * 0.35)
		if loadEstimate < 0.2 {
			loadEstimate = 0.2
		}
		if loadEstimate > 99.0 {
			loadEstimate = 99.0
		}
		sc.cpuPercent = loadEstimate

		sc.lastHits = totalHits
		sc.lastBytesIn = proxyStats.BytesIn
		sc.lastBytesOut = proxyStats.BytesOut
		sc.lastTime = now
		sc.mu.Unlock()
	}
}

func (sc *StatsCollector) GetSystemStats() SystemStats {
	sc.mu.Lock()
	qps := sc.currentQPS
	speedIn := sc.currentInKB
	speedOut := sc.currentOutKB
	cpuPct := sc.cpuPercent
	sc.mu.Unlock()

	_, totalHits, totalCache := sc.dnsHandler.GetCounters()
	proxyStats := sc.sniProxy.GetStats()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var hitRatio float64 = 0.0
	if totalHits > 0 {
		hitRatio = (float64(totalCache) / float64(totalHits)) * 100.0
	}

	return SystemStats{
		TotalQueries:     totalHits,
		QPS:              qps,
		CacheHitRatio:    hitRatio,
		CachedQueries:    totalCache,
		ActiveProxyConns: proxyStats.ActiveConns,
		TotalProxyConns:  proxyStats.TotalConns,
		BytesIn:          proxyStats.BytesIn,
		BytesOut:         proxyStats.BytesOut,
		SpeedInKBps:      speedIn,
		SpeedOutKBps:     speedOut,
		CPUUsagePercent:  cpuPct,
		AllocMemoryMB:    float64(m.Alloc) / 1024.0 / 1024.0,
		TotalAllocMB:     float64(m.TotalAlloc) / 1024.0 / 1024.0,
		SysMemoryMB:      float64(m.Sys) / 1024.0 / 1024.0,
		NumGoroutines:    runtime.NumGoroutine(),
		NumCPU:           runtime.NumCPU(),
		CacheEntries:     sc.dnsCache.Count(),
		UptimeSeconds:    int64(time.Since(sc.startTime).Seconds()),
	}
}
