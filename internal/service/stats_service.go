package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"hyperdns/internal/database"
	"hyperdns/internal/sysmetrics"
)

type StatsService struct {
	db            *database.DB
	startedAt     time.Time
	totalQueries  atomic.Uint64
	logCounter    atomic.Uint64
	telemetryMu   sync.Mutex // guards qps window, speeds & cached runtime metrics
	qpsWindow     [10]uint64
	qpsIndex      int
	qpsRate       float64
	cachedRAMMB   float64
	cachedSysMB   float64
	cachedCPUPct  float64
	numGoroutines int
	numCPU        int
	speedInKBps   float64
	speedOutKBps  float64
	lastBytesSent uint64
	lastBytesRecv uint64
	recentLogs    []database.QueryLogItem
	logMu         sync.RWMutex
	sseClients    map[chan string]struct{}
	sseMu         sync.RWMutex
	getProxyStats func() (int64, uint64, uint64, uint64)
	getCacheStats func() (int, uint64, uint64)

	// getGuardStats reports (queries dropped by the rate limiter, limit in qps).
	// It is a setter rather than a constructor argument because the DNS handler is
	// built *after* this service — the handler takes it as its telemetry sink — so
	// there is nothing to close over at construction time. Read under guardMu
	// because the DNS listeners are started later still, and a dashboard poll can
	// land in between.
	//
	// getPrefetchStats reports the cache's background-refresh counters and shares
	// the same lock for the same reason: it is wired during startup while the HTTP
	// server may already be answering.
	//
	// getProxyGuardStats reports the SNI proxy's two non-relay outcomes (refused,
	// unreadable). It is a setter rather than a second constructor argument only to
	// keep NewStatsService's signature stable; the proxy does exist by then.
	guardMu            sync.RWMutex
	getGuardStats      func() (uint64, int)
	getPrefetchStats   func() (uint64, uint64, uint64, uint64)
	getProxyGuardStats func() (uint64, uint64)

	// Latency distributions, fed from PushQueryLog because every terminal path in
	// the DNS handler logs exactly once. latencyAll is what a client experiences;
	// latencyResolve covers only the queries the cache did not answer.
	latencyAll     latencyHistogram
	latencyResolve latencyHistogram

	// stop ends telemetryLoop, which used to be a bare `for range ticker.C` with no
	// way out. That is harmless for the daemon's single long-lived service, but this
	// loop ticks once a *second*, so every service that outlives its owner keeps
	// charging the whole process for telemetry nobody reads. The web package's test
	// helper builds one per test: fifty-four abandoned loops is fifty-four wasted
	// ticks a second, which is how a package that passes in seconds hits a six-minute
	// timeout under -race. closeOnce keeps a second Close from panicking on an
	// already-closed channel, so callers may pair it with defer.
	stop      chan struct{}
	closeOnce sync.Once
}

// maxSSEClients bounds concurrent live-log subscribers. Each one holds a
// buffered channel and a goroutine, so an unbounded map is a cheap way to
// exhaust the daemon by opening connections and never reading them.
const maxSSEClients = 64

func NewStatsService(
	db *database.DB,
	proxyStats func() (int64, uint64, uint64, uint64),
	cacheStats func() (int, uint64, uint64),
) *StatsService {
	s := &StatsService{
		db:            db,
		startedAt:     time.Now(),
		recentLogs:    make([]database.QueryLogItem, 0, 100),
		sseClients:    make(map[chan string]struct{}),
		getProxyStats: proxyStats,
		getCacheStats: cacheStats,
		numCPU:        runtime.NumCPU(),
		stop:          make(chan struct{}),
	}

	go s.telemetryLoop()
	return s
}

func (s *StatsService) RecordQuery() {
	s.totalQueries.Add(1)
}

// SetGuardStatsSource wires in the DNS handler's rate-limiter counters. Called
// once during startup, after the handler exists and before any listener accepts.
func (s *StatsService) SetGuardStatsSource(fn func() (uint64, int)) {
	s.guardMu.Lock()
	s.getGuardStats = fn
	s.guardMu.Unlock()
}

// SetPrefetchStatsSource wires in the cache's serve-stale and background-refresh
// counters. Call it once during startup.
func (s *StatsService) SetPrefetchStatsSource(fn func() (uint64, uint64, uint64, uint64)) {
	s.guardMu.Lock()
	s.getPrefetchStats = fn
	s.guardMu.Unlock()
}

// SetProxyGuardStatsSource wires in the SNI proxy's refused and unreadable
// counters. Call it once during startup.
func (s *StatsService) SetProxyGuardStatsSource(fn func() (uint64, uint64)) {
	s.guardMu.Lock()
	s.getProxyGuardStats = fn
	s.guardMu.Unlock()
}

func (s *StatsService) PushQueryLog(item database.QueryLogItem) {
	item.ID = s.logCounter.Add(1)
	// Respect a timestamp the caller already set: the DNS handler passes the
	// moment the query arrived, which is what the latency figure is measured from.
	if item.Timestamp.IsZero() {
		item.Timestamp = time.Now()
	}

	// Fold the reading into the histograms before anything can fail or be dropped:
	// the SSE fan-out below is deliberately lossy, and the ring buffer only keeps a
	// hundred entries, so neither is a place percentiles can be computed from.
	s.latencyAll.observe(item.LatencyMs)
	if !item.Cached {
		s.latencyResolve.observe(item.LatencyMs)
	}

	s.logMu.Lock()
	if len(s.recentLogs) >= 100 {
		s.recentLogs = s.recentLogs[1:]
	}
	s.recentLogs = append(s.recentLogs, item)
	s.logMu.Unlock()

	// Broadcast to SSE clients non-blocking. The event frame is marshalled
	// ONCE here (v2.2.0 perf): the per-subscriber loop used to hand the struct
	// to each connection's goroutine, which each marshalled it again — N
	// dashboards meant N JSON encodes of the same query on the resolver's
	// single core. The channel now carries the finished frame and the writer
	// side prints it verbatim.
	frame := ""
	if data, err := json.Marshal(item); err == nil {
		frame = "event: query\ndata: " + string(data) + "\n\n"
	}
	if frame == "" {
		return
	}
	s.sseMu.RLock()
	for ch := range s.sseClients {
		select {
		case ch <- frame:
		default:
		}
	}
	s.sseMu.RUnlock()
}

func (s *StatsService) GetRecentLogs() []database.QueryLogItem {
	s.logMu.RLock()
	defer s.logMu.RUnlock()
	res := make([]database.QueryLogItem, len(s.recentLogs))
	copy(res, s.recentLogs)
	return res
}

// cpuWindowTicks is how many one-second samples the CPU percentage is measured over.
//
// This is the one number in the loop worth explaining. CPU% is a ratio of CPU time to
// wall time, so it needs a window, and the window and the refresh interval do not have
// to be the same length. Differencing against the immediately preceding tick would give
// a one-second window — and on Linux the source is /proc/self/stat, which counts in
// USER_HZ ticks of 10 ms, so a one-second window can only ever resolve CPU% to the
// nearest 1%. A near-idle resolver would read 0% and occasionally 1%, which is not
// information.
//
// Differencing against the sample from five ticks ago instead keeps the 0.2% resolution
// the old five-second cadence had, while still producing a fresh figure every second:
// the window slides rather than resetting. The cost is that a one-second spike is
// averaged across five, which is the same trade top(1) and htop make and the right one
// for a panel someone leaves open.
const cpuWindowTicks = 5

// The two runtime/metrics counters that correspond exactly to the runtime.MemStats
// fields this dashboard reports — Go's own documentation pairs Alloc with the first and
// Sys with the second. They are read instead of calling runtime.ReadMemStats, which
// stops the world; see sampleMemory.
const (
	metricHeapObjectBytes = "/memory/classes/heap/objects:bytes"
	metricTotalBytes      = "/memory/classes/total:bytes"
)

// cpuSample is one reading of the process's cumulative CPU time, with the wall clock
// it was taken at. Both halves are needed: the ratio is meaningless without the
// interval, and the interval cannot be assumed to be exactly one second — a ticker
// under load, or a laptop resuming from sleep, will hand back something else.
type cpuSample struct {
	seconds float64
	at      time.Time
}

// newMemorySamples prepares the runtime/metrics request for the two figures the panel
// shows, and reports whether this Go runtime actually implements them.
//
// The check matters because runtime/metrics names are explicitly *not* covered by the
// Go compatibility promise — a future release may rename or retire one. If that
// happens the sample comes back as KindBad, and silently reporting a KindBad sample
// would put a confident 0.0 MB on the dashboard of a process using 40 MB. Detecting it
// once here lets the caller fall back to runtime.ReadMemStats instead, at the old
// five-second cadence, which is a slower panel rather than a lying one.
func newMemorySamples() ([]metrics.Sample, bool) {
	samples := []metrics.Sample{
		{Name: metricHeapObjectBytes},
		{Name: metricTotalBytes},
	}
	metrics.Read(samples)
	for i := range samples {
		if samples[i].Value.Kind() != metrics.KindUint64 {
			return nil, false
		}
	}
	return samples, true
}

// sampleMemory reads heap and total memory. samples is reused across ticks, so the
// fast path allocates nothing.
//
// runtime.ReadMemStats — what this used to call — stops the world for the duration of
// the read. That is why the old loop only called it every fifth tick, and why the panel
// could not show memory more often than every five seconds: the pause is charged to
// every DNS query in flight, and on a resolver whose whole purpose is latency, paying
// it once a second to animate a number would be the wrong trade. runtime/metrics is the
// supported way to read the same counters without that pause, so the frequency
// question stops being a trade at all.
//
// The third return reports whether new values were obtained; a false leaves the
// previously cached figures in place rather than zeroing the tiles.
func sampleMemory(samples []metrics.Sample, ok bool, tick int) (heap, total uint64, got bool) {
	if ok {
		metrics.Read(samples)
		return samples[0].Value.Uint64(), samples[1].Value.Uint64(), true
	}
	// Degraded path: runtime/metrics did not offer these names, so accept the pause
	// and keep the cadence it was chosen for.
	if tick%5 != 0 {
		return 0, 0, false
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc, m.Sys, true
}

// sampleCPU appends the current CPU reading to ring and returns the percentage over
// the span the ring covers. ring is trimmed to cpuWindowTicks+1 entries, so it holds
// the oldest sample the window needs and nothing more.
//
// It reports false until there are two samples to difference, and on any reading that
// would be nonsense — a non-monotonic CPU counter, a zero or negative wall interval —
// so that a bad sample leaves the last good figure on screen instead of replacing it
// with a spike or a zero.
func sampleCPU(ring *[]cpuSample, numCPU int) (float64, bool) {
	cs, err := processCPUSeconds()
	if err != nil {
		return 0, false
	}
	now := time.Now()

	*ring = append(*ring, cpuSample{seconds: cs, at: now})
	if len(*ring) > cpuWindowTicks+1 {
		*ring = (*ring)[len(*ring)-(cpuWindowTicks+1):]
	}
	if len(*ring) < 2 {
		return 0, false
	}

	oldest := (*ring)[0]
	dCPU := cs - oldest.seconds
	dWall := now.Sub(oldest.at).Seconds()
	if dCPU < 0 || dWall <= 0 {
		return 0, false
	}

	pct := (dCPU / dWall) * 100.0
	// A process can legitimately exceed 100% across several cores, but not more than
	// one core's worth per core. Anything above that is a measurement artefact —
	// clock skew, a suspended host — and is clamped rather than displayed.
	if limit := 100 * numCPUFactor(numCPU); pct > limit {
		pct = limit
	}
	return pct, true
}

// telemetryLoop samples the process's own vital signs once a second, for the tiles on
// the dashboard's home tab: query rate, throughput, memory, CPU, goroutines.
//
// Everything is read *outside* telemetryMu and written inside it, in one critical
// section per tick. The reads include a file read or a syscall (processCPUSeconds), and
// holding the lock across those would make a dashboard poll wait on /proc.
func (s *StatsService) telemetryLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastTotal uint64
	var counter int

	memSamples, memOK := newMemorySamples()

	cpuRing := make([]cpuSample, 0, cpuWindowTicks+1)
	if cs, err := processCPUSeconds(); err == nil {
		cpuRing = append(cpuRing, cpuSample{seconds: cs, at: time.Now()})
	}

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}

		current := s.totalQueries.Load()
		delta := current - lastTotal
		lastTotal = current

		var bytesSent, bytesRecv uint64
		if s.getProxyStats != nil {
			_, _, bytesSent, bytesRecv = s.getProxyStats()
		}

		// runtime.NumCPU is fixed for the life of the process, but it is read here
		// rather than once before the loop because sampleCPU needs it to clamp, and a
		// zero would clamp the first reading of a multi-core process to 100%.
		numCPU := runtime.NumCPU()
		heapBytes, sysBytes, haveMem := sampleMemory(memSamples, memOK, counter)
		cpuPct, haveCPU := sampleCPU(&cpuRing, numCPU)
		goroutines := runtime.NumGoroutine()

		s.telemetryMu.Lock()

		s.qpsWindow[s.qpsIndex] = delta
		s.qpsIndex = (s.qpsIndex + 1) % 10

		var sum uint64
		for _, v := range s.qpsWindow {
			sum += v
		}
		s.qpsRate = float64(sum) / 10.0

		// Network throughput (KB/s) from SNI proxy byte counters. Skipped on the very
		// first tick, where there is no earlier reading to difference against and the
		// counters' absolute values would be reported as one second of traffic.
		if s.lastBytesSent > 0 || s.lastBytesRecv > 0 || counter > 0 {
			dOut := bytesSent - s.lastBytesSent
			dIn := bytesRecv - s.lastBytesRecv
			s.speedInKBps = float64(dIn) / 1024.0
			s.speedOutKBps = float64(dOut) / 1024.0
		}
		s.lastBytesSent = bytesSent
		s.lastBytesRecv = bytesRecv

		if haveMem {
			s.cachedRAMMB = float64(heapBytes) / 1024.0 / 1024.0
			s.cachedSysMB = float64(sysBytes) / 1024.0 / 1024.0
		}
		if haveCPU {
			s.cachedCPUPct = cpuPct
		}
		s.numGoroutines = goroutines
		s.numCPU = numCPU

		s.telemetryMu.Unlock()

		counter++
	}
}

// Close stops the telemetry loop. Every counter the service already holds stays
// readable afterwards and PushQueryLog keeps working — GetLiveStats simply reports
// the last sampled QPS, memory and CPU figures instead of fresh ones, which is the
// right trade for a service whose owner is shutting down. Safe to call more than
// once and safe to call concurrently with GetLiveStats.
//
// Live SSE subscribers are deliberately left alone: each one is owned by its own
// request and exits when that request's context is cancelled, so tearing their
// channels down from here would race with the handler writing to them.
func (s *StatsService) Close() {
	s.closeOnce.Do(func() { close(s.stop) })
}

// numCPUFactor caps process CPU%% against the core count (100%% per core).
func numCPUFactor(n int) float64 {
	if n <= 0 {
		return 1
	}
	return float64(n)
}

type LiveStatsResponse struct {
	TotalQueries uint64  `json:"total_queries"`
	QPS          float64 `json:"qps"`
	ActiveRelays int64   `json:"active_relays"`
	TotalRelays  uint64  `json:"total_relays"`
	BytesSent    uint64  `json:"bytes_sent"`
	BytesRecv    uint64  `json:"bytes_recv"`
	CacheItems   int     `json:"cache_items"`
	CacheHits    uint64  `json:"cache_hits"`
	CacheMisses  uint64  `json:"cache_misses"`
	CacheHitRate float64 `json:"cache_hit_rate"`
	CPUUsage     float64 `json:"cpu_usage"`
	RAMUsageMB   float64 `json:"ram_usage_mb"`
	// Extended telemetry consumed by the dashboard
	AllocMemoryMB   float64 `json:"alloc_memory_mb"`
	SysMemoryMB     float64 `json:"sys_memory_mb"`
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	NumCPU          int     `json:"num_cpu"`
	NumGoroutines   int     `json:"num_goroutines"`
	SpeedInKBps     float64 `json:"speed_in_kbps"`
	SpeedOutKBps    float64 `json:"speed_out_kbps"`
	UptimeSec       int64   `json:"uptime_sec"`

	// RateLimited is how many queries the per-source limiter has dropped or
	// refused since start; RateLimitQPS is the limit in force, 0 when disabled.
	// The limiter answers a UDP flood with silence by design, so without these two
	// the only evidence an operator has that it is working at all is a QPS graph
	// that stops rising — indistinguishable from traffic simply going away.
	RateLimited  uint64 `json:"rate_limited"`
	RateLimitQPS int    `json:"rate_limit_qps"`

	// Machine-wide figures (internal/sysmetrics): the whole server's CPU and
	// RAM, as opposed to the process-only numbers above — the operator reads
	// these as "how loaded is my box". Negative values mean the platform
	// cannot answer (a Windows dev build); the UI renders a dash.
	SystemCPUPercent float64 `json:"system_cpu_percent"`
	SystemMemUsedMB  float64 `json:"system_mem_used_mb"`
	SystemMemTotalMB float64 `json:"system_mem_total_mb"`
	SystemMemPercent float64 `json:"system_mem_percent"`

	// The cache's serve-stale and prefetch counters. StaleServed rising on its own
	// is healthy — it is the feature working. StaleServed rising *together with*
	// RefreshFailed is the one failure serve-stale hides from clients on purpose:
	// they keep getting instant answers from a cache nothing is refilling, so
	// without these two numbers the first symptom an operator sees is names going
	// dark thirty seconds after an upstream dies. RefreshDropped rising means the
	// background worker pool is saturated and renewals are being skipped.
	StaleServed    uint64 `json:"stale_served"`
	RefreshStarted uint64 `json:"refresh_started"`
	RefreshFailed  uint64 `json:"refresh_failed"`
	RefreshDropped uint64 `json:"refresh_dropped"`

	// The SNI proxy's two non-relay outcomes. RelaysRefused counts connections
	// dropped for a blocked target, a self-dial or a full relay table.
	// RelaysUnreadable counts connections whose opening bytes named no
	// destination — nothing to dial, so nothing to count as a relay.
	//
	// Unreadable rising steadily is the one number here that points at a
	// configuration fault rather than at the internet: a name is answered with
	// this server's address, the client connects, and the protocol it speaks is
	// not TLS-with-SNI or HTTP-with-Host, so the proxy cannot learn where it
	// wanted to go. The client sees a connection that opens and dies; the
	// operator, until now, saw nothing at all.
	RelaysRefused    uint64 `json:"relays_refused"`
	RelaysUnreadable uint64 `json:"relays_unreadable"`

	// Latency is the service-time distribution of every query; LatencyUncached is
	// the same restricted to the ones the cache did not answer, which is where an
	// upstream round trip shows up. Reporting only the first would hide a slow
	// upstream behind a good hit rate — at an 85% hit rate the median query is a
	// cache hit, so p50 measures the cache and nothing else.
	Latency         LatencySnapshot `json:"latency"`
	LatencyUncached LatencySnapshot `json:"latency_uncached"`
}

func (s *StatsService) GetLiveStats() LiveStatsResponse {
	sysmemCPU := sysmetrics.CPUPercent()
	sysmemUsed, sysmemTotal, sysmemPct := sysmetrics.Memory()
	var activeRelays int64
	var totalRelays, bytesSent, bytesRecv uint64
	if s.getProxyStats != nil {
		activeRelays, totalRelays, bytesSent, bytesRecv = s.getProxyStats()
	}

	var cacheItems int
	var cacheHits, cacheMisses uint64
	if s.getCacheStats != nil {
		cacheItems, cacheHits, cacheMisses = s.getCacheStats()
	}

	var hitRate float64
	if total := cacheHits + cacheMisses; total > 0 {
		hitRate = (float64(cacheHits) / float64(total)) * 100.0
	}

	s.guardMu.RLock()
	guard := s.getGuardStats
	prefetch := s.getPrefetchStats
	proxyGuard := s.getProxyGuardStats
	s.guardMu.RUnlock()
	var rateLimited uint64
	var rateLimitQPS int
	if guard != nil {
		rateLimited, rateLimitQPS = guard()
	}
	var staleServed, refreshStarted, refreshFailed, refreshDropped uint64
	if prefetch != nil {
		staleServed, refreshStarted, refreshFailed, refreshDropped = prefetch()
	}
	var relaysRefused, relaysUnreadable uint64
	if proxyGuard != nil {
		relaysRefused, relaysUnreadable = proxyGuard()
	}

	// qpsRate is written by telemetryLoop under telemetryMu, so it has to be
	// read here under the same lock — it was previously read outside, which is a
	// genuine data race on a float64 (and reported as such by -race).
	s.telemetryMu.Lock()
	qps := s.qpsRate
	ramMB := s.cachedRAMMB
	sysMB := s.cachedSysMB
	cpuPct := s.cachedCPUPct
	numCPU := s.numCPU
	numGoroutines := s.numGoroutines
	speedIn := s.speedInKBps
	speedOut := s.speedOutKBps
	s.telemetryMu.Unlock()

	return LiveStatsResponse{
		TotalQueries:    s.totalQueries.Load(),
		QPS:             qps,
		ActiveRelays:    activeRelays,
		TotalRelays:     totalRelays,
		BytesSent:       bytesSent,
		BytesRecv:       bytesRecv,
		CacheItems:      cacheItems,
		CacheHits:       cacheHits,
		CacheMisses:     cacheMisses,
		CacheHitRate:    hitRate,
		CPUUsage:        cpuPct,
		RAMUsageMB:      ramMB,
		AllocMemoryMB:   ramMB,
		SysMemoryMB:     sysMB,
		CPUUsagePercent: cpuPct,
		NumCPU:          numCPU,
		NumGoroutines:   numGoroutines,
		SpeedInKBps:     speedIn,
		SpeedOutKBps:    speedOut,
		// UptimeSec is declared in the response and rendered by the dashboard, but
		// was never assigned, so the "Uptime" tile always showed 0.
		UptimeSec:    int64(time.Since(s.startedAt).Seconds()),
		RateLimited:  rateLimited,
		RateLimitQPS: rateLimitQPS,

		StaleServed:    staleServed,
		RefreshStarted: refreshStarted,
		RefreshFailed:  refreshFailed,
		RefreshDropped: refreshDropped,

		RelaysRefused:    relaysRefused,
		RelaysUnreadable: relaysUnreadable,

		Latency:         s.latencyAll.snapshot(),
		LatencyUncached: s.latencyResolve.snapshot(),

		// Machine-wide load (internal/sysmetrics): the whole server's CPU and
		// RAM, as opposed to the process-only figures above.
		SystemCPUPercent: sysmemCPU,
		SystemMemUsedMB:  sysmemUsed,
		SystemMemTotalMB: sysmemTotal,
		SystemMemPercent: sysmemPct,
	}
}

// ServeSSE handles real-time Server-Sent Events stream for live query log
func (s *StatsService) ServeSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusBadRequest)
		return
	}

	// Reserve a slot before writing any headers, so a rejected subscriber gets a
	// plain 503 rather than a half-open event stream. The channel carries
	// pre-rendered SSE frames (see PushQueryLog): one marshal per query, not
	// one per subscriber.
	ch := make(chan string, 32)
	s.sseMu.Lock()
	if len(s.sseClients) >= maxSSEClients {
		s.sseMu.Unlock()
		w.Header().Set("Retry-After", "5")
		http.Error(w, "too many live-log subscribers", http.StatusServiceUnavailable)
		return
	}
	s.sseClients[ch] = struct{}{}
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, ch)
		s.sseMu.Unlock()
		close(ch)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// No Access-Control-Allow-Origin: this stream sits behind session auth and
	// leaks every client's query history, so it must stay same-origin.
	w.Header().Set("X-Accel-Buffering", "no")

	// A stalled reader must not pin the connection's slot and goroutine
	// forever. The server runs with WriteTimeout 0 (a global deadline would
	// sever a stream the dashboard holds open for its whole session), so each
	// write carries its own deadline instead: a client that stops reading
	// fails the current write within sseWriteTimeout, the error returns, and
	// the deferred cleanup below frees the subscriber slot. Without this, an
	// authenticated client could pin every slot until restart (Mantis C-1).
	// The deadline is reset before every write, so the quiet gaps between
	// keep-alives never trip it — it only fires while a write is actually
	// blocked.
	const sseWriteTimeout = 15 * time.Second
	rc := http.NewResponseController(w)
	writeFrame := func(frame string) bool {
		// Best-effort: a ResponseWriter that cannot take a deadline (test
		// recorders, custom wrappers) still writes, and the deadline is the
		// production listener's protection.
		if err := rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := fmt.Fprint(w, frame); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// Send initial snapshot as a named 'history' event (frontend listener)
	snapshot := s.GetRecentLogs()
	if data, err := json.Marshal(snapshot); err == nil {
		if !writeFrame("event: history\ndata: " + string(data) + "\n\n") {
			return
		}
	}

	// Comment frames keep idle streams alive: proxies and load balancers drop a
	// connection that sends nothing, and a quiet resolver can be idle for minutes.
	keepAlive := time.NewTicker(25 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAlive.C:
			if !writeFrame(": keep-alive\n\n") {
				return
			}
		case frame := <-ch:
			if !writeFrame(frame) {
				return
			}
		}
	}
}
