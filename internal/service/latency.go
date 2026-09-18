package service

// Query-latency percentiles.
//
// The mean is the least useful number a resolver can report about itself: a cache
// answering nine queries in ten in forty microseconds pulls the average well
// under a millisecond no matter how badly the tenth behaves, and the tenth is the
// one a game launcher stalls on. Percentiles are what make that tail visible.
//
// This is a fixed-bucket histogram rather than a reservoir of samples, because
// recording a query has to cost one atomic add with no allocation and no lock —
// the whole point of measuring latency is to not become the reason it went up.
// The price is that a reported percentile is only as precise as the bucket it
// lands in, so the edges are dense where the interesting things happen: below a
// millisecond, where a cache hit lives, and through the tens of milliseconds,
// where an upstream round trip does.

import (
	"math"
	"sync/atomic"
)

// latencyBounds are the inclusive upper edges of each bucket, in milliseconds.
// Anything above the last edge lands in one final overflow bucket.
var latencyBounds = [...]float64{
	0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 35, 50, 75, 100, 150, 250, 500, 1000, 2000,
}

// latencyHistogram counts query latencies. It is safe for concurrent use.
type latencyHistogram struct {
	buckets   [len(latencyBounds) + 1]atomic.Uint64
	count     atomic.Uint64
	sumMicros atomic.Uint64
	maxMicros atomic.Uint64
}

// observe records one query's total service time in milliseconds. A negative or
// non-finite reading is dropped rather than folded in: it can only come from a
// clock that went backwards, and it would corrupt every percentile after it.
func (h *latencyHistogram) observe(ms float64) {
	if ms < 0 || math.IsNaN(ms) || math.IsInf(ms, 0) {
		return
	}
	idx := len(latencyBounds)
	for i, edge := range latencyBounds {
		if ms <= edge {
			idx = i
			break
		}
	}
	micros := uint64(ms * 1000)

	h.buckets[idx].Add(1)
	h.count.Add(1)
	h.sumMicros.Add(micros)

	// The exact worst case is worth keeping: it is the number a user reports as
	// "it froze", and no bucketed percentile can reproduce it.
	for {
		cur := h.maxMicros.Load()
		if micros <= cur || h.maxMicros.CompareAndSwap(cur, micros) {
			break
		}
	}
}

// LatencySnapshot is a read-only view of a latency distribution. Every figure is
// in milliseconds, and all of them are cumulative since the daemon started.
type LatencySnapshot struct {
	Count uint64  `json:"count"`
	AvgMs float64 `json:"avg_ms"`
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
	MaxMs float64 `json:"max_ms"`
}

// snapshot reads the counters out. The buckets are read one at a time rather than
// under a lock, so a snapshot taken while queries are arriving can be a handful
// of observations behind — which is the right trade for a number that exists to
// be polled by a dashboard every second.
func (h *latencyHistogram) snapshot() LatencySnapshot {
	counts := make([]uint64, len(h.buckets))
	var total uint64
	for i := range h.buckets {
		counts[i] = h.buckets[i].Load()
		total += counts[i]
	}
	out := LatencySnapshot{
		Count: total,
		MaxMs: float64(h.maxMicros.Load()) / 1000.0,
	}
	if total == 0 {
		return out
	}
	out.AvgMs = float64(h.sumMicros.Load()) / 1000.0 / float64(total)
	out.P50Ms = percentileFrom(counts, total, 0.50)
	out.P95Ms = percentileFrom(counts, total, 0.95)
	out.P99Ms = percentileFrom(counts, total, 0.99)
	return out
}

// percentileFrom reads a quantile out of bucket counts, interpolating inside the
// bucket the quantile falls in on the assumption that its observations are spread
// evenly across it. That assumption is why the edges are placed where they are.
//
// The overflow bucket has no upper edge, so a quantile that lands in it is
// reported as the last edge — "at least this" rather than a number invented from
// nothing.
func percentileFrom(counts []uint64, total uint64, q float64) float64 {
	last := latencyBounds[len(latencyBounds)-1]
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	cumulative := 0.0
	for i, c := range counts {
		below := cumulative
		cumulative += float64(c)
		if cumulative < target {
			continue
		}
		if i >= len(latencyBounds) {
			return last
		}
		upper := latencyBounds[i]
		if c == 0 {
			return upper
		}
		lower := 0.0
		if i > 0 {
			lower = latencyBounds[i-1]
		}
		frac := (target - below) / float64(c)
		return lower + (upper-lower)*min(max(frac, 0), 1)
	}
	return last
}
