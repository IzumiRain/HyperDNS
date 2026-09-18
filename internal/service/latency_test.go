package service

import (
	"math"
	"sync"
	"testing"

	"hyperdns/internal/database"
)

// What these tests defend: an operator uses these numbers to decide whether the
// resolver or the network is at fault, so a percentile that is quietly wrong is
// worse than no percentile at all. Bucketing makes exact equality the wrong
// assertion for most readings — every check below either names the bucket a value
// must land in, or pins a figure the implementation promises exactly (the count,
// the max, and the interpolation inside a known bucket).

// closeEnough compares two millisecond figures. The histogram stores microseconds
// as integers, so anything it reports back is exact to a thousandth of a
// millisecond; this tolerance is for the float arithmetic in the expectations.
func closeEnough(got, want float64) bool {
	return math.Abs(got-want) <= 1e-6
}

// A histogram nobody has written to must report zeros rather than a percentile
// invented from an empty distribution: the TUI and the dashboard both gate their
// latency lines on Count > 0, and a resolver that has answered nothing has no
// median.
func TestEmptyHistogramReportsZeros(t *testing.T) {
	var h latencyHistogram

	snap := h.snapshot()
	if snap.Count != 0 || snap.AvgMs != 0 || snap.P50Ms != 0 ||
		snap.P95Ms != 0 || snap.P99Ms != 0 || snap.MaxMs != 0 {
		t.Errorf("empty histogram = %+v, want every field zero", snap)
	}
}

// TestPercentilesOfAKnownDistribution uses the shape a real resolver produces: a
// large majority answered from cache in tens of microseconds, a minority that had
// to ask an upstream. It is also the case that makes the mean useless — the
// average here is 3 ms while half the queries finish in under 30 µs.
func TestPercentilesOfAKnownDistribution(t *testing.T) {
	var h latencyHistogram
	for range 90 {
		h.observe(0.04) // a cache hit: the first bucket, 0–0.05 ms
	}
	for range 10 {
		h.observe(30) // an upstream round trip: the 20–35 ms bucket
	}

	snap := h.snapshot()
	if snap.Count != 100 {
		t.Fatalf("count = %d, want 100", snap.Count)
	}
	// The median lands inside the first bucket, 50 of its 90 observations in.
	if want := 0.05 * (50.0 / 90.0); !closeEnough(snap.P50Ms, want) {
		t.Errorf("p50 = %.6f ms, want %.6f", snap.P50Ms, want)
	}
	// p95 and p99 land in the 20–35 ms bucket, which holds ten observations, so
	// they interpolate to half and nine tenths of the way across it.
	if want := 20 + 15*0.5; !closeEnough(snap.P95Ms, want) {
		t.Errorf("p95 = %.6f ms, want %.6f", snap.P95Ms, want)
	}
	if want := 20 + 15*0.9; !closeEnough(snap.P99Ms, want) {
		t.Errorf("p99 = %.6f ms, want %.6f", snap.P99Ms, want)
	}
	// The average is the figure this histogram exists to replace: it sits two
	// orders of magnitude above the median and describes no actual query.
	if want := (90*0.04 + 10*30) / 100.0; !closeEnough(snap.AvgMs, want) {
		t.Errorf("avg = %.6f ms, want %.6f", snap.AvgMs, want)
	}
	if snap.MaxMs != 30 {
		t.Errorf("max = %.3f ms, want exactly 30", snap.MaxMs)
	}
	// Ordered, but note what is deliberately *not* asserted: p99 (33.5 ms here)
	// exceeds the exact max (30 ms). Interpolation spreads a bucket's observations
	// evenly across it, and all ten of these sit on the bucket's lower half, so a
	// high quantile reads as "somewhere in the 20–35 ms band" — which is the
	// precision a bucketed histogram buys its zero-allocation write path with.
	// MaxMs is the number to trust for the worst case.
	if !(snap.P50Ms < snap.P95Ms && snap.P95Ms <= snap.P99Ms) {
		t.Errorf("percentiles are out of order: %+v", snap)
	}
}

// The bounds are inclusive upper edges, so a query that lands exactly on one
// belongs to that bucket and not the next. Off-by-one here would move every
// reading up a band and make the resolver look slower than it is.
func TestObservationOnAnEdgeStaysInThatBucket(t *testing.T) {
	var h latencyHistogram
	for range 50 {
		h.observe(1) // exactly the 1 ms edge
	}

	snap := h.snapshot()
	if snap.P50Ms <= 0.5 || snap.P50Ms > 1 {
		t.Errorf("p50 = %.4f ms, want it inside the (0.5, 1] bucket", snap.P50Ms)
	}
	if snap.P99Ms > 1 {
		t.Errorf("p99 = %.4f ms, want at most 1 — the reading was on the edge", snap.P99Ms)
	}
	if snap.MaxMs != 1 {
		t.Errorf("max = %.4f ms, want exactly 1", snap.MaxMs)
	}
}

// A query slower than the last bucket edge has nowhere to be counted but the
// overflow bucket, which has no upper bound. Reporting the last edge is the
// honest answer — "at least two seconds" — and MaxMs is what says how much worse
// it really was. Inventing a number for the overflow bucket would understate a
// timeout as badly as it would overstate a slow answer.
func TestOverflowReportsTheLastEdgeAndKeepsTheExactMax(t *testing.T) {
	var h latencyHistogram
	h.observe(5000)

	snap := h.snapshot()
	last := latencyBounds[len(latencyBounds)-1]
	if snap.P50Ms != last || snap.P99Ms != last {
		t.Errorf("p50 = %.1f, p99 = %.1f, want both %.1f (the last edge)", snap.P50Ms, snap.P99Ms, last)
	}
	if snap.MaxMs != 5000 {
		t.Errorf("max = %.1f ms, want 5000 — the exact worst case must survive bucketing", snap.MaxMs)
	}
	if snap.Count != 1 {
		t.Errorf("count = %d, want 1", snap.Count)
	}
}

// A negative or non-finite reading can only come from a clock that moved
// backwards or from arithmetic on a zero start time. Folding one in would corrupt
// every figure that follows it permanently — a single NaN in the running sum makes
// the average NaN for the lifetime of the process — so they are dropped at the
// door rather than clamped.
func TestImpossibleReadingsAreDropped(t *testing.T) {
	var h latencyHistogram
	h.observe(-1)
	h.observe(math.NaN())
	h.observe(math.Inf(1))
	h.observe(math.Inf(-1))

	if snap := h.snapshot(); snap.Count != 0 || snap.MaxMs != 0 {
		t.Fatalf("a garbage reading was recorded: %+v", snap)
	}

	// And the histogram still works afterwards: dropping is not poisoning.
	h.observe(2)
	snap := h.snapshot()
	if snap.Count != 1 {
		t.Errorf("count = %d after one good reading, want 1", snap.Count)
	}
	if math.IsNaN(snap.AvgMs) || snap.AvgMs <= 0 {
		t.Errorf("avg = %v, want a positive finite number", snap.AvgMs)
	}
	if snap.MaxMs != 2 {
		t.Errorf("max = %.3f ms, want 2", snap.MaxMs)
	}
}

// observe runs on the DNS answer path, called from every listener goroutine at
// once. A lost count would be invisible in the output; a torn max would not.
func TestConcurrentObserveCountsEveryQuery(t *testing.T) {
	var h latencyHistogram
	const goroutines, each = 32, 200

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			// Quarter-millisecond steps: exactly representable, so the max below is
			// an exact expectation rather than a tolerance.
			for i := range each {
				h.observe(float64(g+1) + float64(i%4)*0.25)
			}
		})
	}
	wg.Wait()

	snap := h.snapshot()
	if snap.Count != goroutines*each {
		t.Errorf("count = %d, want %d — an observation was lost under concurrency",
			snap.Count, goroutines*each)
	}
	if want := float64(goroutines) + 0.75; !closeEnough(snap.MaxMs, want) {
		t.Errorf("max = %.4f ms, want %.4f — the CAS loop dropped the highest reading",
			snap.MaxMs, want)
	}
}

// percentileFrom is exercised directly for the two branches observe cannot
// produce: a quantile of zero, and a total the buckets do not account for. The
// second is not hypothetical — snapshot loads the buckets one at a time while
// queries keep arriving, so it can legitimately read a set of counts that no
// single instant ever held.
func TestPercentileFromDegenerateInputs(t *testing.T) {
	counts := make([]uint64, len(latencyBounds)+1)

	if got := percentileFrom(counts, 0, 0.5); got != 0 {
		t.Errorf("percentileFrom with no observations = %v, want 0", got)
	}

	counts[3] = 10
	// q=0 stops at the first bucket, which is empty; an empty bucket has no
	// interior to interpolate across, so its upper edge is the answer.
	if got := percentileFrom(counts, 10, 0); got != latencyBounds[0] {
		t.Errorf("q=0 = %v, want the first bucket's upper edge %v", got, latencyBounds[0])
	}
	if got := percentileFrom(counts, 10, 0.5); got <= latencyBounds[2] || got > latencyBounds[3] {
		t.Errorf("p50 = %v, want it inside the (%v, %v] bucket", got, latencyBounds[2], latencyBounds[3])
	}
	// A total the buckets fall short of: the loop runs out, and the last edge is
	// the only defensible answer left.
	last := latencyBounds[len(latencyBounds)-1]
	if got := percentileFrom(counts, 40, 0.99); got != last {
		t.Errorf("a short count set gave %v, want the last edge %v", got, last)
	}
}

// PushQueryLog is the only feeder for both histograms, and the split between them
// is the entire point: at a healthy hit rate the median query is a cache hit, so a
// single distribution would report the cache's speed and call it the resolver's.
// This is the test that fails if the Cached flag is ever ignored.
func TestPushQueryLogSplitsCachedFromUncached(t *testing.T) {
	s := NewStatsService(nil, nil, nil)
	defer s.Close()

	for range 9 {
		s.PushQueryLog(database.QueryLogItem{
			Domain: "cached.example.", Protocol: "UDP", LatencyMs: 0.03, Cached: true,
		})
	}
	s.PushQueryLog(database.QueryLogItem{
		Domain: "resolved.example.", Protocol: "UDP", LatencyMs: 42, Cached: false,
	})

	st := s.GetLiveStats()
	if st.Latency.Count != 10 {
		t.Errorf("latency.count = %d, want all 10 queries", st.Latency.Count)
	}
	if st.LatencyUncached.Count != 1 {
		t.Errorf("latency_uncached.count = %d, want only the cache miss", st.LatencyUncached.Count)
	}
	// Nine hits in ten drag the overall median into the first bucket while the one
	// real resolution sits at 42 ms. That gap is what a single distribution hides.
	if st.Latency.P50Ms > 0.05 {
		t.Errorf("overall p50 = %.4f ms, want it inside the first bucket", st.Latency.P50Ms)
	}
	if st.LatencyUncached.P50Ms < latencyBounds[9] {
		t.Errorf("uncached p50 = %.4f ms, want the 35–50 ms band", st.LatencyUncached.P50Ms)
	}
	if st.Latency.MaxMs != 42 {
		t.Errorf("latency.max = %.2f ms, want 42", st.Latency.MaxMs)
	}

	// The figures are cumulative since start, not per-poll: the dashboard reads
	// them every second and must not consume them.
	if again := s.GetLiveStats(); again.Latency.Count != st.Latency.Count {
		t.Errorf("a second poll reported %d queries, want the same %d — reading reset the histogram",
			again.Latency.Count, st.Latency.Count)
	}
}
