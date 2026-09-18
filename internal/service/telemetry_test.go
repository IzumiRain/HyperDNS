package service

import (
	"runtime"
	"testing"
	"time"
)

// The home tab's RAM Usage tile is fed by two runtime/metrics counters rather than by
// runtime.ReadMemStats, because ReadMemStats stops the world and the tile refreshes
// once a second. That trade is only sound while the counters exist — and their names
// are explicitly outside Go's compatibility promise, so a toolchain upgrade is allowed
// to retire one without warning.
//
// This is the test that turns that from a silent dashboard regression into a failing
// build. Without it, the failure mode is a panel reporting 0.0 MB for a process using
// forty, with nothing in any log: newMemorySamples would report false, sampleMemory
// would quietly fall back to the five-second ReadMemStats path, and the only visible
// symptom would be a number that updates less often than it used to.
func TestMemoryMetricNamesAreImplementedByThisRuntime(t *testing.T) {
	samples, ok := newMemorySamples()
	if !ok {
		t.Fatalf("runtime/metrics does not implement %q and %q on %s — the telemetry loop "+
			"has fallen back to stop-the-world ReadMemStats; find the current names in "+
			"runtime/metrics.All() and update the constants",
			metricHeapObjectBytes, metricTotalBytes, runtime.Version())
	}
	if len(samples) != 2 {
		t.Fatalf("newMemorySamples returned %d samples, want 2", len(samples))
	}
}

// The two counters have to mean what the tiles claim they mean. /memory/classes/total
// is every byte the runtime has mapped, so it must be at least as large as the live
// heap — if the constants were ever swapped, the panel would report a total smaller
// than its own heap and nothing else in the code would notice.
func TestSampledMemoryIsSelfConsistentAndNonZero(t *testing.T) {
	samples, ok := newMemorySamples()
	if !ok {
		t.Skip("runtime/metrics unavailable; covered by TestMemoryMetricNamesAreImplemented...")
	}

	heap, total, got := sampleMemory(samples, true, 0)
	if !got {
		t.Fatal("sampleMemory reported no reading with metrics available")
	}
	if heap == 0 {
		t.Error("live heap sampled as 0 bytes, which no running Go process has")
	}
	if total < heap {
		t.Errorf("total mapped memory %d is smaller than the live heap %d — the two metric "+
			"constants are the wrong way round", total, heap)
	}
}

// The degraded path exists so that a runtime without those counters shows a slower
// panel rather than a lying one. It keeps the old five-second cadence, so it must
// report "no reading" on the four ticks in between — a caller that took a zero from it
// would blank the tiles four seconds out of five.
func TestSampleMemoryFallbackKeepsTheFiveSecondCadence(t *testing.T) {
	for tick := range 10 {
		heap, total, got := sampleMemory(nil, false, tick)
		wantReading := tick%5 == 0

		if got != wantReading {
			t.Errorf("tick %d: reported got=%v, want %v", tick, got, wantReading)
		}
		if !wantReading && (heap != 0 || total != 0) {
			t.Errorf("tick %d: returned %d/%d alongside got=false; a caller that ignored "+
				"the flag would show these", tick, heap, total)
		}
		if wantReading && heap == 0 {
			t.Errorf("tick %d: ReadMemStats fallback reported a zero heap", tick)
		}
	}
}

// CPU% is a ratio, so the first sample cannot produce one — there is nothing to
// difference it against. Reporting false rather than 0.0 is what keeps the tile showing
// its previous value instead of flashing to zero every time the loop restarts.
func TestSampleCPUReportsNothingUntilItHasTwoSamples(t *testing.T) {
	ring := make([]cpuSample, 0, cpuWindowTicks+1)

	if _, ok := sampleCPU(&ring, 4); ok {
		t.Error("first sample produced a percentage; there was no interval to divide by")
	}
	if len(ring) != 1 {
		t.Fatalf("ring holds %d samples after one call, want 1", len(ring))
	}

	// A real interval has to pass, or dWall is 0 and the reading is correctly rejected.
	time.Sleep(20 * time.Millisecond)

	pct, ok := sampleCPU(&ring, 4)
	if !ok {
		t.Fatal("second sample produced no percentage")
	}
	if pct < 0 {
		t.Errorf("CPU%% reported as %.2f", pct)
	}
}

// The ring is what makes the figure refresh every second while still being measured
// over five. It has to stay bounded — this loop runs for the life of the daemon, so a
// ring that grew one entry per second would be a slow leak — and it has to keep exactly
// the oldest sample the window needs, no more.
func TestSampleCPURingStaysBoundedAtTheWindowLength(t *testing.T) {
	ring := make([]cpuSample, 0, cpuWindowTicks+1)

	for range cpuWindowTicks * 4 {
		sampleCPU(&ring, runtime.NumCPU())
		if len(ring) > cpuWindowTicks+1 {
			t.Fatalf("ring grew to %d samples, want at most %d", len(ring), cpuWindowTicks+1)
		}
	}

	if len(ring) != cpuWindowTicks+1 {
		t.Errorf("ring settled at %d samples, want %d — the window is not the length it "+
			"claims to be", len(ring), cpuWindowTicks+1)
	}

	// Oldest first, newest last: the percentage is computed against ring[0], so a ring
	// trimmed from the wrong end would silently shorten the window to one tick.
	for i := 1; i < len(ring); i++ {
		if ring[i].at.Before(ring[i-1].at) {
			t.Fatalf("sample %d is older than sample %d; the ring is trimmed from the "+
				"wrong end", i, i-1)
		}
	}
}

// A process cannot use more than one core's worth of CPU per core. Anything above that
// is an artefact — the shape to guard against is a host that suspended and resumed,
// where cumulative CPU time has advanced far more than the wall interval the loop
// thinks elapsed — and the panel should clamp it rather than render 4000%.
//
// The oldest sample is given an unphysical CPU reading to construct that ratio
// deterministically. The point under test is the clamp arithmetic, not the plausibility
// of the input: a real suspend produces the same large-dCPU/small-dWall shape.
func TestSampleCPUIsClampedToTheCoreCount(t *testing.T) {
	ring := []cpuSample{{seconds: -1e9, at: time.Now()}}

	// Windows' monotonic clock is coarse enough that two back-to-back time.Now() calls
	// can differ by exactly zero, which sampleCPU correctly refuses to divide by. Sleep
	// so the interval is real and the clamp branch is the one being exercised.
	time.Sleep(20 * time.Millisecond)

	pct, ok := sampleCPU(&ring, 1)
	if !ok {
		t.Fatal("sampleCPU rejected a readable sample pair")
	}
	if want := 100 * numCPUFactor(1); pct != want {
		t.Errorf("reported %.1f%% for a single-core clamp, want exactly %.1f%%", pct, want)
	}

	// Same reading, four cores: the ceiling scales with the core count rather than
	// being a flat 100.
	ring = []cpuSample{{seconds: -1e9, at: time.Now()}}
	time.Sleep(20 * time.Millisecond)
	if pct, ok := sampleCPU(&ring, 4); !ok || pct != 400 {
		t.Errorf("four-core clamp reported %.1f%% (ok=%v), want 400.0%%", pct, ok)
	}
}

// The reason the tiles can refresh once a second at all. ReadMemStats stops the world;
// metrics.Read does not, and on a resolver that pause is charged to every query in
// flight. Measured on a 13th-gen i5, -benchtime 2000x:
//
//	BenchmarkSampleMemoryViaRuntimeMetrics-12       846.8 ns/op
//	BenchmarkSampleMemoryViaReadMemStats-12       55083   ns/op
//
// 65x, and the 55 µs is the part that halts every goroutine rather than just this one.
// Paying it once a second to animate a number would have been the wrong trade; at 847 ns
// there is no trade left to make.
func BenchmarkSampleMemoryViaRuntimeMetrics(b *testing.B) {
	samples, ok := newMemorySamples()
	if !ok {
		b.Skip("runtime/metrics unavailable")
	}
	for b.Loop() {
		sampleMemory(samples, true, 0)
	}
}

func BenchmarkSampleMemoryViaReadMemStats(b *testing.B) {
	for b.Loop() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
	}
}
