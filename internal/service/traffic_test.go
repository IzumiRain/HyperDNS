package service

import (
	"sync"
	"testing"
	"time"

	"hyperdns/internal/database"
)

func newTrafficClient(t *testing.T, db *database.DB, id string, limitGB float64, used uint64) *database.Client {
	t.Helper()

	c := &database.Client{
		ID:               id,
		UUID:             database.GenerateUUID(),
		Name:             "Subscriber " + id,
		Token:            "tok-" + id,
		AllowedIPs:       []string{"203.0.113." + id},
		TrafficLimitGB:   limitGB,
		TrafficUsedBytes: used,
		Enabled:          true,
		CreatedAt:        time.Now(),
	}
	if err := db.SaveClient(*c); err != nil {
		t.Fatalf("failed to save client %s: %v", id, err)
	}
	return c
}

func TestLedgerAddGet(t *testing.T) {
	l := newTrafficLedger()

	l.add("c1", 100)
	l.add("c1", 50)
	if got := l.get("c1"); got != 150 {
		t.Fatalf("get(c1) = %d, want 150", got)
	}

	if got := l.get("missing"); got != 0 {
		t.Fatalf("get(missing) = %d, want 0", got)
	}
	// The guards against empty ids and zero counts.
	l.add("", 100)
	l.add("c2", 0)
	if got := l.get("c2"); got != 0 {
		t.Fatalf("add with n=0 recorded %d bytes", got)
	}
}

func TestLedgerDrainSwapsToZero(t *testing.T) {
	l := newTrafficLedger()

	l.add("c1", 200)
	l.add("c2", 300)

	drained := l.drain()
	if drained["c1"] != 200 || drained["c2"] != 300 {
		t.Fatalf("drain() = %v, want c1=200 c2=300", drained)
	}

	// Drain moves the counts out: a second drain must be empty, and the
	// counters must still exist so a later add is not lost.
	if again := l.drain(); len(again) != 0 {
		t.Fatalf("second drain returned %v, want empty", again)
	}
	l.add("c1", 5)
	if got := l.get("c1"); got != 5 {
		t.Fatalf("get(c1) after re-add = %d, want 5", got)
	}
}

func TestLedgerResetDiscardsPendingOnly(t *testing.T) {
	l := newTrafficLedger()

	l.add("c1", 500)
	l.reset("c1")
	if got := l.get("c1"); got != 0 {
		t.Fatalf("get(c1) after reset = %d, want 0", got)
	}

	// Resetting an id that never existed must not create an entry or panic.
	l.reset("ghost")

	// Adds after a reset are kept — the reset cleared what came before, not
	// the counter itself.
	l.add("c1", 7)
	if got := l.get("c1"); got != 7 {
		t.Fatalf("get(c1) = %d, want 7 after post-reset add", got)
	}
}

func TestLedgerConcurrentAddIsLossless(t *testing.T) {
	l := newTrafficLedger()

	const goroutines = 16
	const each = 1000

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				l.add("c1", 1)
			}
		}()
	}
	// A concurrent reader exercises the RLock path while writers run. It must
	// not drain: a drain discards its return value here and the bytes it took
	// would be gone from the accounting below.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			_ = l.get("c1")
		}
	}()
	wg.Wait()

	// Every byte added is either still pending or comes out of the final
	// drain — none lost, none double-counted.
	total := uint64(0)
	for _, n := range l.drain() {
		total += n
	}
	if remaining := l.get("c1"); total+remaining != goroutines*each {
		t.Fatalf("drained %d + pending %d != %d added", total, remaining, goroutines*each)
	}
}

func TestQuotaExceededEdges(t *testing.T) {
	svc, _, cleanup := setupClientFixture(t)
	defer cleanup()

	gb := uint64(1) << 30

	// nil client and a zero (unlimited) limit never exceed, whatever the usage.
	if svc.QuotaExceeded(nil) {
		t.Fatal("nil client reported over quota")
	}
	unlimited := &database.Client{ID: "u", TrafficLimitGB: 0, TrafficUsedBytes: 1 << 40}
	if svc.QuotaExceeded(unlimited) {
		t.Fatal("unlimited account reported over quota")
	}

	// Used exactly at the limit counts as spent; one byte under does not.
	atLimit := &database.Client{ID: "a", TrafficLimitGB: 2, TrafficUsedBytes: 2 * gb}
	if !svc.QuotaExceeded(atLimit) {
		t.Fatal("account at exactly its limit was not reported over quota")
	}
	under := &database.Client{ID: "b", TrafficLimitGB: 2, TrafficUsedBytes: 2*gb - 1}
	if svc.QuotaExceeded(under) {
		t.Fatal("account one byte under its limit reported over quota")
	}

	// Pending usage counts toward the quota without waiting for a flush.
	pending := &database.Client{ID: "p", TrafficLimitGB: 2, TrafficUsedBytes: gb}
	svc.AddTraffic("p", gb)
	if !svc.QuotaExceeded(pending) {
		t.Fatal("pending bytes did not count toward the quota")
	}
	svc.traffic.reset("p")
	if svc.QuotaExceeded(pending) {
		t.Fatal("quota stayed exceeded after the pending bytes were discarded")
	}
}

func TestTrafficUsedCombinesDiskAndPending(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	newTrafficClient(t, db, "10", 10, 1000)

	// The in-memory cache is what callers hand to TrafficUsed, so its stale
	// TrafficUsedBytes plus the live pending counter is the answer.
	cached, err := db.GetClient("10")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got := svc.TrafficUsed(cached); got != 1000 {
		t.Fatalf("TrafficUsed = %d, want the 1000 on disk", got)
	}

	svc.AddTraffic("10", 500)
	if got := svc.TrafficUsed(cached); got != 1500 {
		t.Fatalf("TrafficUsed = %d, want 1500 with 500 pending", got)
	}
	if got := svc.PendingTraffic("10"); got != 500 {
		t.Fatalf("PendingTraffic = %d, want 500", got)
	}

	// An empty id and a nil client are safe no-ops rather than panics.
	svc.AddTraffic("", 100)
	if got := svc.TrafficUsed(nil); got != 0 {
		t.Fatalf("TrafficUsed(nil) = %d, want 0", got)
	}
}

func TestFlushTrafficPersistsAndReloads(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	newTrafficClient(t, db, "20", 0, 100)

	svc.AddTraffic("20", 400)
	if err := svc.FlushTraffic(); err != nil {
		t.Fatalf("FlushTraffic: %v", err)
	}

	// The bytes reached disk and the pending counter is clear.
	stored, err := db.GetClient("20")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.TrafficUsedBytes != 500 {
		t.Fatalf("stored TrafficUsedBytes = %d, want 500", stored.TrafficUsedBytes)
	}
	if got := svc.PendingTraffic("20"); got != 0 {
		t.Fatalf("PendingTraffic after flush = %d, want 0", got)
	}

	// A flush with nothing pending is a cheap no-op, not an error.
	if err := svc.FlushTraffic(); err != nil {
		t.Fatalf("empty FlushTraffic errored: %v", err)
	}
}

func TestFlushTrafficHonoursInterleavedReset(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	newTrafficClient(t, db, "40", 0, 100)

	svc.AddTraffic("40", 300)

	// The operator resets traffic between the add and the flush. The pending
	// 300 must not survive the reset and be written on top of the zero.
	svc.traffic.reset("40")
	if err := svc.FlushTraffic(); err != nil {
		t.Fatalf("FlushTraffic: %v", err)
	}

	stored, err := db.GetClient("40")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.TrafficUsedBytes != 100 {
		t.Fatalf("stored TrafficUsedBytes = %d, want the pre-reset 100", stored.TrafficUsedBytes)
	}
}

func TestStartTrafficFlusherStopsAndFlushesFinal(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	newTrafficClient(t, db, "50", 0, 0)

	stop := svc.StartTrafficFlusher(time.Hour) // ticks never fire in the test
	svc.AddTraffic("50", 700)

	// The stop closure must block until the final flush is done — a fire-
	// and-forget signal would race the caller closing the database — and be
	// safe to call twice.
	stop()
	stop()

	stored, err := db.GetClient("50")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.TrafficUsedBytes != 700 {
		t.Fatalf("stored TrafficUsedBytes = %d after stop, want the final flush's 700", stored.TrafficUsedBytes)
	}
	if got := svc.PendingTraffic("50"); got != 0 {
		t.Fatalf("PendingTraffic after final flush = %d, want 0", got)
	}
}

func TestFlushTrafficKeepsBytesOnWriteFailure(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	newTrafficClient(t, db, "30", 0, 0)

	svc.AddTraffic("30", 111)

	// Close the database underneath the service: writes now fail. The bytes
	// must come back to the ledger — a transient fault must not make traffic
	// free — and the error must surface.
	_ = db.Close()
	if err := svc.FlushTraffic(); err == nil {
		t.Fatal("FlushTraffic reported success with the database closed")
	}
	if got := svc.PendingTraffic("30"); got != 111 {
		t.Fatalf("PendingTraffic(30) = %d after failed flush, want the 111 handed back", got)
	}
}

func TestFlushTrafficDropsDeletedClientQuietly(t *testing.T) {
	svc, _, cleanup := setupClientFixture(t)
	defer cleanup()

	// Bytes accounted for a client whose account was deleted before the flush
	// have nowhere to be written. That is not an operator-actionable error: it
	// must be swallowed, not surfaced, and not retried forever.
	svc.AddTraffic("ghost", 999)
	if err := svc.FlushTraffic(); err != nil {
		t.Fatalf("FlushTraffic returned %v for a deleted account, want silence", err)
	}
	if got := svc.PendingTraffic("ghost"); got != 0 {
		t.Fatalf("PendingTraffic(ghost) = %d, want the bytes dropped", got)
	}
}

func TestFlushTrafficIsSerialised(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	newTrafficClient(t, db, "60", 0, 0)

	// Two flushes racing must both land: flushMu exists so the read-modify-
	// write cannot interleave and one delta overwrite the other.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.AddTraffic("60", 100)
			if err := svc.FlushTraffic(); err != nil {
				t.Errorf("FlushTraffic: %v", err)
			}
		}()
	}
	wg.Wait()

	stored, err := db.GetClient("60")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.TrafficUsedBytes != 800 {
		t.Fatalf("stored TrafficUsedBytes = %d, want 800 from 8 racing flushes", stored.TrafficUsedBytes)
	}
}
