package service

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

// Every DNS query from an unknown source address passes through IsIPAllowed
// before the resolver will answer it, so this lookup sits on the hot path next to
// the cache. These benchmarks exist because the documentation claims a specific
// per-lookup cost ("< 15ns", "lock-free") that the implementation does not
// deliver — the maps are guarded by a sync.RWMutex — and a published figure has
// to come from a measurement, not from a design intention.
//
// reloadCache is benchmarked alongside them because it is not a hot path but a
// write-path amplifier: every client create, update, renew, delete, toggle and IP
// registration rebuilds all three indexes from a full database scan. For a
// reseller with hundreds of subscribers that cost is what an operator actually
// feels in the dashboard.

// benchService builds a ClientService backed by a real encrypted database holding
// n enabled clients, and returns the addresses that are in the index. Files live
// in the benchmark's temp directory.
func benchService(b *testing.B, n int, allowAll bool) (*ClientService, []string) {
	b.Helper()

	dir := b.TempDir()
	cipher, err := crypto.LoadOrGenerateMasterKey(filepath.Join(dir, "bench.key"))
	if err != nil {
		b.Fatalf("failed to create cipher: %v", err)
	}
	db, err := database.Open(filepath.Join(dir, "bench.db"), cipher)
	if err != nil {
		b.Fatalf("failed to open database: %v", err)
	}
	b.Cleanup(func() { _ = db.Close() })

	ips := make([]string, n)
	for i := range n {
		// 10.x.y.z keeps every address distinct up to 16M clients without
		// colliding with the documentation ranges used elsewhere in the tests.
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		ips[i] = ip
		c := database.Client{
			ID:         fmt.Sprintf("bench%06d", i),
			UUID:       database.GenerateUUID(),
			Name:       fmt.Sprintf("Subscriber %d", i),
			Token:      fmt.Sprintf("tok%06d", i),
			AllowedIPs: []string{ip},
			Enabled:    true,
			CreatedAt:  time.Now(),
		}
		if err := db.SaveClient(c); err != nil {
			b.Fatalf("failed to save client %d: %v", i, err)
		}
	}

	// NewClientService populates the indexes from disk, so the maps are warm
	// before the timer starts.
	return NewClientService(db, allowAll), ips
}

// BenchmarkIsIPAllowedHit is the cost paid by every query from a known
// subscriber: one RLock, one map hit, one RUnlock.
func BenchmarkIsIPAllowedHit(b *testing.B) {
	svc, ips := benchService(b, 1000, false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if _, ok := svc.IsIPAllowed(ips[i%len(ips)]); !ok {
			b.Fatal("known address was not allowed")
		}
	}
}

// BenchmarkIsIPAllowedMiss is the cost paid by a stranger — including anyone
// probing the resolver, so it is the one an attacker can drive.
func BenchmarkIsIPAllowedMiss(b *testing.B) {
	svc, _ := benchService(b, 1000, false)
	// Built up front: formatting an address inside the loop would allocate once
	// per iteration and report the benchmark's own cost as the lookup's.
	strangers := strangerIPs(256)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if _, ok := svc.IsIPAllowed(strangers[i%len(strangers)]); ok {
			b.Fatal("unknown address was allowed")
		}
	}
}

// BenchmarkIsIPAllowedAllowAll covers the open-resolver configuration, where the
// lookup still runs but its result only decides whether per-client policy applies.
func BenchmarkIsIPAllowedAllowAll(b *testing.B) {
	svc, _ := benchService(b, 1000, true)
	strangers := strangerIPs(256)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if _, ok := svc.IsIPAllowed(strangers[i%len(strangers)]); !ok {
			b.Fatal("allowAll refused an address")
		}
	}
}

// strangerIPs returns n addresses that benchService never indexes.
func strangerIPs(n int) []string {
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("198.51.100.%d", i&0xff)
	}
	return out
}

// BenchmarkIsIPAllowedParallel is the figure that matters for the "QPS per core"
// claim: the map is shared behind one RWMutex, so this shows whether concurrent
// resolver goroutines actually scale or queue on the reader lock.
func BenchmarkIsIPAllowedParallel(b *testing.B) {
	svc, ips := benchService(b, 4096, false)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, ok := svc.IsIPAllowed(ips[i%len(ips)]); !ok {
				b.Error("known address was not allowed")
				return
			}
			i++
		}
	})
}

// BenchmarkFindClientByUUID covers the subscription-link path: the portal
// resolves a UUID on every fetch of a client's configuration.
func BenchmarkFindClientByUUID(b *testing.B) {
	svc, _ := benchService(b, 1000, false)

	svc.mu.RLock()
	uuids := make([]string, 0, len(svc.uuidMap))
	for u := range svc.uuidMap {
		uuids = append(uuids, u)
	}
	svc.mu.RUnlock()
	if len(uuids) == 0 {
		b.Fatal("no UUIDs were indexed")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if _, err := svc.FindClientByUUID(uuids[i%len(uuids)]); err != nil {
			b.Fatalf("indexed UUID not found: %v", err)
		}
	}
}

// BenchmarkReloadCache100 and BenchmarkReloadCache1000 measure what every write
// costs, because each one rebuilds all three indexes from a full database scan.
// The pair is here to show the scaling: a reseller's dashboard pays this on every
// subscriber edit, and the decrypt-per-record work makes it far from free.
func BenchmarkReloadCache100(b *testing.B)  { benchReload(b, 100) }
func BenchmarkReloadCache1000(b *testing.B) { benchReload(b, 1000) }

func benchReload(b *testing.B, n int) {
	svc, _ := benchService(b, n, false)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		svc.reloadCache()
	}
}
