package service

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"hyperdns/internal/database"
)

// bytesPerGB converts the operator-facing TrafficLimitGB into the unit usage is
// counted in. A gibibyte is what the dashboard's own formatter divides by, so the
// limit means the same thing on both sides of the API.
const bytesPerGB = 1 << 30

// defaultFlushInterval bounds how much accounted traffic a crash can lose.
const defaultFlushInterval = 30 * time.Second

// trafficLedger accumulates relayed bytes per client in memory so a finished
// relay never waits on a database write. Before this existed TrafficUsedBytes was
// written in exactly one place — the reset to zero — so every TrafficLimitGB an
// operator configured was decorative.
//
// Counters are never removed from the map. A relay goroutine can hold a pointer
// taken under RLock while a flush swaps values out, so deleting an entry would
// silently discard whatever that goroutine adds next. Keys are client IDs read
// from the database, never anything a client sends, so the map is bounded by the
// number of accounts rather than by traffic.
type trafficLedger struct {
	mu      sync.RWMutex
	pending map[string]*atomic.Uint64
}

func newTrafficLedger() *trafficLedger {
	return &trafficLedger{pending: make(map[string]*atomic.Uint64)}
}

// counter returns the accumulator for id, creating it on first use.
func (l *trafficLedger) counter(id string) *atomic.Uint64 {
	l.mu.RLock()
	ctr := l.pending[id]
	l.mu.RUnlock()
	if ctr != nil {
		return ctr
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if ctr = l.pending[id]; ctr == nil {
		ctr = new(atomic.Uint64)
		l.pending[id] = ctr
	}
	return ctr
}

func (l *trafficLedger) add(id string, n uint64) {
	if id == "" || n == 0 {
		return
	}
	l.counter(id).Add(n)
}

func (l *trafficLedger) get(id string) uint64 {
	if id == "" {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if ctr := l.pending[id]; ctr != nil {
		return ctr.Load()
	}
	return 0
}

// reset discards usage that has not been persisted yet, so a traffic reset is not
// undone by the next flush writing pre-reset bytes on top of the zero.
func (l *trafficLedger) reset(id string) {
	l.mu.RLock()
	ctr := l.pending[id]
	l.mu.RUnlock()
	if ctr != nil {
		ctr.Store(0)
	}
}

// take removes and returns the usage that has not been persisted yet. It is reset
// with the value in hand: a quota rollover has to know what the period consumed
// *and* start the next one from zero, and doing those as a read then a clear would
// lose whatever a relay added in between.
func (l *trafficLedger) take(id string) uint64 {
	if id == "" {
		return 0
	}
	l.mu.RLock()
	ctr := l.pending[id]
	l.mu.RUnlock()
	if ctr == nil {
		return 0
	}
	return ctr.Swap(0)
}

// drain moves every accumulated count out of the ledger and returns it. Swapping
// each counter to zero rather than replacing the map is what makes a concurrent
// add safe: the worst case is that those bytes land in the following drain.
func (l *trafficLedger) drain() map[string]uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make(map[string]uint64, len(l.pending))
	for id, ctr := range l.pending {
		if n := ctr.Swap(0); n > 0 {
			out[id] = n
		}
	}
	return out
}

// AddTraffic records n bytes carried on a client's behalf. Every finished relay
// calls it, so it touches neither the database nor the lock that guards the IP
// lookup tables.
func (s *ClientService) AddTraffic(clientID string, n uint64) {
	s.traffic.add(clientID, n)
}

// TrafficUsed is a client's total usage: what is stored on disk plus what has
// accumulated since the last flush.
func (s *ClientService) TrafficUsed(c *database.Client) uint64 {
	if c == nil {
		return 0
	}
	return c.TrafficUsedBytes + s.traffic.get(c.ID)
}

// PendingTraffic is the usage counted for a client but not yet persisted.
func (s *ClientService) PendingTraffic(clientID string) uint64 {
	return s.traffic.get(clientID)
}

// QuotaExceeded reports whether a client has spent its whole allowance. A limit
// of zero means unlimited, which is what every account created before quotas were
// enforced carries, so switching this on cannot retroactively cut anyone off.
func (s *ClientService) QuotaExceeded(c *database.Client) bool {
	if c == nil {
		return false
	}
	return quotaExceededFor(s.TrafficUsed(c), c.TrafficLimitGB)
}

// quotaExceededFor is the comparison itself, over a usage figure the caller has
// already settled. ClientView needs it for a record whose pending bytes are folded
// in already, and duplicating the test there would put the enforcement rule in two
// places — the panel would then be free to disagree with the resolver about who is
// cut off.
//
// The comparison is done in float64 rather than by converting the limit to uint64:
// a limit large enough to overflow the integer conversion is implementation-
// defined in Go and could wrap to a tiny quota, cutting off exactly the accounts
// the operator meant to leave alone.
func quotaExceededFor(usedBytes uint64, limitGB float64) bool {
	if limitGB <= 0 {
		return false
	}
	return float64(usedBytes) >= limitGB*bytesPerGB
}

// FlushTraffic persists everything the ledger has accumulated, in one write
// transaction. Each record is read back inside it before its delta is added, so a
// limit change or a reset made through the dashboard in the meantime is not
// clobbered by a stale in-memory copy.
//
// Bytes that could not be written are handed back to the ledger so the next flush
// retries them: a transient fault must not make traffic free. Bytes belonging to a
// deleted account are dropped instead, because retrying those forever would keep
// reporting an error no operator can act on.
func (s *ClientService) FlushTraffic() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	deltas := s.traffic.drain()
	if len(deltas) == 0 {
		return nil
	}

	unapplied, err := s.db.AddClientTraffic(deltas)
	for id, n := range unapplied {
		s.traffic.add(id, n)
	}
	if err != nil {
		return err
	}

	// The cached client records carry the pre-flush TrafficUsedBytes, and
	// QuotaExceeded is evaluated against exactly those copies — so without this the
	// pending counter would reset to zero every flush while the cached total stayed
	// behind, and a subscriber over quota would come back under it every 30
	// seconds.
	if len(unapplied) < len(deltas) {
		s.reloadCache()
	}
	return nil
}

// StartTrafficFlusher persists accounted usage on a ticker and once more when the
// returned function is called.
//
// It hands back a stop function rather than the channel StartExpirationWatcher
// uses, because this one has to be waited on: main closes the database from a
// defer registered long before the flusher starts, so a final flush that had
// merely been signalled would race that close and lose exactly the usage it
// exists to save. The returned function is safe to call more than once.
func (s *ClientService) StartTrafficFlusher(interval time.Duration) func() {
	if interval <= 0 {
		interval = defaultFlushInterval
	}
	stopChan := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.FlushTraffic(); err != nil {
					log.Printf("[ClientService] Traffic flush failed: %v", err)
				}
			case <-stopChan:
				// Usage counted since the last tick would otherwise be lost on
				// every restart, which is how a metered account becomes free.
				if err := s.FlushTraffic(); err != nil {
					log.Printf("[ClientService] Final traffic flush failed: %v", err)
				}
				return
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() { close(stopChan) })
		<-done
	}
}
