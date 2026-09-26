package database

import (
	"errors"
	"slices"
	"sync"
	"testing"
)

// TestConcurrentSameIPBindsYieldOneWinner is the C-04 race regression (audit
// F-5): two subscriptions racing to bind the same address must resolve to
// exactly one success and one ErrDuplicateIPConflict — never two accepts. The
// atomic single-transaction registerIP makes the uniqueness scan and the write
// commit together, so the second writer sees the first's claim.
//
// There is no race detector in this environment (no C compiler), so this is a
// barrier-started stress substitute over many rounds; the atomic path passes it
// deterministically, while the previous read-scan-in-one-txn / write-in-another
// design accepted both binds.
func TestConcurrentSameIPBindsYieldOneWinner(t *testing.T) {
	const ip = "203.0.113.7"
	for round := 0; round < 40; round++ {
		db := newMaxDevDB(t)
		if err := db.SaveClient(Client{ID: "a", Token: "ta", Enabled: true, RegisterSecret: "s"}); err != nil {
			t.Fatalf("round %d save a: %v", round, err)
		}
		if err := db.SaveClient(Client{ID: "b", Token: "tb", Enabled: true, RegisterSecret: "s"}); err != nil {
			t.Fatalf("round %d save b: %v", round, err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for i, id := range []string{"a", "b"} {
			wg.Add(1)
			go func(i int, id string) {
				defer wg.Done()
				<-start
				_, _, errs[i] = db.RegisterIPForClient(id, ip)
			}(i, id)
		}
		close(start)
		wg.Wait()

		oks, conflicts := 0, 0
		for _, e := range errs {
			switch {
			case e == nil:
				oks++
			case errors.Is(e, ErrDuplicateIPConflict):
				conflicts++
			default:
				t.Fatalf("round %d: unexpected error: %v", round, e)
			}
		}
		if oks != 1 || conflicts != 1 {
			t.Fatalf("round %d: want exactly one success and one conflict, got oks=%d conflicts=%d", round, oks, conflicts)
		}

		holders := 0
		for _, id := range []string{"a", "b"} {
			c, _ := db.GetClient(id)
			if c != nil && slices.Contains(c.AllowedIPs, ip) {
				holders++
			}
		}
		if holders != 1 {
			t.Fatalf("round %d: exactly one account must hold %s, got %d holders", round, ip, holders)
		}
	}
}

// TestBindOnSuspendedAccountRefusesAndKeepsItDisabled is the lost-update
// regression (audit F-2): a bind must never re-enable an account the operator
// suspended. With the atomic registerIP the gate is re-read inside the same
// write transaction as the save, so a stale whole-record write can no longer
// revert the suspension.
func TestBindOnSuspendedAccountRefusesAndKeepsItDisabled(t *testing.T) {
	db := newMaxDevDB(t)
	if err := db.SaveClient(Client{ID: "c", Token: "t", Enabled: true, RegisterSecret: "s"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, _, err := db.RegisterIPForClient("c", "203.0.113.9"); err != nil {
		t.Fatalf("initial bind: %v", err)
	}

	c, _ := db.GetClient("c")
	c.Enabled = false
	if err := db.SaveClient(*c); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	_, _, err := db.RegisterIPForClient("c", "203.0.113.10")
	if !errors.Is(err, ErrClientSuspended) {
		t.Fatalf("bind on a suspended account must return ErrClientSuspended, got %v", err)
	}
	got, _ := db.GetClient("c")
	if got.Enabled {
		t.Fatal("a bind re-enabled a suspended account (lost update)")
	}
	if slices.Contains(got.AllowedIPs, "203.0.113.10") {
		t.Fatal("a refused bind still recorded its address")
	}
}
