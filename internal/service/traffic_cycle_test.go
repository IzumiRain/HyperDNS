package service

import (
	"errors"
	"testing"
	"time"
	_ "time/tzdata"

	"hyperdns/internal/database"
)

// A recurring quota is what turns a limit an operator has to administer by hand
// every month into one they can sell. These tests pin the arithmetic, because every
// way it can go wrong is silent: a boundary that drifts earlier each year, a period
// that resets on every sweep, or an allowance handed back once per month the server
// happened to be switched off.

// utc is shorthand for the fixed dates these tests are written against. Nothing
// here reads the clock — every boundary is checked at a chosen instant — so a run
// in February cannot behave differently from a run in July.
func utc(y int, m time.Month, d, h int) time.Time {
	return time.Date(y, m, d, h, 0, 0, 0, time.UTC)
}

// An unknown cycle name has to be refused rather than read as "no cycle": a typo in
// an API call that silently means *never reset* sells a recurring quota that does
// not recur, and the operator finds out when their subscriber complains.
func TestNormalizeTrafficCycle(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		want  string
		valid bool
	}{
		{"", TrafficCycleNone, true},
		{"   ", TrafficCycleNone, true},
		{"daily", TrafficCycleDaily, true},
		{"Daily", TrafficCycleDaily, true},
		{"  MONTHLY  ", TrafficCycleMonthly, true},
		{"weekly", TrafficCycleWeekly, true},
		{"yearly", "", false},
		{"month", "", false},
		{"30d", "", false},
		{"none", "", false},
	} {
		got, ok := NormalizeTrafficCycle(tc.raw)
		if ok != tc.valid {
			t.Errorf("NormalizeTrafficCycle(%q) valid = %v, want %v", tc.raw, ok, tc.valid)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeTrafficCycle(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// time.Time.AddDate normalises overflow, so January 31st plus one month is March
// 3rd. For a quota boundary that is not a rounding difference: the boundary walks
// forward through the calendar every time it crosses a short month, and the
// subscriber's period gets longer every year.
func TestAddMonthsClampedStaysInsideTheTargetMonth(t *testing.T) {
	for _, tc := range []struct {
		from   time.Time
		months int
		want   time.Time
	}{
		{utc(2026, time.January, 31, 9), 1, utc(2026, time.February, 28, 9)},
		// A leap year, and a century that is not one.
		{utc(2024, time.January, 31, 9), 1, utc(2024, time.February, 29, 9)},
		{utc(2100, time.January, 31, 9), 1, utc(2100, time.February, 28, 9)},
		// Clamping applies to the boundary that needs it and to no other: the 31st
		// has to come back in March.
		{utc(2026, time.January, 31, 9), 2, utc(2026, time.March, 31, 9)},
		{utc(2026, time.January, 30, 9), 1, utc(2026, time.February, 28, 9)},
		{utc(2026, time.March, 31, 9), 1, utc(2026, time.April, 30, 9)},
		// Across a year boundary, forwards and back.
		{utc(2026, time.December, 31, 9), 1, utc(2027, time.January, 31, 9)},
		{utc(2026, time.December, 31, 9), 12, utc(2027, time.December, 31, 9)},
		{utc(2026, time.March, 31, 9), -1, utc(2026, time.February, 28, 9)},
		{utc(2026, time.January, 15, 9), -1, utc(2025, time.December, 15, 9)},
		{utc(2026, time.January, 15, 9), -13, utc(2024, time.December, 15, 9)},
		{utc(2026, time.January, 15, 9), 0, utc(2026, time.January, 15, 9)},
	} {
		if got := addMonthsClamped(tc.from, tc.months); !got.Equal(tc.want) {
			t.Errorf("addMonthsClamped(%s, %d) = %s, want %s",
				tc.from.Format(time.RFC3339), tc.months,
				got.Format(time.RFC3339), tc.want.Format(time.RFC3339))
		}
	}
}

// daysInMonth is the definition the clamp rests on, so it is worth pinning
// separately: February in a leap year, in a common year and in a century that is
// not a leap year, plus December, where a naive "first of the next month" would
// overflow the year.
func TestDaysInMonth(t *testing.T) {
	for _, tc := range []struct {
		year  int
		month time.Month
		want  int
	}{
		{2026, time.February, 28},
		{2024, time.February, 29},
		{2000, time.February, 29},
		{2100, time.February, 28},
		{2026, time.January, 31},
		{2026, time.April, 30},
		{2026, time.December, 31},
	} {
		if got := daysInMonth(tc.year, tc.month); got != tc.want {
			t.Errorf("daysInMonth(%d, %s) = %d, want %d", tc.year, tc.month, got, tc.want)
		}
	}
}

// The anti-drift property, stated as a year of boundaries: a monthly quota
// anchored on the 31st falls back to the end of every short month and returns to
// the 31st in the next long one, and twelve boundaries on it is the 31st again.
//
// This is what the immutable anchor buys. Advancing a mutable "last reset"
// timestamp would make February's clamp permanent, and a subscription sold on the
// 31st would renew three days earlier every year — days the subscriber paid for and
// never gets back.
func TestTrafficCycleEndDoesNotDrift(t *testing.T) {
	anchor := utc(2026, time.January, 31, 9)

	want := []time.Time{
		utc(2026, time.February, 28, 9),
		utc(2026, time.March, 31, 9),
		utc(2026, time.April, 30, 9),
		utc(2026, time.May, 31, 9),
		utc(2026, time.June, 30, 9),
		utc(2026, time.July, 31, 9),
		utc(2026, time.August, 31, 9),
		utc(2026, time.September, 30, 9),
		utc(2026, time.October, 31, 9),
		utc(2026, time.November, 30, 9),
		utc(2026, time.December, 31, 9),
		utc(2027, time.January, 31, 9),
	}
	for n, w := range want {
		got, ok := trafficCycleEnd(TrafficCycleMonthly, anchor, uint64(n))
		if !ok {
			t.Fatalf("trafficCycleEnd(monthly, %d) reported the cycle as unusable", n)
		}
		if !got.Equal(w) {
			t.Errorf("boundary %d = %s, want %s", n, got.Format(time.RFC3339), w.Format(time.RFC3339))
		}
	}

	// Daily and weekly are measured in calendar days from the same anchor.
	for _, tc := range []struct {
		cycle string
		n     uint64
		want  time.Time
	}{
		{TrafficCycleDaily, 0, utc(2026, time.February, 1, 9)},
		{TrafficCycleDaily, 27, utc(2026, time.February, 28, 9)},
		{TrafficCycleWeekly, 0, utc(2026, time.February, 7, 9)},
		{TrafficCycleWeekly, 51, utc(2027, time.January, 30, 9)},
	} {
		got, ok := trafficCycleEnd(tc.cycle, anchor, tc.n)
		if !ok {
			t.Fatalf("trafficCycleEnd(%s, %d) reported the cycle as unusable", tc.cycle, tc.n)
		}
		if !got.Equal(tc.want) {
			t.Errorf("trafficCycleEnd(%s, %d) = %s, want %s",
				tc.cycle, tc.n, got.Format(time.RFC3339), tc.want.Format(time.RFC3339))
		}
	}
}

// A record this code cannot compute a boundary for must report that, not guess. A
// guess in either direction is a live failure: "already due" resets the account on
// every sweep, and a wrong date is a quota that comes back at the wrong time.
func TestTrafficCycleEndRejectsWhatItCannotCompute(t *testing.T) {
	anchor := utc(2026, time.January, 10, 0)

	for _, tc := range []struct {
		name   string
		cycle  string
		anchor time.Time
		n      uint64
	}{
		{"no cycle", TrafficCycleNone, anchor, 0},
		{"unknown cycle", "yearly", anchor, 0},
		{"hand-edited cycle", "Monthly", anchor, 0},
		{"zero anchor", TrafficCycleMonthly, time.Time{}, 0},
		{"count past the bound", TrafficCycleDaily, anchor, maxCatchUpCycles + 1},
	} {
		if got, ok := trafficCycleEnd(tc.cycle, tc.anchor, tc.n); ok {
			t.Errorf("%s: trafficCycleEnd reported %s as usable", tc.name, got.Format(time.RFC3339))
		}
	}
}

// A boundary is a wall-clock time, not a count of hours: stepping in calendar days
// means a daily quota that resets at noon keeps resetting at noon across a
// daylight-saving change, instead of walking an hour each way twice a year.
func TestTrafficCycleBoundariesKeepTheirWallClockAcrossDST(t *testing.T) {
	// Embedded via the tzdata import, so this does not depend on the host having a
	// zoneinfo database — which Windows does not.
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}

	// US daylight saving starts on 8 March 2026, inside every window below.
	anchor := time.Date(2026, time.March, 1, 12, 0, 0, 0, loc)
	for _, cycle := range []string{TrafficCycleDaily, TrafficCycleWeekly, TrafficCycleMonthly} {
		for n := range uint64(10) {
			got, ok := trafficCycleEnd(cycle, anchor, n)
			if !ok {
				t.Fatalf("trafficCycleEnd(%s, %d): unusable", cycle, n)
			}
			if h, m := got.Hour(), got.Minute(); h != 12 || m != 0 {
				t.Errorf("%s boundary %d landed at %s — the wall-clock time moved",
					cycle, n, got.Format(time.RFC3339))
			}
		}
	}
}

// dueTrafficResets counts boundaries rather than answering yes/no, because a daemon
// that was off for three months has to land on the *current* cycle. Advancing by
// one would leave the next boundary in the past, and the account would then be reset
// on every sweep until it caught up.
func TestDueTrafficResets(t *testing.T) {
	anchor := utc(2026, time.January, 10, 0)

	for _, tc := range []struct {
		name   string
		cycle  string
		anchor time.Time
		count  uint64
		now    time.Time
		want   uint64
	}{
		{"before the first boundary", TrafficCycleMonthly, anchor, 0, utc(2026, time.February, 9, 23), 0},
		{"on the boundary", TrafficCycleMonthly, anchor, 0, utc(2026, time.February, 10, 0), 1},
		{"just past it", TrafficCycleMonthly, anchor, 0, utc(2026, time.February, 11, 0), 1},
		{"three months offline", TrafficCycleMonthly, anchor, 0, utc(2026, time.April, 20, 0), 3},
		{"already caught up", TrafficCycleMonthly, anchor, 3, utc(2026, time.April, 20, 0), 0},
		{"partly caught up", TrafficCycleMonthly, anchor, 2, utc(2026, time.April, 20, 0), 1},
		{"five days of a daily cycle", TrafficCycleDaily, anchor, 0, utc(2026, time.January, 15, 12), 5},
		{"three weeks of a weekly cycle", TrafficCycleWeekly, anchor, 0, utc(2026, time.February, 1, 0), 3},
		{"no cycle never comes due", TrafficCycleNone, anchor, 0, utc(2030, time.January, 1, 0), 0},
		{"unknown cycle never comes due", "yearly", anchor, 0, utc(2030, time.January, 1, 0), 0},
		{"no anchor never comes due", TrafficCycleMonthly, time.Time{}, 0, utc(2030, time.January, 1, 0), 0},
	} {
		got := dueTrafficResets(tc.cycle, tc.anchor, tc.count, tc.now)
		if got != tc.want {
			t.Errorf("%s: dueTrafficResets = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// NextTrafficReset is what the panel and the portal render. The second return has
// to be false — not a zero time — whenever there is no boundary, so a caller shows
// "does not reset" instead of the first of January in year one.
func TestNextTrafficReset(t *testing.T) {
	anchor := utc(2026, time.January, 31, 9)

	if _, ok := NextTrafficReset(nil); ok {
		t.Error("NextTrafficReset(nil) reported a date")
	}
	for _, c := range []database.Client{
		{ID: "none"},
		{ID: "blank cycle", TrafficResetAnchor: anchor},
		{ID: "unknown cycle", TrafficResetCycle: "yearly", TrafficResetAnchor: anchor},
		{ID: "no anchor", TrafficResetCycle: TrafficCycleMonthly},
	} {
		if got, ok := NextTrafficReset(&c); ok {
			t.Errorf("%s: NextTrafficReset reported %s", c.ID, got.Format(time.RFC3339))
		}
	}

	// A cycle that is set, with the count the record has actually reached.
	c := database.Client{
		ID: "live", TrafficResetCycle: "Monthly", TrafficResetAnchor: anchor, TrafficResetCount: 2,
	}
	got, ok := NextTrafficReset(&c)
	if !ok {
		t.Fatal("NextTrafficReset reported no date for a monthly cycle")
	}
	if want := utc(2026, time.April, 30, 9); !got.Equal(want) {
		t.Errorf("NextTrafficReset = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

// A rollover needs the period's total *and* a zeroed counter. Reading and then
// clearing would lose whatever a relay added in between, which on a busy box is
// every rollover.
func TestTrafficLedgerTakeSwapsAtomically(t *testing.T) {
	l := newTrafficLedger()

	if got := l.take("never-seen"); got != 0 {
		t.Errorf("take on an unknown id = %d, want 0", got)
	}
	if got := l.take(""); got != 0 {
		t.Errorf("take on an empty id = %d, want 0", got)
	}

	l.add("a", 700)
	if got := l.take("a"); got != 700 {
		t.Errorf("take = %d, want 700", got)
	}
	if got := l.get("a"); got != 0 {
		t.Errorf("the counter was left at %d after a take", got)
	}
	// Bytes that arrive after the take belong to the period that just started.
	l.add("a", 5)
	if got := l.get("a"); got != 5 {
		t.Errorf("post-take usage = %d, want 5", got)
	}
}

// The whole point of the feature, end to end: a subscriber who has spent their
// allowance is over quota, and when the period rolls over they are under it again
// without anybody opening the panel.
func TestApplyTrafficCyclesRollsOverTheQuotaOnce(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	anchor := utc(2026, time.January, 10, 0)
	if err := db.SaveClient(database.Client{
		ID: "c1", UUID: database.GenerateUUID(), Name: "monthly", Token: "tok-c1",
		AllowedIPs: []string{"203.0.113.11"}, Enabled: true, CreatedAt: anchor,
		TrafficLimitGB: 1, TrafficUsedBytes: 900_000_000,
		TrafficResetCycle: TrafficCycleMonthly, TrafficResetAnchor: anchor,
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	// Counted but not yet flushed. These bytes belong to the period that is ending.
	svc.AddTraffic("c1", 200_000_000)

	before, err := db.GetClient("c1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !svc.QuotaExceeded(before) {
		t.Fatalf("the account is not over quota to begin with: used %d of %v GB",
			svc.TrafficUsed(before), before.TrafficLimitGB)
	}

	now := utc(2026, time.February, 11, 0)
	clients, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if changed := svc.applyTrafficCycles(clients, now); changed != 1 {
		t.Fatalf("applyTrafficCycles rewrote %d record(s), want 1", changed)
	}

	got, err := db.GetClient("c1")
	if err != nil {
		t.Fatalf("GetClient after the rollover: %v", err)
	}
	if got.TrafficUsedBytes != 0 {
		t.Errorf("stored usage = %d, want 0", got.TrafficUsedBytes)
	}
	if p := svc.PendingTraffic("c1"); p != 0 {
		t.Errorf("%d unflushed bytes survived the rollover and would be charged to the new period", p)
	}
	if got.TrafficPrevCycleBytes != 1_100_000_000 {
		t.Errorf("the period that ended recorded %d bytes, want 1100000000 (stored plus unflushed)",
			got.TrafficPrevCycleBytes)
	}
	if got.TrafficResetCount != 1 {
		t.Errorf("cycle index = %d, want 1", got.TrafficResetCount)
	}
	if !got.TrafficResetAnchor.Equal(anchor) {
		t.Errorf("the anchor moved to %s; boundaries are measured from it and must not drift",
			got.TrafficResetAnchor.Format(time.RFC3339))
	}
	if svc.QuotaExceeded(got) {
		t.Error("the subscriber is still over quota after their period rolled over")
	}
	next, ok := NextTrafficReset(got)
	if !ok || !next.Equal(utc(2026, time.March, 10, 0)) {
		t.Errorf("the next boundary is %s (ok=%v), want 2026-03-10", next.Format(time.RFC3339), ok)
	}

	// The sweep runs on a ticker, so the same instant comes round again and again.
	// A second pass must find nothing to do.
	clients, err = db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if changed := svc.applyTrafficCycles(clients, now); changed != 0 {
		t.Errorf("a repeat pass at the same instant rewrote %d record(s)", changed)
	}
}

// A daemon that was off for three months has to come back on the *current* cycle
// and hand back one allowance, not one per month it missed. Advancing by a single
// period instead would leave the next boundary in the past, and the account would be
// reset again on every sweep until the counter caught up.
func TestApplyTrafficCyclesCatchesUpWithoutOverpaying(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	anchor := utc(2026, time.January, 15, 0)
	if err := db.SaveClient(database.Client{
		ID: "gap", UUID: database.GenerateUUID(), Name: "was offline", Token: "tok-gap",
		Enabled: true, CreatedAt: anchor, TrafficLimitGB: 10, TrafficUsedBytes: 3_000_000,
		TrafficResetCycle: TrafficCycleMonthly, TrafficResetAnchor: anchor,
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	now := utc(2026, time.April, 20, 0)
	clients, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if changed := svc.applyTrafficCycles(clients, now); changed != 1 {
		t.Fatalf("applyTrafficCycles rewrote %d record(s), want 1", changed)
	}

	got, err := db.GetClient("gap")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.TrafficResetCount != 3 {
		t.Errorf("cycle index = %d, want 3 — the account has to land on the current period", got.TrafficResetCount)
	}
	if got.TrafficUsedBytes != 0 {
		t.Errorf("stored usage = %d, want 0", got.TrafficUsedBytes)
	}
	if got.TrafficPrevCycleBytes != 3_000_000 {
		t.Errorf("the period that ended recorded %d bytes, want 3000000", got.TrafficPrevCycleBytes)
	}
	// The postcondition that makes the catch-up worth doing at all.
	next, ok := NextTrafficReset(got)
	if !ok {
		t.Fatal("no next boundary after a catch-up")
	}
	if !next.After(now) {
		t.Errorf("the next boundary is %s, not after %s — the account would be reset on every sweep",
			next.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if want := utc(2026, time.May, 15, 0); !next.Equal(want) {
		t.Errorf("next boundary = %s, want %s", next.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

// A cycle with no anchor arrived some other way — imported, hand-edited, restored
// from a partial backup. It has to be anchored at now and otherwise left alone:
// anchoring is not a rollover, and zeroing usage here would hand back an allowance
// the subscriber has already spent.
func TestApplyTrafficCyclesAnchorsWithoutZeroingUsage(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	if err := db.SaveClient(database.Client{
		ID: "no-anchor", UUID: database.GenerateUUID(), Name: "imported", Token: "tok-no-anchor",
		Enabled: true, CreatedAt: utc(2026, time.January, 1, 0),
		TrafficLimitGB: 20, TrafficUsedBytes: 7_000_000,
		TrafficResetCycle: TrafficCycleWeekly,
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	now := utc(2026, time.June, 1, 8)
	clients, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if changed := svc.applyTrafficCycles(clients, now); changed != 1 {
		t.Fatalf("applyTrafficCycles rewrote %d record(s), want 1", changed)
	}

	got, err := db.GetClient("no-anchor")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !got.TrafficResetAnchor.Equal(now) {
		t.Errorf("anchor = %s, want %s", got.TrafficResetAnchor.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if got.TrafficResetCount != 0 {
		t.Errorf("cycle index = %d, want 0 for a freshly anchored cycle", got.TrafficResetCount)
	}
	if got.TrafficUsedBytes != 7_000_000 {
		t.Errorf("anchoring discarded usage the subscriber had spent: %d, want 7000000", got.TrafficUsedBytes)
	}
	if got.TrafficPrevCycleBytes != 0 {
		t.Errorf("anchoring recorded %d bytes as a finished period; no period has ended yet",
			got.TrafficPrevCycleBytes)
	}
	// With an anchor in place the first boundary is a whole period away, not immediate.
	next, ok := NextTrafficReset(got)
	if !ok || !next.Equal(utc(2026, time.June, 8, 8)) {
		t.Errorf("first boundary = %s (ok=%v), want 2026-06-08T08:00", next.Format(time.RFC3339), ok)
	}
}

// Everything without a cycle this daemon implements has to come out of the sweep
// byte-for-byte unchanged — including the unknown value, which must not be quietly
// anchored as though it were valid. An operator who mistyped a cycle needs the API's
// rejection to be the only thing that happens.
func TestApplyTrafficCyclesLeavesOtherRecordsAlone(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	seed := []database.Client{
		{
			ID: "plain", UUID: database.GenerateUUID(), Name: "no cycle", Token: "tok-plain",
			Enabled: true, TrafficLimitGB: 5, TrafficUsedBytes: 11,
		},
		{
			ID: "hand-edited", UUID: database.GenerateUUID(), Name: "unknown cycle", Token: "tok-hand",
			Enabled: true, TrafficLimitGB: 5, TrafficUsedBytes: 22, TrafficResetCycle: "yearly",
		},
	}
	for _, c := range seed {
		if err := db.SaveClient(c); err != nil {
			t.Fatalf("SaveClient(%s): %v", c.ID, err)
		}
	}

	clients, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	// Years past any plausible boundary, so a record that can come due has.
	if changed := svc.applyTrafficCycles(clients, utc(2030, time.January, 1, 0)); changed != 0 {
		t.Fatalf("applyTrafficCycles rewrote %d record(s) with no usable cycle", changed)
	}

	for _, want := range seed {
		got, err := db.GetClient(want.ID)
		if err != nil {
			t.Fatalf("GetClient(%s): %v", want.ID, err)
		}
		if got.TrafficUsedBytes != want.TrafficUsedBytes {
			t.Errorf("%s: usage = %d, want %d", want.ID, got.TrafficUsedBytes, want.TrafficUsedBytes)
		}
		if !got.TrafficResetAnchor.IsZero() {
			t.Errorf("%s was given an anchor of %s", want.ID, got.TrafficResetAnchor.Format(time.RFC3339))
		}
		if got.TrafficResetCycle != want.TrafficResetCycle {
			t.Errorf("%s: cycle = %q, want %q", want.ID, got.TrafficResetCycle, want.TrafficResetCycle)
		}
	}
}

// The list the sweep walks was decrypted at the top of the pass. An operator who
// renews an account in that window must not have the renewal overwritten by a
// one-field update carrying every other field's stale value — including the expiry
// that made the account look expired in the first place.
func TestDeactivateExpiredRereadsBeforeWriting(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	now := time.Now()
	if err := db.SaveClient(database.Client{
		ID: "renewed", UUID: database.GenerateUUID(), Name: "renewed mid-sweep", Token: "tok-renewed",
		AllowedIPs: []string{"198.51.100.4"}, Enabled: true,
		CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	// The snapshot the sweep is holding still says "expired an hour ago"...
	stale, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	// ...while the record on disk has since been renewed through the panel.
	if err := svc.RenewClient("renewed", 30); err != nil {
		t.Fatalf("RenewClient: %v", err)
	}

	if changed := svc.deactivateExpired(stale, now); changed != 0 {
		t.Fatalf("deactivateExpired wrote %d record(s) from a stale list", changed)
	}

	got, err := db.GetClient("renewed")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !got.Enabled {
		t.Error("a renewal made during the sweep was overwritten and the subscriber is disabled")
	}
	if !got.ExpiresAt.After(now) {
		t.Errorf("expiry came back as %s, which is not in the future — the stale copy was written back",
			got.ExpiresAt.Format(time.RFC3339))
	}
}

// And the case the sweep exists for: an account that really has run out is disabled
// *and* leaves the resolver's index, so queries from its address stop being answered
// without waiting for an unrelated write to rebuild the cache.
func TestSweepClientsDeindexesAnExpiredAccount(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	const ip = "198.51.100.7"
	now := time.Now()
	// Still valid as the index is built, so the address is genuinely served first.
	if err := db.SaveClient(database.Client{
		ID: "done", UUID: database.GenerateUUID(), Name: "ran out", Token: "tok-done",
		AllowedIPs: []string{ip}, Enabled: true,
		CreatedAt: now.Add(-72 * time.Hour), ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	svc.reloadCache()
	if got := indexedIP(t, svc, ip); got != "done" {
		t.Fatalf("the address maps to %q before the sweep, want done", got)
	}

	// One pass taken an hour after the subscription lapsed.
	svc.sweepClients(now.Add(2 * time.Hour))

	got, err := db.GetClient("done")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.Enabled {
		t.Error("an expired account is still enabled after the sweep")
	}
	if owner := indexedIP(t, svc, ip); owner != "" {
		t.Errorf("the resolver still answers %s for %q; the index was not rebuilt", ip, owner)
	}
}

// UpdateClientRequest carries pointers so that "not sent" and "sent as empty" stay
// distinguishable, and Go 1.26's new(expr) is the shortest honest way to write one.

// Switching a cycle on anchors it at the moment of the request, so the first
// rollover is a whole period away instead of immediate. Re-sending the same cycle as
// part of an unrelated edit must not restart the period, or a subscriber whose note
// happens to be edited every month would never reach a rollover at all.
func TestUpdateClientAnchorsACycleOnlyWhenItChanges(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	if err := db.SaveClient(database.Client{
		ID: "u1", UUID: database.GenerateUUID(), Name: "upgradeable", Token: "tok-u1",
		Enabled: true, CreatedAt: time.Now().Add(-30 * 24 * time.Hour), TrafficLimitGB: 5,
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	before := time.Now()
	got, err := svc.UpdateClient("u1", UpdateClientRequest{TrafficResetCycle: new("Monthly")})
	if err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if got.TrafficResetCycle != TrafficCycleMonthly {
		t.Errorf("stored cycle = %q, want the canonical %q", got.TrafficResetCycle, TrafficCycleMonthly)
	}
	// Anchored at the request, not at CreatedAt: anchoring in the past would make a
	// period that has already elapsed come due on the very next sweep.
	anchor := got.TrafficResetAnchor
	if anchor.Before(before) || anchor.After(time.Now()) {
		t.Errorf("anchor = %s, want the moment of the request", anchor.Format(time.RFC3339Nano))
	}
	if got.TrafficResetCount != 0 {
		t.Errorf("cycle index = %d, want 0", got.TrafficResetCount)
	}

	// An unrelated edit that happens to carry the same cycle.
	again, err := svc.UpdateClient("u1", UpdateClientRequest{
		Note: new("renewed by hand"), TrafficResetCycle: new("monthly"),
	})
	if err != nil {
		t.Fatalf("UpdateClient (unrelated edit): %v", err)
	}
	if !again.TrafficResetAnchor.Equal(anchor) {
		t.Errorf("the anchor moved to %s on an unrelated edit; the period restarted and the subscriber never reaches a rollover",
			again.TrafficResetAnchor.Format(time.RFC3339Nano))
	}
	if again.Note != "renewed by hand" {
		t.Errorf("note = %q, want the edit to have been applied", again.Note)
	}
}

// A mistyped cycle has to be refused and nothing else in the request written, so the
// operator's second attempt starts from a record they still recognise. Reading an
// unknown value as "no cycle" instead would sell a recurring quota that never
// recurs, and the reseller would hear about it from their subscriber.
func TestUpdateClientRejectsAnUnknownCycle(t *testing.T) {
	svc, db, cleanup := setupClientFixture(t)
	defer cleanup()

	if err := db.SaveClient(database.Client{
		ID: "u2", UUID: database.GenerateUUID(), Name: "typo victim", Token: "tok-u2",
		Enabled: true, CreatedAt: time.Now(), Note: "original",
		TrafficResetCycle: TrafficCycleDaily, TrafficResetAnchor: utc(2026, time.February, 2, 6),
		TrafficResetCount: 4,
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	for _, bad := range []string{"yearly", "30d", "none", "MONTHLY!"} {
		got, err := svc.UpdateClient("u2", UpdateClientRequest{
			Note: new("must not be written"), TrafficResetCycle: new(bad),
		})
		if !errors.Is(err, ErrInvalidTrafficCycle) {
			t.Errorf("UpdateClient(cycle=%q) = %v, %v; want ErrInvalidTrafficCycle", bad, got, err)
		}
	}

	stored, err := db.GetClient("u2")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.TrafficResetCycle != TrafficCycleDaily || stored.TrafficResetCount != 4 {
		t.Errorf("the rejected request changed the cycle state: %q count=%d",
			stored.TrafficResetCycle, stored.TrafficResetCount)
	}
	if stored.Note != "original" {
		t.Errorf("the rejected request still wrote the rest of the edit: note = %q", stored.Note)
	}

	// Clearing the cycle is a legitimate value rather than a typo: the account keeps
	// its usage and simply stops resetting.
	cleared, err := svc.UpdateClient("u2", UpdateClientRequest{TrafficResetCycle: new("  ")})
	if err != nil {
		t.Fatalf("UpdateClient (clearing the cycle): %v", err)
	}
	if cleared.TrafficResetCycle != TrafficCycleNone {
		t.Errorf("cycle = %q, want it cleared", cleared.TrafficResetCycle)
	}
	if got, ok := NextTrafficReset(cleared); ok {
		t.Errorf("an account with no cycle reports a reset date of %s", got.Format(time.RFC3339))
	}
}
