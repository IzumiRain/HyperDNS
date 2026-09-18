package service

import (
	"log"
	"strings"
	"time"

	"hyperdns/internal/database"
)

// The recurring-quota cycles an operator may choose.
//
// A limit with no cycle is spent once and the account is then dead until somebody
// opens the panel and presses reset. That is the difference between a quota an
// operator can *sell* monthly and one they have to *administer* monthly, and with
// a few dozen subscribers it is the difference between a product and a chore.
const (
	TrafficCycleNone    = ""
	TrafficCycleDaily   = "daily"
	TrafficCycleWeekly  = "weekly"
	TrafficCycleMonthly = "monthly"
)

// maxCatchUpCycles bounds the boundary walk in trafficCyclesElapsed.
//
// The walk normally runs once per elapsed period, so a daemon that was off for a
// month takes about thirty steps for a daily cycle. The bound is for the record
// this code cannot rule out: an anchor from a hand-edited or half-imported
// database, far enough in the past that the walk would spin. 100,000 daily steps
// is roughly 274 years, so no honest record reaches it, and a record that does is
// re-anchored to now rather than walked.
const maxCatchUpCycles = 100_000

// NormalizeTrafficCycle canonicalises an operator-supplied cycle name and reports
// whether it is one this daemon implements. Unknown values are refused rather than
// treated as "no cycle": a typo in an API call that silently means *never reset*
// is a quota the reseller thinks is recurring and their subscriber finds is not.
func NormalizeTrafficCycle(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case TrafficCycleNone:
		return TrafficCycleNone, true
	case TrafficCycleDaily:
		return TrafficCycleDaily, true
	case TrafficCycleWeekly:
		return TrafficCycleWeekly, true
	case TrafficCycleMonthly:
		return TrafficCycleMonthly, true
	}
	return "", false
}

// daysInMonth returns the length of one calendar month. Day zero of the following
// month is the last day of this one, which is the only definition that gets
// February right in both a leap year and a century that is not one.
func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// addMonthsClamped advances t by whole calendar months, keeping the day of the
// month where it can and clamping it to the target month's length where it cannot.
//
// time.Time.AddDate is not usable here: it normalises overflow, so January 31st
// plus one month is March 3rd. For a monthly quota that is not a rounding
// difference — it is a boundary that walks forward through the calendar until it
// falls off the end of the year, and a subscriber whose month starts on the 31st
// would be billed for a period that gets longer every time it crosses February.
// Clamping gives the behaviour every subscription service has: the 31st becomes
// the 28th in February and is the 31st again in March.
func addMonthsClamped(t time.Time, months int) time.Time {
	year, month, day := t.Date()
	hour, min, sec := t.Clock()

	// Months since year zero, so a negative count borrows across a year boundary
	// without a special case.
	total := int(month) - 1 + months
	targetYear := year + total/12
	targetMonth := total % 12
	if targetMonth < 0 {
		targetMonth += 12
		targetYear--
	}
	m := time.Month(targetMonth + 1)

	if last := daysInMonth(targetYear, m); day > last {
		day = last
	}
	return time.Date(targetYear, m, day, hour, min, sec, t.Nanosecond(), t.Location())
}

// trafficCycleEnd returns the instant the n-th cycle after anchor ends, i.e. the
// deadline that applies to an account which has already been reset n times.
//
// Every boundary is measured from the fixed anchor rather than from the previous
// boundary. That is what keeps a monthly cycle from drifting: the February
// clamping applies to one boundary and the next is computed from the anchor again,
// so the 31st comes back. It reports false for a cycle name it does not implement,
// which is how a corrupt or hand-edited record ends up simply never resetting
// instead of resetting on every sweep.
//
// Daily and weekly steps are calendar days rather than multiples of 24 hours, so a
// boundary keeps its wall-clock time across a daylight-saving change instead of
// walking an hour each way twice a year.
func trafficCycleEnd(cycle string, anchor time.Time, n uint64) (time.Time, bool) {
	if anchor.IsZero() || n > maxCatchUpCycles {
		return time.Time{}, false
	}
	steps := int(n) + 1
	switch cycle {
	case TrafficCycleDaily:
		return anchor.AddDate(0, 0, steps), true
	case TrafficCycleWeekly:
		return anchor.AddDate(0, 0, 7*steps), true
	case TrafficCycleMonthly:
		return addMonthsClamped(anchor, steps), true
	}
	return time.Time{}, false
}

// dueTrafficResets counts the cycle boundaries that have passed for an account
// already reset count times, as of now.
//
// It returns a count rather than a boolean because a daemon that was off for three
// months has to end up on the *current* cycle, not merely one cycle further on:
// leaving the counter behind would put the next boundary in the past, and the
// account would then be reset on every sweep for as long as it took to catch up.
// The usage itself is zeroed once regardless of how many boundaries are being
// crossed — the subscriber gets their allowance back, not one allowance per month
// the server was down.
func dueTrafficResets(cycle string, anchor time.Time, count uint64, now time.Time) uint64 {
	var elapsed uint64
	for elapsed < maxCatchUpCycles {
		end, ok := trafficCycleEnd(cycle, anchor, count+elapsed)
		if !ok || now.Before(end) {
			break
		}
		elapsed++
	}
	return elapsed
}

// NextTrafficReset reports when an account's allowance comes back, for the panel
// and the subscriber portal to show. The second return is false when there is no
// cycle, which the caller has to render as "does not reset" rather than as a date.
func NextTrafficReset(c *database.Client) (time.Time, bool) {
	if c == nil {
		return time.Time{}, false
	}
	cycle, ok := NormalizeTrafficCycle(c.TrafficResetCycle)
	if !ok || cycle == TrafficCycleNone {
		return time.Time{}, false
	}
	return trafficCycleEnd(cycle, c.TrafficResetAnchor, c.TrafficResetCount)
}

// applyTrafficCycles rolls over every account whose quota period has ended and
// reports how many records it rewrote, so the caller can rebuild the resolver's
// index once rather than once per account.
//
// The whole pass runs under flushMu. Nothing here is expensive when no account is
// due — it is arithmetic over a list the caller already holds — and the alternative
// is to detect dueness first and lock second, which leaves a window in which a
// flush writes pre-rollover bytes on top of the zero this pass is about to write.
func (s *ClientService) applyTrafficCycles(clients []database.Client, now time.Time) int {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	changed := 0
	for i := range clients {
		cycle, valid := NormalizeTrafficCycle(clients[i].TrafficResetCycle)
		if !valid || cycle == TrafficCycleNone {
			continue
		}
		id := clients[i].ID
		anchor := clients[i].TrafficResetAnchor
		count := clients[i].TrafficResetCount

		// An anchor is written the moment a cycle is set, so a record without one
		// arrived some other way: imported, hand-edited, restored from a partial
		// backup. Anchoring at now rather than at CreatedAt means switching a cycle on
		// can never retroactively discard usage a subscriber has already paid for.
		if anchor.IsZero() {
			if s.anchorTrafficCycle(id, now) {
				changed++
			}
			continue
		}

		elapsed := dueTrafficResets(cycle, anchor, count, now)
		if elapsed == 0 {
			continue
		}
		// The postcondition, checked rather than assumed: after crediting elapsed
		// periods the next boundary has to be in the future. If it is not, the walk
		// was cut short by its own bound and the anchor cannot be used. Re-anchoring
		// is self-healing and costs the subscriber nothing beyond the current period.
		if end, ok := trafficCycleEnd(cycle, anchor, count+elapsed); !ok || !now.Before(end) {
			log.Printf("[ClientService] Traffic cycle of %s has an unusable anchor (%s); re-anchoring to now",
				id, anchor.Format(time.RFC3339))
			if s.anchorTrafficCycle(id, now) {
				changed++
			}
			continue
		}
		if s.resetTrafficCycle(id, count+elapsed) {
			changed++
		}
	}
	return changed
}

// anchorTrafficCycle fixes a cycle's origin at now and starts counting from zero.
// Callers hold flushMu.
func (s *ClientService) anchorTrafficCycle(id string, now time.Time) bool {
	client, err := s.db.GetClient(id)
	if err != nil || client == nil {
		return false
	}
	client.TrafficResetAnchor = now
	client.TrafficResetCount = 0
	if err := s.db.SaveClient(*client); err != nil {
		log.Printf("[ClientService] Could not anchor the traffic cycle of %s: %v", id, err)
		return false
	}
	return true
}

// resetTrafficCycle returns an account's usage to zero, records what the period
// that just ended consumed, and advances the cycle index. Callers hold flushMu.
//
// When more than one boundary is being crossed at once — a daemon that was off for
// a while — the recorded figure is the usage of the last period that actually saw
// traffic rather than of the period immediately before now. There is no history to
// attribute it to a particular month, and the alternative is to discard it.
func (s *ClientService) resetTrafficCycle(id string, newCount uint64) bool {
	// Taken, not merely cleared: the swap is atomic, so bytes a relay adds after
	// this point belong to the new period and every byte added before it is counted
	// in the old one. Clearing and reading separately would lose whatever landed in
	// between.
	pending := s.traffic.take(id)

	// Re-read rather than reusing the listed copy. An operator may have raised the
	// limit or renamed the account since the list was taken, and writing a stale
	// record back to change one field would silently undo that.
	client, err := s.db.GetClient(id)
	if err != nil || client == nil {
		// The bytes have already left the ledger. Hand them back so a transient read
		// failure cannot make traffic free; if the account is genuinely gone, the next
		// flush drops them, which is what it already does for a deleted account.
		s.traffic.add(id, pending)
		return false
	}

	client.TrafficPrevCycleBytes = client.TrafficUsedBytes + pending
	client.TrafficUsedBytes = 0
	client.TrafficResetCount = newCount
	if err := s.db.SaveClient(*client); err != nil {
		s.traffic.add(id, pending)
		log.Printf("[ClientService] Could not roll over the traffic cycle of %s: %v", id, err)
		return false
	}

	log.Printf("[ClientService] Quota period rolled over for %s (%s): %d bytes used in the period that ended",
		client.Name, id, client.TrafficPrevCycleBytes)
	return true
}
