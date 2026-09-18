package web

// The diagnostics score is a percentage of reachable game targets, and it is
// printed next to the raw "reachable N/M" count on the same panel. Those two
// numbers are derived from the same pair of integers, so any disagreement
// between them is a bug the operator sees directly: 7 of 8 targets reachable is
// 87.5%, and int() truncates towards zero, so the panel showed "87" beside
// "7/8" — the score claiming a worse result than the count it came from.
//
// Rounding is what makes them agree. This test pins the arithmetic at the
// boundary cases rather than the endpoint, because reaching the real endpoint
// requires eight live TLS dials to third-party game servers.

import (
	"math"
	"testing"
)

// diagnosticsScore mirrors the expression in handleDiagnosticsRun. Kept as a
// separate function on purpose: the handler's copy is one line inside a body
// that also dials sockets, and a test that had to run those dials could not
// assert on arithmetic at all.
func diagnosticsScore(successCount, total int) int {
	if total == 0 {
		return 100
	}
	return int(math.Round((float64(successCount) / float64(total)) * 100))
}

func TestDiagnosticsScoreRoundsInsteadOfTruncating(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ok      int
		total   int
		want    int
		wasWhen int // what plain int() truncation produced, where it differed
	}{
		// The case seen on a live server: one of eight game targets down.
		{"seven of eight", 7, 8, 88, 87},
		{"five of eight", 5, 8, 63, 62},
		{"one of three", 1, 3, 33, 33},
		{"two of three", 2, 3, 67, 66},
		{"one of six", 1, 6, 17, 16},

		// Exact ratios must be untouched by the change.
		{"all reachable", 8, 8, 100, 100},
		{"none reachable", 0, 8, 0, 0},
		{"half", 4, 8, 50, 50},

		// An empty target list is the only division by zero, and it reports 100
		// rather than 0 because "nothing to test" is not "everything failed".
		{"no targets", 0, 0, 100, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := diagnosticsScore(tc.ok, tc.total)
			if got != tc.want {
				t.Errorf("score for %d/%d = %d, want %d", tc.ok, tc.total, got, tc.want)
			}
			if tc.wasWhen != tc.want && got == tc.wasWhen {
				t.Errorf("score for %d/%d is still truncating to %d", tc.ok, tc.total, got)
			}
		})
	}
}

// TestDiagnosticsScoreAgreesWithTheReachableCount is the property the panel
// actually needs: whatever the score is, it must not contradict the N/M the
// panel prints beside it. Checked across every ratio up to a plausible target
// count, since the target list grows as games are added.
func TestDiagnosticsScoreAgreesWithTheReachableCount(t *testing.T) {
	for total := 1; total <= 24; total++ {
		for ok := 0; ok <= total; ok++ {
			score := diagnosticsScore(ok, total)

			if score < 0 || score > 100 {
				t.Fatalf("score for %d/%d is %d, outside 0-100", ok, total, score)
			}
			// Zero reachable must never read as anything but zero, and a full
			// sweep must never read as less than 100 -- those are the two values
			// an operator acts on.
			if ok == 0 && score != 0 {
				t.Errorf("%d/%d scored %d; no reachable target must score 0", ok, total, score)
			}
			if ok == total && score != 100 {
				t.Errorf("%d/%d scored %d; every target reachable must score 100", ok, total, score)
			}
			// The rounded score cannot be more than half a step away from the
			// true ratio; a truncating conversion breaks this for most ratios.
			exact := float64(ok) / float64(total) * 100
			if math.Abs(float64(score)-exact) > 0.5 {
				t.Errorf("score for %d/%d is %d but the ratio is %.2f%%", ok, total, score, exact)
			}
		}
	}
}
