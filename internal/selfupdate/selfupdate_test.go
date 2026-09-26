package selfupdate

import "testing"

// compareSemver decides whether the dashboard offers an update, so a wrong
// verdict here either nags on every load or hides a real release. These pin the
// numeric-core comparison and the suffix-stripping behaviour.
func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign: >0 a newer, 0 equal, <0 a older
	}{
		{"2.6.0", "2.5.0", 1},
		{"2.5.0", "2.6.0", -1},
		{"2.5.0", "2.5.0", 0},
		{"2.5.1", "2.5.0", 1},
		{"2.10.0", "2.9.0", 1}, // numeric, not lexical
		{"3.0.0", "2.99.99", 1},
		{"v2.6.0", "2.5.0", 1},          // leading v tolerated
		{"2.6.0-beta", "2.5.0", 1},      // suffix ignored on the core compare
		{"2.5.0-beta.2", "2.5.0-beta.1", 0}, // suffix not compared -> equal cores
		{"2.5", "2.5.0", 0},             // missing field reads as zero
	}
	for _, c := range cases {
		got := compareSemver(c.a, c.b)
		if (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) || (got == 0) != (c.want == 0) {
			t.Errorf("compareSemver(%q,%q)=%d, want sign of %d", c.a, c.b, got, c.want)
		}
	}
}
