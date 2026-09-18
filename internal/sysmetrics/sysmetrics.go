// Package sysmetrics reports machine-wide CPU and memory utilization by
// reading /proc directly (Linux). Zero dependencies, no goroutines: CPU
// percent is the delta between successive calls, so callers that poll
// (the dashboard's stats endpoint, the TUI menu redraw) get a real
// utilization figure, and a single cold call gets the delta since the
// previous caller — good enough for a headline number.
//
// On non-Linux platforms (a Windows dev box) /proc does not exist and every
// function returns the negative "unavailable" sentinel; callers render a dash
// rather than a made-up number.
package sysmetrics

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Unavailable is returned by every function when the platform cannot answer
// (anything but Linux). Callers test for it with < 0.
const Unavailable = -1.0

var (
	mu       sync.Mutex
	lastStat []byte    // raw /proc/stat first line from the previous call
	lastTime time.Time // when it was read
)

// CPUPercent returns machine-wide CPU utilization (0-100) as the busy-time
// delta between this call and the previous one. The first call establishes
// the baseline and returns 0 — the dashboard polls every few seconds, so a
// cold first frame costs nothing. Unavailable off Linux.
func CPUPercent() float64 {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return Unavailable
	}
	// First line: cpu  user nice system idle iowait irq softirq steal ...
	line := ""
	for _, l := range strings.SplitN(string(raw), "\n", 2) {
		if strings.HasPrefix(l, "cpu ") {
			line = l
			break
		}
	}
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Unavailable
	}
	var vals [10]uint64
	for i := 1; i < len(fields) && i <= len(vals); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return Unavailable // a malformed counter is garbage, not zero
		}
		vals[i-1] = v
	}
	idle := vals[3] + vals[4] // idle + iowait
	total := uint64(0)
	for _, v := range vals {
		total += v
	}

	now := time.Now()
	mu.Lock()
	prevStat, prevTime := lastStat, lastTime
	lastStat = []byte(line)
	lastTime = now
	mu.Unlock()

	if prevStat == nil || now.Sub(prevTime) <= 0 {
		return 0 // baseline call
	}
	prevFields := strings.Fields(string(prevStat))
	if len(prevFields) < 5 {
		return Unavailable
	}
	var pvals [10]uint64
	for i := 1; i < len(prevFields) && i <= len(pvals); i++ {
		v, err := strconv.ParseUint(prevFields[i], 10, 64)
		if err != nil {
			return Unavailable
		}
		pvals[i-1] = v
	}
	pIdle := pvals[3] + pvals[4]
	pTotal := uint64(0)
	for _, v := range pvals {
		pTotal += v
	}

	// The counters must move forward. On some virtualized setups (lxcfs and
	// friends) /proc/stat resets while the daemon keeps running; an unsigned
	// wrap would otherwise turn into a huge delta and a confidently wrong
	// headline number. Re-baseline instead and report nothing for this frame.
	if total < pTotal || idle < pIdle {
		return Unavailable
	}
	dTotal := total - pTotal
	dIdle := idle - pIdle
	if dTotal == 0 {
		return 0
	}
	pct := 100 * float64(dTotal-dIdle) / float64(dTotal)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

// Memory returns system memory as (usedMB, totalMB, usedPercent), computed
// from /proc/meminfo the way free(1) does: used = MemTotal - MemAvailable
// (available is what the kernel can hand out without swapping, which is the
// honest "how full is this box" number on a server with page cache). All
// three are Unavailable off Linux.
func Memory() (usedMB, totalMB, usedPct float64) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return Unavailable, Unavailable, Unavailable
	}
	var totalKB, availKB uint64
	found := 0
	for _, l := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(l, "MemTotal:"):
			v, err := strconv.ParseUint(trimColonField(l), 10, 64)
			if err != nil {
				return Unavailable, Unavailable, Unavailable
			}
			totalKB = v
			found++
		case strings.HasPrefix(l, "MemAvailable:"):
			v, err := strconv.ParseUint(trimColonField(l), 10, 64)
			if err != nil {
				return Unavailable, Unavailable, Unavailable
			}
			availKB = v
			found++
		}
		if found == 2 {
			break
		}
	}
	if found < 2 || totalKB == 0 {
		return Unavailable, Unavailable, Unavailable
	}
	totalMB = float64(totalKB) / 1024
	usedMB = float64(totalKB-availKB) / 1024
	if totalMB > 0 {
		usedPct = 100 * usedMB / totalMB
	}
	return usedMB, totalMB, usedPct
}

// trimColonField extracts the numeric value from a /proc/meminfo line such as
// "MemTotal:       16305240 kB".
func trimColonField(l string) string {
	_, rest, ok := strings.Cut(l, ":")
	if !ok {
		return ""
	}
	rest = strings.TrimSpace(rest)
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = rest[:i]
	}
	return rest
}
