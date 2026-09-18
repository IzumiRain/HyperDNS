//go:build !windows

package service

import (
	"os"
	"strconv"
	"strings"
)

// processCPUSeconds returns total user+system CPU seconds consumed by the
// current process (Unix implementation via /proc/self/stat).
func processCPUSeconds() (float64, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	// Format: pid (comm) state ppid ... utime(14) stime(15) ...
	// comm can contain spaces, so parse after the last ')'.
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0, os.ErrInvalid
	}
	fields := strings.Fields(s[idx+2:])
	// After ')': field 3 (state) is index 0, so utime = index 11, stime = index 12.
	if len(fields) < 13 {
		return 0, os.ErrInvalid
	}
	utime, err1 := strconv.ParseFloat(fields[11], 64)
	stime, err2 := strconv.ParseFloat(fields[12], 64)
	if err1 != nil || err2 != nil {
		return 0, os.ErrInvalid
	}
	// Clock ticks are typically 100/s; use os.Getpagesize-free standard CLK_TCK assumption.
	return (utime + stime) / 100.0, nil
}
