package service

import "sync/atomic"

// BenchmarkRunner provides one asynchronous benchmark gate shared by the web
// panel and the root-local control plane.
type BenchmarkRunner struct {
	run     func()
	running atomic.Bool
}

func NewBenchmarkRunner(run func()) *BenchmarkRunner {
	return &BenchmarkRunner{run: run}
}

func (b *BenchmarkRunner) Start() bool {
	if b == nil || b.run == nil || !b.running.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer b.running.Store(false)
		b.run()
	}()
	return true
}

func (b *BenchmarkRunner) Running() bool {
	return b != nil && b.running.Load()
}
