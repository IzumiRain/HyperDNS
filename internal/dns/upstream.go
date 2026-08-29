package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type UpstreamStat struct {
	Address     string        `json:"address"`
	Latency     time.Duration `json:"latency"`
	SuccessRate float64       `json:"success_rate"`
	TotalHits   uint64        `json:"total_hits"`
	TotalErrors uint64        `json:"total_errors"`
	LastCheck   time.Time     `json:"last_check"`
}

type UpstreamPool struct {
	mu           sync.RWMutex
	upstreams    []string
	timeout      time.Duration
	client       *dns.Client
	racing       bool
	ecsClientIP  net.IP
	stats        map[string]*upstreamStatInternal
}

type upstreamStatInternal struct {
	mu          sync.Mutex
	avgLatency  time.Duration
	hits        uint64
	errors      uint64
	lastUpdated time.Time
}

func NewUpstreamPool(upstreams []string, timeout time.Duration, racing bool, ecsIP string) *UpstreamPool {
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}

	var parsedECS net.IP
	if ecsIP != "" {
		parsedECS = net.ParseIP(ecsIP)
	}

	pool := &UpstreamPool{
		upstreams:   upstreams,
		timeout:     timeout,
		racing:      racing,
		ecsClientIP: parsedECS,
		stats:       make(map[string]*upstreamStatInternal),
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
	}

	for _, u := range upstreams {
		pool.stats[u] = &upstreamStatInternal{
			avgLatency:  12 * time.Millisecond,
			lastUpdated: time.Now(),
		}
	}

	// Trigger immediate benchmark on all upstreams
	go pool.BenchmarkAll()

	return pool
}

func (p *UpstreamPool) BenchmarkAll() {
	m := new(dns.Msg)
	m.SetQuestion("cloudflare.com.", dns.TypeA)

	p.mu.RLock()
	servers := make([]string, len(p.upstreams))
	copy(servers, p.upstreams)
	p.mu.RUnlock()

	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
			start := time.Now()
			_, _, err := client.Exchange(m, addr)
			dur := time.Since(start)
			if err == nil {
				p.recordStat(addr, dur, true)
			} else {
				p.recordStat(addr, dur, false)
			}
		}(s)
	}
	wg.Wait()
}

func (p *UpstreamPool) SetUpstreams(upstreams []string) {
	p.mu.Lock()
	p.upstreams = upstreams
	for _, u := range upstreams {
		if _, ok := p.stats[u]; !ok {
			p.stats[u] = &upstreamStatInternal{
				avgLatency:  12 * time.Millisecond,
				lastUpdated: time.Now(),
			}
		}
	}
	p.mu.Unlock()
	go p.BenchmarkAll()
}

// Exchange queries upstreams according to racing or sequential mode
func (p *UpstreamPool) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, string, error) {
	p.mu.RLock()
	upstreams := make([]string, len(p.upstreams))
	copy(upstreams, p.upstreams)
	racing := p.racing
	timeout := p.timeout
	p.mu.RUnlock()

	if len(upstreams) == 0 {
		return nil, 0, "", errors.New("no upstream resolvers configured")
	}

	// Attach ECS if configured
	queryMsg := req.Copy()
	if p.ecsClientIP != nil {
		p.attachECS(queryMsg, p.ecsClientIP)
	}

	if racing && len(upstreams) > 1 {
		return p.exchangeRacing(queryMsg, upstreams, timeout)
	}

	return p.exchangeSequential(queryMsg, upstreams, timeout)
}

func (p *UpstreamPool) exchangeRacing(req *dns.Msg, upstreams []string, timeout time.Duration) (*dns.Msg, time.Duration, string, error) {
	type result struct {
		resp     *dns.Msg
		duration time.Duration
		upstream string
		err      error
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resChan := make(chan result, len(upstreams))

	for _, u := range upstreams {
		go func(addr string) {
			start := time.Now()
			client := &dns.Client{
				Net:     "udp",
				Timeout: timeout,
			}
			
			resp, rtt, err := client.ExchangeContext(ctx, req, addr)
			if err != nil {
				// Retry with TCP if truncated
				if resp != nil && resp.Truncated {
					client.Net = "tcp"
					resp, rtt, err = client.ExchangeContext(ctx, req, addr)
				}
			}

			dur := time.Since(start)
			if err == nil && resp != nil {
				p.recordStat(addr, dur, true)
				select {
				case resChan <- result{resp: resp, duration: rtt, upstream: addr, err: nil}:
				case <-ctx.Done():
				}
			} else {
				p.recordStat(addr, dur, false)
				select {
				case resChan <- result{resp: nil, duration: dur, upstream: addr, err: err}:
				case <-ctx.Done():
				}
			}
		}(u)
	}

	var lastErr error
	for i := 0; i < len(upstreams); i++ {
		select {
		case res := <-resChan:
			if res.err == nil && res.resp != nil {
				cancel()
				return res.resp, res.duration, res.upstream, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			if lastErr != nil {
				return nil, 0, "", lastErr
			}
			return nil, 0, "", errors.New("upstream query timed out")
		}
	}

	if lastErr != nil {
		return nil, 0, "", lastErr
	}
	return nil, 0, "", errors.New("all upstream servers failed to respond")
}

func (p *UpstreamPool) exchangeSequential(req *dns.Msg, upstreams []string, timeout time.Duration) (*dns.Msg, time.Duration, string, error) {
	var lastErr error
	for _, u := range upstreams {
		client := &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		}
		start := time.Now()
		resp, rtt, err := client.Exchange(req, u)
		dur := time.Since(start)
		if err == nil && resp != nil {
			if resp.Truncated {
				client.Net = "tcp"
				resp, rtt, err = client.Exchange(req, u)
			}
			if err == nil && resp != nil {
				p.recordStat(u, dur, true)
				return resp, rtt, u, nil
			}
		}
		p.recordStat(u, dur, false)
		lastErr = err
	}
	return nil, 0, "", lastErr
}

func (p *UpstreamPool) recordStat(addr string, rtt time.Duration, success bool) {
	p.mu.RLock()
	stat, ok := p.stats[addr]
	p.mu.RUnlock()

	if !ok {
		return
	}

	stat.mu.Lock()
	defer stat.mu.Unlock()

	if success {
		stat.hits++
		if stat.avgLatency == 0 {
			stat.avgLatency = rtt
		} else {
			stat.avgLatency = (stat.avgLatency*4 + rtt) / 5
		}
	} else {
		stat.errors++
	}
	stat.lastUpdated = time.Now()
}

func (p *UpstreamPool) GetStats() []UpstreamStat {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]UpstreamStat, 0, len(p.stats))
	for addr, st := range p.stats {
		st.mu.Lock()
		hits := atomic.LoadUint64(&st.hits)
		errs := atomic.LoadUint64(&st.errors)
		total := hits + errs
		rate := 100.0
		if total > 0 {
			rate = (float64(hits) / float64(total)) * 100.0
		}

		out = append(out, UpstreamStat{
			Address:     addr,
			Latency:     st.avgLatency,
			SuccessRate: rate,
			TotalHits:   hits,
			TotalErrors: errs,
			LastCheck:   st.lastUpdated,
		})
		st.mu.Unlock()
	}
	return out
}

func (p *UpstreamPool) attachECS(msg *dns.Msg, ip net.IP) {
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, false)
		opt = msg.IsEdns0()
	}

	var subnet *dns.EDNS0_SUBNET
	if ip.To4() != nil {
		subnet = &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: 24,
			SourceScope:   0,
			Address:       ip.To4(),
		}
	} else {
		subnet = &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        2,
			SourceNetmask: 56,
			SourceScope:   0,
			Address:       ip.To16(),
		}
	}

	// Remove existing ECS if any
	filtered := make([]dns.EDNS0, 0, len(opt.Option))
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0SUBNET {
			filtered = append(filtered, o)
		}
	}
	filtered = append(filtered, subnet)
	opt.Option = filtered
}
