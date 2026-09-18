package integration

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"hyperdns/internal/core/cache"
	resolver "hyperdns/internal/core/dns"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
)

// These two assertions are the cheapest lines in the package and half the reason it
// exists. NewHandler takes AccessProvider as an interface and picks QuotaEnforcer up
// by type assertion, so a ClientService that stopped satisfying the second one would
// still compile, still run, and silently stop enforcing every traffic limit the
// operator had sold.
var (
	_ resolver.AccessProvider = (*service.ClientService)(nil)
	_ resolver.QuotaEnforcer  = (*service.ClientService)(nil)
)

const (
	// testPublicIP is the address the resolver claims as its own, which is what
	// makes a proxied answer identifiable with no network involved.
	testPublicIP = "198.51.100.1"

	// proxiedName is routed through the relay by the default presets, so the
	// handler answers it locally from testPublicIP. internal/core/dns's own tests
	// rest on the same property.
	proxiedName = "playvalorant.com."

	// unselectedName belongs to a different preset, so it is relayed for an account
	// with no policy selection and must not be for one that bought only Riot.
	unselectedName = "discord.com."

	subscriberIP = "203.0.113.10"
	strangerIP   = "203.0.113.77"

	// gib is the unit the service converts TrafficLimitGB into.
	gib = 1 << 30
)

// recorder is the handler's telemetry sink. It is what lets these tests assert on
// the identity behind a query: the response carries an address, never the account
// the resolver attributed it to, so without the log a test cannot tell a subscriber
// being recognised apart from an anonymous visitor being served the same answer.
type recorder struct {
	mu      sync.Mutex
	entries []database.QueryLogItem
	queries int
}

func (r *recorder) PushQueryLog(item database.QueryLogItem) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, item)
}

func (r *recorder) RecordQuery() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries++
}

func (r *recorder) last(t *testing.T) database.QueryLogItem {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		t.Fatal("the handler logged nothing at all, so there is no decision to inspect")
	}
	return r.entries[len(r.entries)-1]
}

// counts returns the number of queries counted and the number logged. They are
// separate numbers on purpose: the counter feeds the dashboard's queries-per-second
// figure and is incremented for every query including the refused ones, while the log
// is written only where the handler has something to say.
func (r *recorder) counts() (counted, logged int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queries, len(r.entries)
}

// fixture is one daemon: a real database, the real ClientService, and the real
// resolver handler pointed at it. Each test builds its own, because bbolt takes an
// exclusive lock on its file and because -shuffle=on forbids shared state.
type fixture struct {
	svc *service.ClientService
	dns *resolver.Handler
	log *recorder
}

func newFixture(t *testing.T, allowAll bool) *fixture {
	t.Helper()

	dir := t.TempDir()
	cipher, err := crypto.LoadOrGenerateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateMasterKey: %v", err)
	}
	db, err := database.Open(filepath.Join(dir, "data.db"), cipher)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	svc := service.NewClientService(db, allowAll)
	sink := &recorder{}

	// 127.0.0.1:1 is deliberately dead. Every case below has to be decided before
	// the resolver reaches an upstream, so a change that starts depending on one
	// fails here rather than quietly querying the public internet from CI — and the
	// pool's constructor benchmarks its upstreams in a goroutine, which is the other
	// reason the address must go nowhere.
	pool := upstream.NewUpstreamPool([]string{"127.0.0.1:1"}, 200*time.Millisecond, false, "")

	dnsCache := cache.NewCache(1000, 60, 3600)
	t.Cleanup(dnsCache.Close)

	return &fixture{
		svc: svc,
		dns: resolver.NewHandler(svc, dnsCache, matcher.NewMatcher(), pool, sink, testPublicIP),
		log: sink,
	}
}

// provision creates a subscriber exactly the way the dashboard and the REST API do.
func (f *fixture) provision(t *testing.T, req service.CreateClientRequest) *database.Client {
	t.Helper()
	c, err := f.svc.ProvisionClient(req)
	if err != nil {
		t.Fatalf("ProvisionClient(%+v): %v", req, err)
	}
	return c
}

// resolve asks the handler for proxiedName as clientIP would.
func (f *fixture) resolve(t *testing.T, clientIP string) *dns.Msg {
	t.Helper()
	return f.resolveName(t, clientIP, proxiedName)
}

func (f *fixture) resolveName(t *testing.T, clientIP, name string) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	resp := f.dns.ProcessQuery(req, clientIP, "UDP")
	if resp == nil {
		t.Fatalf("ProcessQuery returned no response at all for %s from %s", name, clientIP)
	}
	return resp
}

// wantServed asserts the query came back pointing at this server, which is what
// sends the client into the SNI relay and is therefore what "the subscriber's
// service works" looks like from the wire.
func wantServed(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode is %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("%s came back with no answer section", proxiedName)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want an A record", resp.Answer[0])
	}
	if got := a.A.String(); got != testPublicIP {
		t.Fatalf("answer is %s, want the relay at %s", got, testPublicIP)
	}
}

func wantRefused(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode is %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

// A provisioned address has to be recognised by the resolver on its first query. The
// account name is asserted rather than only the answer, because with allow_all off a
// stranger is refused and with it on a stranger gets the same answer as a subscriber
// — the log is the only place the two are distinguishable.
func TestProvisionedSubscriberIsRecognisedByTheResolver(t *testing.T) {
	f := newFixture(t, false)
	c := f.provision(t, service.CreateClientRequest{Name: "Reseller Customer", Days: 30, IP: subscriberIP})

	wantServed(t, f.resolve(t, subscriberIP))

	if got := f.log.last(t).AccountName; got != c.Name {
		t.Errorf("the query was attributed to %q, want %q: the resolver did not map the "+
			"address back to the account that owns it", got, c.Name)
	}
	if counted, _ := f.log.counts(); counted != 1 {
		t.Errorf("the resolver counted %d queries, want 1 — this is the number the dashboard's "+
			"queries-per-second figure is derived from", counted)
	}
}

func TestUnknownAddressIsRefusedWhenAllowAllIsOff(t *testing.T) {
	f := newFixture(t, false)
	f.provision(t, service.CreateClientRequest{Name: "Reseller Customer", Days: 30, IP: subscriberIP})

	wantRefused(t, f.resolve(t, strangerIP))

	// The refusal is deliberately silent: an open resolver being scanned would otherwise
	// fill the query log, and fan every packet of the scan out to every dashboard
	// watching the live stream. It is still counted, so the traffic remains visible.
	counted, logged := f.log.counts()
	if counted != 1 {
		t.Errorf("a refused query was counted %d times, want 1", counted)
	}
	if logged != 0 {
		t.Errorf("a refused stranger produced %d log entries, want 0: every unauthorised "+
			"packet becoming a log write and an SSE broadcast is the amplification the silent "+
			"refusal exists to avoid", logged)
	}
}

// Expiry is enforced by leaving the address out of the resolver's index, not by a
// check on the query path. That is worth an end-to-end test precisely because the two
// halves are so far apart: nothing in the handler mentions expiry at all.
func TestExpiredSubscriberIsRefusedWhenAllowAllIsOff(t *testing.T) {
	f := newFixture(t, false)
	c := f.provision(t, service.CreateClientRequest{Name: "Lapsing Customer", Days: 30, IP: subscriberIP})

	// Served first, so the refusal below is demonstrably the expiry and not a fixture
	// that never worked.
	wantServed(t, f.resolve(t, subscriberIP))

	past := time.Now().Add(-time.Hour)
	if _, err := f.svc.UpdateClient(c.ID, service.UpdateClientRequest{ExpiresAt: &past}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	wantRefused(t, f.resolve(t, subscriberIP))
}

// Disabling is the same mechanism as expiry and the operator's manual equivalent of
// it, so it is pinned separately: the two conditions sit on adjacent lines of
// indexLocked and a refactor can easily keep one and lose the other.
func TestDisabledSubscriberIsRefusedWhenAllowAllIsOff(t *testing.T) {
	f := newFixture(t, false)
	c := f.provision(t, service.CreateClientRequest{Name: "Suspended Customer", Days: 30, IP: subscriberIP})

	wantServed(t, f.resolve(t, subscriberIP))

	if _, err := f.svc.ToggleClient(c.ID, false); err != nil {
		t.Fatalf("ToggleClient: %v", err)
	}
	wantRefused(t, f.resolve(t, subscriberIP))
}

// The quota check is the one refusal that runs on the query path, and the only one
// that logs. Two properties matter to a reseller and neither is visible from either
// package alone: that the limit sold through ProvisionClient is the limit the resolver
// enforces, and that it bites against the in-memory ledger — an account that burns its
// allowance is cut off in the same second, not at the next thirty-second flush.
func TestExhaustedQuotaIsRefusedAndLogged(t *testing.T) {
	f := newFixture(t, false)
	c := f.provision(t, service.CreateClientRequest{
		Name:           "Metered Customer",
		Days:           30,
		IP:             subscriberIP,
		TrafficLimitGB: 1,
	})

	wantServed(t, f.resolve(t, subscriberIP))

	f.svc.AddTraffic(c.ID, 2*gib)

	wantRefused(t, f.resolve(t, subscriberIP))
	entry := f.log.last(t)
	if entry.Action != "QUOTA" {
		t.Errorf("the refusal was logged as %q, want %q: the panel filters on this string, "+
			"so an operator answering \"why did it stop working\" cannot see the reason", entry.Action, "QUOTA")
	}
	if entry.AccountName != c.Name {
		t.Errorf("the refusal was logged against %q, want %q", entry.AccountName, c.Name)
	}
}

// The reseller's self-service link: an account is sold with no address, the subscriber
// opens /ip/{token}, and their address has to work on the very next query. That path
// re-files one account into the index instead of rebuilding the whole thing, which is
// exactly the kind of optimisation that can silently index nothing.
func TestPortalRegistrationReachesTheResolverImmediately(t *testing.T) {
	f := newFixture(t, false)
	c := f.provision(t, service.CreateClientRequest{Name: "Dynamic Address Customer", Days: 30})

	// Sold but unbound, so there is nothing to recognise yet.
	wantRefused(t, f.resolve(t, subscriberIP))

	cSecret := c.RegisterSecret
	if _, existed, err := f.svc.RegisterIP(c.Token, cSecret, subscriberIP); err != nil {
		t.Fatalf("RegisterIP: %v", err)
	} else if existed {
		t.Error("RegisterIP reports the address was already on the account, which it was not")
	}

	wantServed(t, f.resolve(t, subscriberIP))
	if got := f.log.last(t).AccountName; got != c.Name {
		t.Errorf("the query was attributed to %q, want %q: the single-account re-index did "+
			"not put the new address anywhere the resolver looks", got, c.Name)
	}
}

// allow_all defaults to true, which makes the daemon an open resolver: a personal
// install serves the household without anyone provisioning anything. The account name
// is the assertion, because the answer is identical either way.
func TestAllowAllServesAnUnknownAddressAsPublic(t *testing.T) {
	f := newFixture(t, true)

	wantServed(t, f.resolve(t, strangerIP))

	if got := f.log.last(t).AccountName; got != "Public" {
		t.Errorf("an unprovisioned address was attributed to %q, want %q", got, "Public")
	}
}

// The consequence of the two mechanisms meeting, pinned because it is genuinely
// surprising and a reseller has to know it: expiry works by dropping the address from
// the index, allow_all serves an unindexed address as anonymous "Public", and "Public"
// has no allowance to exceed. So under allow_all, expiring an account that is over its
// quota gives its service back.
//
// This is coherent for the setting's purpose — allow_all means "serve everyone", and
// the resolver has no grounds to keep refusing an address an ISP may have already
// reassigned — but it is not what "expired" reads like. Anyone selling access has to
// run with allow_all off, and the README says so. If that ever changes, this test is
// the record of what the old behaviour was.
func TestAllowAllStopsEnforcingQuotaOnceTheAccountExpires(t *testing.T) {
	f := newFixture(t, true)
	c := f.provision(t, service.CreateClientRequest{
		Name:           "Metered Customer",
		Days:           30,
		IP:             subscriberIP,
		TrafficLimitGB: 1,
	})
	f.svc.AddTraffic(c.ID, 2*gib)

	// While the account is live its quota is enforced even with allow_all on: being
	// known to the resolver is what makes a limit applicable at all.
	wantRefused(t, f.resolve(t, subscriberIP))

	past := time.Now().Add(-time.Hour)
	if _, err := f.svc.UpdateClient(c.ID, service.UpdateClientRequest{ExpiresAt: &past}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	wantServed(t, f.resolve(t, subscriberIP))
	if got := f.log.last(t).AccountName; got != "Public" {
		t.Errorf("the expired account resolves as %q, want %q — if this now fails because the "+
			"query was refused, the behaviour was tightened on purpose and this test should be "+
			"replaced rather than repaired", got, "Public")
	}
}

// Per-client policies are how one plan is sold with Riot and another with everything:
// a non-empty selection narrows the presets that apply to that account. The list is
// stored inside the encrypted client record, which makes it exactly the sort of field
// that can be lost in the round trip without anything looking broken — an account whose
// policies came back empty is relayed *every* preset, which reads as a working
// subscriber rather than as a bug.
func TestPerClientPoliciesNarrowWhatIsRelayedForThatAccount(t *testing.T) {
	f := newFixture(t, false)
	c := f.provision(t, service.CreateClientRequest{
		Name:           "Riot Only Plan",
		Days:           30,
		IP:             subscriberIP,
		CustomPolicies: []string{"enable_riot"},
	})
	if len(c.CustomPolicies) != 1 {
		t.Fatalf("the account was stored with policies %v, want one entry", c.CustomPolicies)
	}

	// The preset the plan includes.
	wantServed(t, f.resolve(t, subscriberIP))
	if got := f.log.last(t).Action; got != "PROXY" {
		t.Fatalf("the query for %s was logged as %q, want PROXY", proxiedName, got)
	}

	// One it does not. The answer itself cannot be asserted — an unselected name falls
	// through to DIRECT, which here means the deliberately dead upstream — so the
	// assertion is that the relay's own address is not what came back.
	for _, rr := range f.resolveName(t, subscriberIP, unselectedName).Answer {
		a, ok := rr.(*dns.A)
		if ok && a.A.String() == testPublicIP {
			t.Errorf("%s was relayed for an account whose plan is %v, so the policy list did "+
				"not survive storage and the account is being given every preset",
				unselectedName, c.CustomPolicies)
		}
	}
}
