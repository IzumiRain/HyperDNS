package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"hyperdns/internal/database"
)

// ErrInvalidIP reports an address that an operator typed or pasted and that is not
// an IP at all. It is a sentinel so a handler can answer 400 rather than 500: bad
// input is not a server fault, and a 500 tells the dashboard to say "the server
// failed" when the honest answer is "that is not an address".
var ErrInvalidIP = errors.New("invalid IP address")

// ErrDuplicateIPConflict is database.ErrDuplicateIPConflict re-exported: the
// portal API answers it with 409 and never deactivates either account (C-04).
var ErrDuplicateIPConflict = database.ErrDuplicateIPConflict

// ErrInvalidTrafficCycle reports a quota cycle this daemon does not implement. It
// is a sentinel for the same reason ErrInvalidIP is: a rejected value the operator
// typed is a 400, and silently reading an unknown cycle as "never reset" would sell
// a recurring quota that never recurs.
var ErrInvalidTrafficCycle = errors.New("invalid traffic reset cycle")

// normalizeAllowedIP validates an operator-supplied address and returns it in the
// one form the resolver can actually match.
//
// Access control here is a string lookup, not an address comparison: indexLocked
// keys ipMap by this exact value and IsIPAllowed looks up the address the listener
// reports, which is always Go's canonical net.IP.String() form. Anything stored in
// another form silently whitelists nobody — and until now nothing checked, so
// " 203.0.113.9" with a pasted space, "::FFFF:203.0.113.9" in upper case, or the
// typo "203.0.113.999" were all accepted and displayed in the panel as the
// client's allowed IP while that client went on being refused. The operator's only
// symptom was a subscriber who could not resolve, with the dashboard insisting
// their address was whitelisted.
//
// An empty string is valid and means "no address on file": both UpdateClient and
// SetClientIP use it to clear the list.
func normalizeAllowedIP(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	// "203.0.113.9:53" and "[2001:db8::1]:853" are what an address looks like when
	// it is copied out of a log line, so take the host half rather than refusing it.
	if host, _, err := net.SplitHostPort(trimmed); err == nil && host != "" {
		trimmed = host
	}
	trimmed = strings.Trim(trimmed, "[]")
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidIP, raw)
	}
	// String() collapses a v4-mapped v6 address to its dotted quad, which is what a
	// dual-stack listener reports for an IPv4 peer, so no separate To4 branch is
	// needed to make the two sides agree.
	return ip.String(), nil
}

type UpdateClientRequest struct {
	Name           *string    `json:"name"`
	UUID           *string    `json:"uuid"`
	AllowedIP      *string    `json:"allowed_ip"`
	TrafficLimitGB *float64   `json:"traffic_limit_gb"`
	ExpiresAt      *time.Time `json:"expires_at"`
	DaysToAdd      *int       `json:"days_to_add"`
	Enabled        *bool      `json:"enabled"`
	Note           *string    `json:"note"`
	CustomPolicies *[]string  `json:"custom_policies"`

	// TrafficResetCycle is "", "daily", "weekly" or "monthly". Switching a cycle on
	// anchors it at the moment of the request, so the first rollover is a whole
	// period away instead of immediate.
	TrafficResetCycle *string `json:"traffic_reset_cycle"`
}

type ClientService struct {
	db       *database.DB
	allowAll bool
	idMap    map[string]*database.Client // in-memory fast ID lookup
	ipMap    map[string]*database.Client // in-memory fast IP lookup
	tokenMap map[string]*database.Client // in-memory fast Token lookup
	uuidMap  map[string]*database.Client // in-memory fast UUID lookup
	// bindMu serializes RegisterIP per token (v2.1.0 B-23 remediation): two
	// concurrent binds both read the cached record, both saved, and the
	// interleaving left the resolver index and the DB pointing at different
	// bindings until the next full reload.
	bindMu sync.Mutex
	bindWG map[string]*sync.Mutex
	mu     sync.RWMutex

	// traffic accumulates metered bytes between database writes; flushMu
	// serialises the read-modify-write that persists them against the reset that
	// zeroes them, so neither can overwrite the other's result.
	traffic *trafficLedger
	flushMu sync.Mutex
}

func NewClientService(db *database.DB, allowAll bool) *ClientService {
	s := &ClientService{
		db:       db,
		allowAll: allowAll,
		idMap:    make(map[string]*database.Client),
		ipMap:    make(map[string]*database.Client),
		tokenMap: make(map[string]*database.Client),
		uuidMap:  make(map[string]*database.Client),
		traffic:  newTrafficLedger(),
	}
	s.reloadCache()
	// Phase B (Mantis C-03) migration: records written before the registration
	// secret existed get one now, so every account is enrolable the moment the
	// daemon starts. Idempotent; the log line names how many legacy records it
	// upgraded.
	s.ensureRegisterSecrets()
	return s
}

// ensureRegisterSecrets gives every stored account that lacks one a registration
// secret, persisting the backfill. A record that already carries a secret is left
// exactly as it is, the same way ensureAdminPath never regenerates a chosen path.
// A failed write is skipped, not fatal: the record stays secretless and the next
// start retries, rather than the daemon refusing to boot over one bad record.
func (s *ClientService) ensureRegisterSecrets() {
	clients, err := s.db.ListClients()
	if err != nil {
		return
	}
	backfilled := 0
	for i := range clients {
		c := &clients[i]
		if c.RegisterSecret != "" {
			continue
		}
		c.RegisterSecret = GenerateRegisterSecret()
		if err := s.db.SaveClient(*c); err != nil {
			continue
		}
		s.mu.Lock()
		if cur, ok := s.idMap[c.ID]; ok {
			cur.RegisterSecret = c.RegisterSecret
		}
		s.mu.Unlock()
		backfilled++
	}
	if backfilled > 0 {
		log.Printf("[Main] Issued register secrets for %d existing subscriber account(s)", backfilled)
	}
}

// GenerateRegisterSecret returns the out-of-band half of the IP-registration
// credential: 24 hex characters (96 bits) from crypto/rand. It travels a
// different channel than the portal link — shown once at creation and
// regenerable from the panel — which is what makes a leaked link read-only
// (Mantis C-03).
func GenerateRegisterSecret() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// reloadCache loads all clients from DB into in-memory fast lookup tables
func (s *ClientService) reloadCache() {
	clients, err := s.db.ListClients()
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.idMap = make(map[string]*database.Client, len(clients))
	s.ipMap = make(map[string]*database.Client, len(clients))
	s.tokenMap = make(map[string]*database.Client, len(clients))
	s.uuidMap = make(map[string]*database.Client, len(clients))
	now := time.Now()

	for i := range clients {
		s.indexLocked(&clients[i], now)
	}
}

// indexLocked files one account into every lookup table. Callers hold s.mu.
//
// The token and UUID indexes deliberately include disabled and expired accounts:
// the portal has to resolve their credential in order to tell the subscriber that
// the subscription has run out. Only ipMap is restricted to accounts the resolver
// should currently answer for.
func (s *ClientService) indexLocked(c *database.Client, now time.Time) {
	if c == nil || c.ID == "" {
		return
	}
	s.idMap[c.ID] = c
	if c.Token != "" {
		s.tokenMap[c.Token] = c
	}
	if c.UUID != "" {
		s.uuidMap[c.UUID] = c
	}
	if !c.Enabled {
		return
	}
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
		return
	}
	for _, ip := range c.AllowedIPs {
		if ip != "" {
			s.ipMap[ip] = c
		}
	}
}

// deindexLocked removes one previously indexed record. Callers hold s.mu.
//
// Every deletion is conditional on the entry still pointing at this exact record,
// so an account that has since claimed the same address — the normal case when a
// subscriber's address moves between two accounts — keeps its own entry.
func (s *ClientService) deindexLocked(old *database.Client) {
	if old == nil {
		return
	}
	if s.idMap[old.ID] == old {
		delete(s.idMap, old.ID)
	}
	if old.Token != "" && s.tokenMap[old.Token] == old {
		delete(s.tokenMap, old.Token)
	}
	if old.UUID != "" && s.uuidMap[old.UUID] == old {
		delete(s.uuidMap, old.UUID)
	}
	for _, ip := range old.AllowedIPs {
		if s.ipMap[ip] == old {
			delete(s.ipMap, ip)
		}
	}
}

// refreshClientIndex re-files a single account without the full-database rescan
// reloadCache performs.
//
// The subscriber portal reaches RegisterIP on every visit, and rebuilding all
// three indexes there cost a decrypt of every stored record — measured at ~5.6ms
// and 2.4MB of garbage per request with a thousand accounts — held under the same
// write lock every DNS query needs in order to read. One subscriber refreshing a
// page stalled resolution for everybody.
func (s *ClientService) refreshClientIndex(c *database.Client) {
	if c == nil || c.ID == "" {
		return
	}

	// Index a private copy: the caller keeps its own pointer, and a later mutation
	// of the record it was handed must not silently rewrite what the resolver sees.
	stored := *c
	stored.AllowedIPs = slices.Clone(c.AllowedIPs)
	stored.CustomPolicies = slices.Clone(c.CustomPolicies)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.deindexLocked(s.idMap[stored.ID])
	s.indexLocked(&stored, time.Now())
}

// IsIPAllowed resolves a source address to its subscriber account.
//
// It is one map lookup behind a read lock — measured at 15–18ns on a 1000-account
// index, allocation-free — which is the whole reason the index exists: the
// alternative is a decrypt of every stored record on every query. It is not
// lock-free, and concurrent callers do contend: the parallel figure is 30–32ns per
// lookup across 12 threads, i.e. worse per operation than serial, because readers
// share one RWMutex.
// Count returns the number of provisioned subscriber accounts, straight from
// the in-memory index — O(1), no database walk. The console header reads it
// on every redraw.
func (s *ClientService) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.idMap)
}

func (s *ClientService) IsIPAllowed(ip string) (*database.Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.allowAll {
		client := s.ipMap[ip]
		return client, true
	}

	client, ok := s.ipMap[ip]
	return client, ok
}

func (s *ClientService) IsAllowAll() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowAll
}

func (s *ClientService) SetAllowAll(allow bool) {
	s.mu.Lock()
	s.allowAll = allow
	s.mu.Unlock()
	_ = s.db.SetSetting("allow_all", allow)
}

// CreateClientRequest is everything an operator can settle at the moment a
// subscriber account is created.
//
// It exists because both front-ends used to create the account and then
// immediately update it to attach the quota, the cycle, the note and the policies —
// two writes, with the second one's error swallowed so the request could still
// answer 201. A reseller who sold a 50 GB monthly plan and hit a write failure in
// that gap was handed a live account with no limit at all, which is worse than
// having been told the create failed. One write cannot half-succeed.
type CreateClientRequest struct {
	Name string
	Days int
	IP   string

	// ExpiresAt is the absolute moment the plan ends. Set, it wins over Days —
	// the panel's picker answers an exact date, and rounding it into whole days
	// would silently move the expiry. Zero keeps the Days behaviour.
	ExpiresAt time.Time

	// TrafficResetCycle is "", "daily", "weekly" or "monthly", validated here so a
	// typo writes nothing rather than leaving an account behind. A cycle is anchored
	// at creation, so the first rollover is a whole period away.
	TrafficLimitGB    float64
	TrafficResetCycle string

	Note           string
	CustomPolicies []string
}

// ProvisionClient creates a subscriber account from a full plan in a single write.
func (s *ClientService) ProvisionClient(req CreateClientRequest) (*database.Client, error) {
	// Negative values read as their opposite here: a limit below zero failed
	// every comparison and behaved as unlimited, a negative validity ran
	// lifetime. A typo'd "-50" must not silently invert the plan's meaning.
	if req.Days < 0 {
		return nil, fmt.Errorf("validity days cannot be negative (omit or send 0 for an account that never expires)")
	}
	if req.TrafficLimitGB < 0 {
		return nil, fmt.Errorf("traffic limit cannot be negative (0 means unlimited)")
	}
	cycle, ok := NormalizeTrafficCycle(req.TrafficResetCycle)
	if !ok {
		return nil, fmt.Errorf("%w: %q (use daily, weekly, monthly, or an empty value for none)",
			ErrInvalidTrafficCycle, req.TrafficResetCycle)
	}

	// 32 bytes (64 hex chars) — the same entropy class as session tokens. The
	// 8-byte form gave the UUID an offline brute-force target of 2^64 once the
	// UUID was visible (v2.1.0 A-02 remediation), and the token IS the
	// credential, so its length should not be the weakest link anywhere.
	tokBytes := make([]byte, 32)
	_, _ = rand.Read(tokBytes)
	token := hex.EncodeToString(tokBytes)

	// The out-of-band half of the registration credential (Phase B, Mantis
	// C-03): shown once to the operator at creation, regenerable from the
	// panel, and required by /ip/<token> before it will move a binding.
	registerSecret := GenerateRegisterSecret()

	idBytes := make([]byte, 5)
	_, _ = rand.Read(idBytes)
	id := fmt.Sprintf("%d%s", time.Now().Unix()%100000, hex.EncodeToString(idBytes))

	now := time.Now()
	var expiresAt time.Time
	if !req.ExpiresAt.IsZero() {
		expiresAt = req.ExpiresAt
	} else if req.Days > 0 {
		expiresAt = now.Add(time.Duration(req.Days) * 24 * time.Hour)
	}

	// A cycle is anchored at creation rather than left zero: the sweep would anchor it
	// on its next pass anyway, and doing it here means the record is complete the
	// moment the operator sees it in the panel.
	var anchor time.Time
	if cycle != TrafficCycleNone {
		anchor = now
	}

	// Initialised, not nil: this slice is JSON-encoded straight to the dashboard, and a
	// subscriber created without an IP used to arrive as "allowed_ips": null. Every
	// clearing path below already writes []string{} for exactly that reason.
	ips := []string{}
	normalized, err := normalizeAllowedIP(req.IP)
	if err != nil {
		return nil, err
	}
	if normalized != "" {
		ips = []string{normalized}
	}

	// Same reason as ips above: an omitted custom_policies must not come back as null.
	// unpackClient already normalises it on the way out, so without this the create
	// response and a later GET of the same record described the field two ways.
	policies := req.CustomPolicies
	if policies == nil {
		policies = []string{}
	}

	client := database.Client{
		ID:             id,
		UUID:           database.GenerateUUID(),
		Name:           req.Name,
		Token:          token,
		AllowedIPs:     ips,
		TrafficLimitGB: req.TrafficLimitGB,
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
		Enabled:        true,
		Note:           req.Note,
		CustomPolicies: policies,

		RegisterSecret: registerSecret,

		TrafficResetCycle:  cycle,
		TrafficResetAnchor: anchor,
	}

	if err := s.db.SaveClient(client); err != nil {
		return nil, err
	}

	s.reloadCache()
	return &client, nil
}

// CreateClient provisions an account from nothing but a name, a duration and an
// optional address. It is the shape the TUI and the older callers ask for, and it is
// deliberately still here rather than replaced: most accounts are created with no
// quota at all, and those callers should not have to name a plan to say so.
func (s *ClientService) CreateClient(name string, days int, ip string) (*database.Client, error) {
	return s.ProvisionClient(CreateClientRequest{Name: name, Days: days, IP: ip})
}

func (s *ClientService) UpdateClient(id string, req UpdateClientRequest) (*database.Client, error) {
	client, err := s.db.GetClient(id)
	if err != nil {
		return nil, err
	}

	if req.Name != nil && *req.Name != "" {
		client.Name = *req.Name
	}
	if req.UUID != nil && *req.UUID != "" {
		client.UUID = *req.UUID
	}
	if req.AllowedIP != nil {
		normalized, err := normalizeAllowedIP(*req.AllowedIP)
		if err != nil {
			return nil, err
		}
		if normalized == "" {
			client.AllowedIPs = []string{}
		} else {
			client.AllowedIPs = []string{normalized}
		}
	}
	if req.TrafficLimitGB != nil {
		if *req.TrafficLimitGB < 0 {
			return nil, fmt.Errorf("traffic limit cannot be negative (0 means unlimited)")
		}
		client.TrafficLimitGB = *req.TrafficLimitGB
	}
	if req.TrafficResetCycle != nil {
		cycle, ok := NormalizeTrafficCycle(*req.TrafficResetCycle)
		if !ok {
			return nil, fmt.Errorf("%w: %q (use daily, weekly, monthly, or an empty value for none)",
				ErrInvalidTrafficCycle, *req.TrafficResetCycle)
		}
		// Anchored only when the cycle actually changes. Re-sending the same cycle as
		// part of an unrelated edit must not restart the period, or a subscriber whose
		// note happens to be edited every month would never reach a rollover at all.
		if cycle != TrafficCycleNone && client.TrafficResetCycle != cycle {
			client.TrafficResetAnchor = time.Now()
			client.TrafficResetCount = 0
		}
		client.TrafficResetCycle = cycle
	}
	if req.ExpiresAt != nil {
		client.ExpiresAt = *req.ExpiresAt
	}
	if req.DaysToAdd != nil && *req.DaysToAdd != 0 {
		base := client.ExpiresAt
		if base.IsZero() || time.Now().After(base) {
			base = time.Now()
		}
		client.ExpiresAt = base.Add(time.Duration(*req.DaysToAdd) * 24 * time.Hour)
	}
	if req.Enabled != nil {
		client.Enabled = *req.Enabled
	}
	if req.Note != nil {
		client.Note = *req.Note
	}
	if req.CustomPolicies != nil {
		client.CustomPolicies = *req.CustomPolicies
	}

	if err := s.db.SaveClient(*client); err != nil {
		return nil, err
	}

	s.reloadCache()
	return client, nil
}

func (s *ClientService) RegenerateUUID(id string) (string, error) {
	client, err := s.db.GetClient(id)
	if err != nil {
		return "", err
	}
	newUUID := database.GenerateUUID()
	client.UUID = newUUID
	if err := s.db.SaveClient(*client); err != nil {
		return "", err
	}
	s.reloadCache()
	return newUUID, nil
}

// SetClientIP replaces the client's allowed address with one supplied by an
// operator. It replaces rather than appends by design: the resolver identifies a
// subscriber by their current address, which moves whenever their ISP reassigns
// it, so the list holds at most one entry — see registerIP, which does the same
// thing when the subscriber's own portal visit reports a new address.
func (s *ClientService) SetClientIP(id string, ip string) error {
	normalized, err := normalizeAllowedIP(ip)
	if err != nil {
		return err
	}
	client, err := s.db.GetClient(id)
	if err != nil {
		return err
	}
	if normalized == "" {
		client.AllowedIPs = []string{}
	} else {
		client.AllowedIPs = []string{normalized}
	}
	client.LastSeen = time.Now()
	if err := s.db.SaveClient(*client); err != nil {
		return err
	}
	s.reloadCache()
	return nil
}

// RemoveClientIP drops one address from the client's list.
//
// The comparison is deliberately exact rather than normalised: records written
// before SetClientIP validated its input may hold a malformed entry, and this is
// the only route that can clear one. Normalising the argument would make those
// entries unremovable.
func (s *ClientService) RemoveClientIP(id string, ip string) error {
	client, err := s.db.GetClient(id)
	if err != nil {
		return err
	}
	// Non-nil even when it empties the list: a nil slice marshals as JSON null, and
	// the dashboard iterates this field. Every other write path here stores
	// []string{} for "no address", so this one should not be the odd one out.
	newIPs := []string{}
	for _, cur := range client.AllowedIPs {
		if cur != ip {
			newIPs = append(newIPs, cur)
		}
	}
	client.AllowedIPs = newIPs
	if err := s.db.SaveClient(*client); err != nil {
		return err
	}
	s.reloadCache()
	return nil
}

func (s *ClientService) RenewClient(id string, days int) error {
	client, err := s.db.GetClient(id)
	if err != nil {
		return err
	}
	base := client.ExpiresAt
	if base.IsZero() || time.Now().After(base) {
		base = time.Now()
	}
	client.ExpiresAt = base.Add(time.Duration(days) * 24 * time.Hour)
	client.Enabled = true
	if err := s.db.SaveClient(*client); err != nil {
		return err
	}
	s.reloadCache()
	return nil
}

// GetClient returns a stored client with its live traffic total. The write paths
// deliberately read through s.db instead, so a save never persists a figure that
// the next flush would add to a second time.
func (s *ClientService) GetClient(id string) (*database.Client, error) {
	client, err := s.db.GetClient(id)
	if err != nil {
		return nil, err
	}
	client.TrafficUsedBytes += s.traffic.get(client.ID)
	return client, nil
}

func (s *ClientService) FindClientByUUID(uuid string) (*database.Client, error) {
	s.mu.RLock()
	c, ok := s.uuidMap[uuid]
	s.mu.RUnlock()
	if ok && c != nil {
		return c, nil
	}
	return nil, errors.New("client not found by UUID")
}

// RegisterIP binds newIP to the subscription named by token, gated on the
// out-of-band register secret (Phase B, Mantis C-03). The secret comparison is
// constant-time and runs BEFORE any state changes; a wrong or missing secret is
// indistinguishable from an unknown token from the caller's side (both answer
// ErrClientNotFound at the HTTP layer), so a prober holding only a leaked link
// learns nothing by probing secrets against it.
func (s *ClientService) RegisterIP(token, secret, newIP string) (*database.Client, bool, error) {
	// Resolve through the in-memory token index. The database fallback has to
	// walk every stored record, so an unauthenticated caller submitting bogus
	// tokens would otherwise pay for a full bucket scan per request.
	s.mu.RLock()
	cached, ok := s.tokenMap[token]
	s.mu.RUnlock()
	if !ok || cached == nil {
		return nil, false, database.ErrClientNotFound
	}

	// Constant-time secret check, deliberately ahead of the IP normalization:
	// an attacker probing secrets must not get normalization feedback (a 400
	// vs 404 distinction) that tells them their token is live.
	if subtle.ConstantTimeCompare([]byte(cached.RegisterSecret), []byte(strings.TrimSpace(secret))) != 1 || cached.RegisterSecret == "" {
		return nil, false, database.ErrClientNotFound
	}

	// Quota gate FIRST against the LIVE figure (persisted + unflushed ledger),
	// the same number the resolver enforces against: a stored counter alone
	// reads zero for a subscriber whose bytes are still pending, and the gate
	// would wave them through (Mantis C-02 dynamic finding).
	if view := s.ViewClient(cached); view.QuotaExceeded {
		return nil, false, database.ErrQuotaExceeded
	}

	// Canonicalize before storing (v2.1.0 B-24 remediation): the self-service
	// path stored the raw header-derived string, and a non-canonical form such
	// as "::ffff:203.0.113.9" never matched the canonical ip.String() key the
	// listener reports — the bind silently failed. The operator path has run
	// this normalizer all along; the subscriber path now gets the same rules.
	normalized, err := normalizeAllowedIP(newIP)
	if err != nil {
		return nil, false, err
	}
	newIP = normalized

	// Serialize per token (v2.1.0 B-23 remediation): the read-modify-save plus
	// the index refresh below are one logical operation, and the interleaving
	// of two concurrent binds used to leave the index and the DB disagreeing
	// until the next full reload. Only binds for the SAME subscription wait;
	// different tokens never contend.
	lock := s.tokenBindLock(token)
	lock.Lock()
	defer lock.Unlock()

	client, alreadyPresent, err := s.db.RegisterIPForClient(cached.ID, newIP)
	// An expired account is disabled on disk by that call, so the index has to be
	// updated even though an error came back — otherwise ipMap keeps serving the
	// account until the next unrelated write. A targeted refresh rather than
	// reloadCache: this is a public endpoint, and a full rescan here let one
	// subscriber's page refreshes hold the write lock against every DNS query.
	if err == nil || errors.Is(err, database.ErrClientExpired) {
		s.refreshClientIndex(client)
	}
	return client, alreadyPresent, err
}

// RegenerateRegisterSecret replaces an account's registration secret and
// persists it, returning the new value. Every outstanding copy of the old
// secret stops working the moment this returns — that immediacy is what makes
// a circulated secret revocable.
func (s *ClientService) RegenerateRegisterSecret(id string) (string, error) {
	client, err := s.db.GetClient(id)
	if err != nil {
		return "", err
	}
	client.RegisterSecret = GenerateRegisterSecret()
	if err := s.db.SaveClient(*client); err != nil {
		return "", err
	}
	s.mu.Lock()
	if cur, ok := s.idMap[id]; ok {
		cur.RegisterSecret = client.RegisterSecret
	}
	s.mu.Unlock()
	return client.RegisterSecret, nil
}

// RegisterSecretFor returns the current registration secret of one account,
// for the two places that may show it: the operator's panel and the
// subscriber's own portal page.
func (s *ClientService) RegisterSecretFor(id string) (string, error) {
	client, err := s.db.GetClient(id)
	if err != nil {
		return "", err
	}
	return client.RegisterSecret, nil
}

// LookupByToken resolves a subscription token without writing anything.
//
// It exists for the link-preview path. Opening a /sub/ link re-binds the account's
// allowed address, so when the fetch is a messenger's preview crawler or a browser
// prefetch rather than the subscriber, the page still has to render — a preview card
// reading "invalid link" is worse than no card — but the registration must not happen.
// See isLinkPreviewFetch in package web for what counts as one.
//
// An expired account comes back with ErrClientExpired and, unlike RegisterIP, is not
// disabled on disk: a crawler's fetch is not the event that should retire an account.
func (s *ClientService) LookupByToken(token string) (*database.Client, error) {
	s.mu.RLock()
	cached, ok := s.tokenMap[token]
	s.mu.RUnlock()
	if !ok || cached == nil {
		return nil, database.ErrClientNotFound
	}

	// A copy, because the index holds pointers into the cache the resolver reads on
	// every query and the caller is about to hand this to a template.
	client := *cached
	if !client.ExpiresAt.IsZero() && time.Now().After(client.ExpiresAt) {
		return &client, database.ErrClientExpired
	}
	return &client, nil
}

// ListClients returns every stored client with its live traffic total, so the
// dashboard shows usage as it accrues rather than as of the last flush.
func (s *ClientService) ListClients() ([]database.Client, error) {
	clients, err := s.db.ListClients()
	if err != nil {
		return nil, err
	}
	for i := range clients {
		clients[i].TrafficUsedBytes += s.traffic.get(clients[i].ID)
	}
	return clients, nil
}

func (s *ClientService) DeleteClient(id string) error {
	err := s.db.DeleteClient(id)
	if err == nil {
		s.reloadCache()
	}
	return err
}

func (s *ClientService) ToggleClient(id string, enabled bool) (*database.Client, error) {
	c, err := s.db.GetClient(id)
	if err != nil {
		return nil, err
	}
	c.Enabled = enabled
	err = s.db.SaveClient(*c)
	if err == nil {
		s.reloadCache()
	}
	return c, err
}

// StartExpirationWatcher runs the periodic account sweep until the returned
// channel is closed.
func (s *ClientService) StartExpirationWatcher(interval time.Duration) chan struct{} {
	stopChan := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.sweepClients(time.Now())
			case <-stopChan:
				return
			}
		}
	}()
	return stopChan
}

// sweepClients is one pass over every account: it deactivates the subscriptions
// that have run out and rolls over the quotas whose period has ended.
//
// Both jobs share the pass because both need the whole account list, and that list
// costs an AES-GCM open per stored record. Running them as two watchers would
// double that for no benefit — and would also mean two rebuilds of the resolver's
// index per tick, each one taking the write lock every DNS query needs to read.
//
// now is a parameter so the behaviour can be tested at a chosen date instead of
// only at whatever time the test happens to run.
func (s *ClientService) sweepClients(now time.Time) {
	clients, err := s.db.ListClients()
	if err != nil {
		return
	}
	changed := s.deactivateExpired(clients, now)
	changed += s.applyTrafficCycles(clients, now)
	if changed > 0 {
		s.reloadCache()
	}
}

// deactivateExpired disables the accounts whose expiry has passed and reports how
// many it wrote.
//
// Each record is re-read before it is written. The listed copy was decrypted at the
// top of the sweep, and an operator renewing an account in that window would
// otherwise have their renewal overwritten by a one-field update carrying every
// other field's stale value — including the expiry that made the account look
// expired in the first place.
func (s *ClientService) deactivateExpired(clients []database.Client, now time.Time) int {
	changed := 0
	for i := range clients {
		if c := &clients[i]; !c.Enabled || c.ExpiresAt.IsZero() || !now.After(c.ExpiresAt) {
			continue
		}
		id := clients[i].ID
		stored, err := s.db.GetClient(id)
		if err != nil || stored == nil {
			continue
		}
		if !stored.Enabled || stored.ExpiresAt.IsZero() || !now.After(stored.ExpiresAt) {
			continue // renewed or already disabled since the list was taken
		}
		stored.Enabled = false
		if err := s.db.SaveClient(*stored); err != nil {
			log.Printf("[ClientService] Could not deactivate the expired account %s: %v", id, err)
			continue
		}
		changed++
		log.Printf("[ClientService] Deactivated expired account: %s (%s)", stored.Name, id)
	}
	return changed
}

func (s *ClientService) ResetClientTraffic(id string) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	// Discard the unpersisted count first. Leaving it would let the next flush
	// add pre-reset bytes on top of the zero written here.
	s.traffic.reset(id)

	client, err := s.db.GetClient(id)
	if err != nil {
		return err
	}
	client.TrafficUsedBytes = 0
	if err := s.db.SaveClient(*client); err != nil {
		return err
	}
	s.reloadCache()
	return nil
}

// tokenBindLock returns the per-token mutex that serializes IP registrations
// for one subscription, creating it on first use. The map itself grows by one
// entry per subscription — bounded by the subscriber count, not by traffic.
func (s *ClientService) tokenBindLock(token string) *sync.Mutex {
	s.bindMu.Lock()
	defer s.bindMu.Unlock()
	if s.bindWG == nil {
		s.bindWG = make(map[string]*sync.Mutex)
	}
	m, ok := s.bindWG[token]
	if !ok {
		m = &sync.Mutex{}
		s.bindWG[token] = m
	}
	return m
}
