package matcher

import (
	"slices"
	"strings"
	"sync"

	"hyperdns/presets"
)

type Action int

const (
	ActionDirect Action = iota
	ActionProxy
	ActionBlock
)

func (a Action) String() string {
	switch a {
	case ActionProxy:
		return "PROXY"
	case ActionBlock:
		return "BLOCK"
	default:
		return "DIRECT"
	}
}

// Rule names for the operator's own three lists. These are admin-wide: a domain
// typed into one of them applies to every client, including clients that carry
// their own policy selection. The per-client policy picker offers only enable_*
// preset keys, so gating these on a client's selection — as the previous version
// did — meant an explicitly blocked domain stayed resolvable for every subscriber.
const (
	RuleCustomDirect = "Custom Direct"
	RuleCustomBlock  = "Custom Block"
	RuleCustomProxy  = "Custom Proxy"
)

// Rule names for the forced-direct plane described in realtime.go: names the SNI
// proxy has no path for, which are answered directly no matter what the presets
// say. Neither is a category, neither can be switched off, and both apply to every
// client. They appear in the query log so an operator who expects a name to be
// proxied can see which rule answered it directly instead — and which of the two
// reasons applied, since one is about transport and the other about ports.
//
// isForcedDirect is the predicate; add a rule name here and to forcedDirectGroups
// together, or the new label will be filterable like an ordinary preset.
const (
	RuleRealtimeDirect    = "Realtime Media"
	RuleUnproxyableDirect = "Unproxyable Port"
)

func isForcedDirect(rule string) bool {
	return rule == RuleRealtimeDirect || rule == RuleUnproxyableDirect
}

// acceptAll is the zero policyFilter: no disable map, perClient false, so accept
// returns true for everything. It turns a lookup into the question "is this name in
// this set at all", separately from whether the rule that owns it is switched on —
// which is what the download veto needs, because for that set being switched *off*
// is the state that changes the verdict.
var acceptAll = policyFilter{}

// blockPresets names the preset categories whose domains are sinkholed rather than
// proxied. Every preset used to be loaded into the proxy index, so switching on
// "AdBlock & Tracker Sinkhole" relayed ad and tracker traffic through the
// operator's own SNI proxy — paying VPS bandwidth to deliver the ads it was meant
// to remove — and "FamilySafe Protection" routed adult sites through that proxy
// instead of blocking them.
var blockPresets = func() map[string]bool {
	m := make(map[string]bool)
	for _, p := range presets.All() {
		if p.Kind == presets.KindBlock {
			m[p.Name] = true
		}
	}
	return m
}()

// defaultOffPresets names every category that ships disabled — the two sinkholes
// plus the download veto, which has the same "surprising if it fired on its own"
// property for a different reason: it takes traffic off the proxy rather than
// putting it there, so a subscriber whose only route to a CDN is the proxy would
// find installs failing on a fresh install of this daemon.
//
// Derived from blockPresets rather than restating it, so a new sinkhole category is
// off by default without anyone remembering to add it twice. Go orders package
// variable initialisation by dependency, so reading blockPresets here is safe
// regardless of declaration order.
var defaultOffPresets = func() map[string]bool {
	m := make(map[string]bool)
	for _, p := range presets.All() {
		if !p.DefaultEnabled {
			m[p.Name] = true
		}
	}
	return m
}()

// ruleSet indexes rule domains for one action. exact holds names that match
// themselves; wildcard holds parent domains that match any strict subdomain. A
// plain rule ("riotgames.com") is indexed in both, a wildcard rule
// ("*.riotgames.com") only in wildcard — so "*.foo.com" never matches "foo.com",
// which is what the previous leading-dot suffix encoding did as well.
//
// This replaced a []struct{suffix, ruleName} scanned with strings.HasSuffix on
// every query. The built-in presets alone made that 845 string comparisons before
// a clean domain could be declared DIRECT (~2µs on the reference machine), and the
// cost grew with every domain the operator added, so loading a real blocklist
// would have taxed every unrelated lookup. A label walk costs one map probe per
// label instead.
// A domain may be claimed by more than one preset — "rainbow6.com" is listed by
// both "Ubisoft & Rainbow Six" and the tactical-shooters category, "ea.com" by both
// the EA policy and the sports one. One map key holds one rule name, so the domain
// used to be attributed to whichever preset sorted first, and that attribution was
// also the only one honored: a subscriber sold the sports plan did not get "ea.com"
// proxied, because the key said "EA & Origin", and an operator who switched the
// shooters category off turned Rainbow Six off for their Ubisoft users too.
//
// exactAlso and wildcardAlso record the losing claims, so a rejected owner can fall
// back to a co-owner the filter does accept. They are consulted only after a
// rejection and are nil for every domain with a single owner, which is nearly all of
// them — the accepted-on-first-try path is exactly what it was.
type ruleSet struct {
	exact    map[string]string
	wildcard map[string]string

	exactAlso    map[string][]string
	wildcardAlso map[string][]string
}

func newRuleSet() *ruleSet {
	return &ruleSet{
		exact:    make(map[string]string),
		wildcard: make(map[string]string),
	}
}

// addOwner appends a co-owner, allocating the map on first use. Repeats are dropped:
// a preset that lists both "foo.com" and "*.foo.com" indexes the same key twice.
func addOwner(m map[string][]string, domain, ruleName string) map[string][]string {
	if slices.Contains(m[domain], ruleName) {
		return m
	}
	if m == nil {
		m = make(map[string][]string, 4)
	}
	m[domain] = append(m[domain], ruleName)
	return m
}

// acceptFirst returns the first rule in names the filter accepts.
func acceptFirst(names []string, f policyFilter) (string, bool) {
	for _, n := range names {
		if f.accept(n) {
			return n, true
		}
	}
	return "", false
}

// index adds one rule domain. It accepts "foo.com", "*.foo.com" and trailing dots.
// When overwrite is false an already-indexed domain keeps the rule it has, which is
// how presets are loaded: they are applied in sorted order, so a domain listed by
// two presets is attributed to the same one on every start instead of to whichever
// preset map iteration happened to reach first. The rule that lost is kept as a
// co-owner rather than discarded — see the ruleSet comment.
//
// overwrite is for the operator's own lists, and it drops the co-owners with the
// entry it replaces: a domain typed into Custom Proxy belongs to that rule alone.
func (rs *ruleSet) index(domain, ruleName string, overwrite bool) {
	d := normalizeDomain(domain)
	wild := strings.HasPrefix(d, "*.")
	if wild {
		d = d[2:]
	}
	// A pattern the index cannot honor is dropped rather than stored under a
	// literal "*" label, where it would silently never match.
	if d == "" || strings.Contains(d, "*") {
		return
	}
	if !wild {
		if cur, dup := rs.exact[d]; !dup || overwrite {
			rs.exact[d] = ruleName
			if overwrite {
				delete(rs.exactAlso, d)
			}
		} else if cur != ruleName {
			rs.exactAlso = addOwner(rs.exactAlso, d, ruleName)
		}
	}
	if cur, dup := rs.wildcard[d]; !dup || overwrite {
		rs.wildcard[d] = ruleName
		if overwrite {
			delete(rs.wildcardAlso, d)
		}
	} else if cur != ruleName {
		rs.wildcardAlso = addOwner(rs.wildcardAlso, d, ruleName)
	}
}

// unindex removes one rule domain, accepting the same forms index does. It exists
// so a domain can be lifted out of a set that was built before the caller knew
// about a higher-priority entry covering it — specifically, so an operator's own
// Custom Proxy entry can override the forced-direct real-time set.
//
// It removes only the exact pattern given: unindexing "voice.example.com" leaves a
// "example.com" entry in place. That asymmetry is deliberate for the one caller —
// a too-narrow override keeps the guarded name direct, which is the behaviour that
// works.
func (rs *ruleSet) unindex(domain string) {
	d := normalizeDomain(domain)
	wild := strings.HasPrefix(d, "*.")
	if wild {
		d = d[2:]
	}
	if d == "" || strings.Contains(d, "*") {
		return
	}
	if !wild {
		delete(rs.exact, d)
		delete(rs.exactAlso, d)
	}
	delete(rs.wildcard, d)
	delete(rs.wildcardAlso, d)
}

// lookup returns the rule matching d, walking from the most specific candidate to
// the least and skipping rules the filter rejects. Skipping rather than stopping is
// deliberate: a rule the operator disabled, or one a client has not selected, must
// not shadow a shorter rule that does apply.
//
// A rejected owner is retried against the domain's co-owners before the walk moves
// on, so a domain two presets claim is honored for a client holding either policy.
//
// Precedence inside a set is longest-suffix-wins. That is a deliberate change: the
// previous linear scan returned whichever overlapping rule happened to be indexed
// first, which for the presets was map-iteration order and therefore differed
// between restarts.
func (rs *ruleSet) lookup(d string, f policyFilter) (string, bool) {
	if len(rs.exact) > 0 {
		if name, ok := rs.exact[d]; ok {
			if f.accept(name) {
				return name, true
			}
			if alt, ok := acceptFirst(rs.exactAlso[d], f); ok {
				return alt, true
			}
		}
	}
	// An empty set is the normal state for the operator's custom lists, and the
	// label walk is the expensive half of a lookup — skip it rather than probe an
	// empty map once per label of every queried name.
	if len(rs.wildcard) == 0 {
		return "", false
	}
	// Probe each parent domain in turn: for "a.b.riotgames.com" that is
	// "b.riotgames.com", then "riotgames.com", then "com". The substrings share
	// d's backing array, so the walk allocates nothing.
	for i := 0; i < len(d); {
		dot := strings.IndexByte(d[i:], '.')
		if dot < 0 {
			break
		}
		i += dot + 1
		if i >= len(d) {
			break
		}
		if name, ok := rs.wildcard[d[i:]]; ok {
			if f.accept(name) {
				return name, true
			}
			if alt, ok := acceptFirst(rs.wildcardAlso[d[i:]], f); ok {
				return alt, true
			}
		}
	}
	return "", false
}

// size is the number of distinct rule domains indexed. Every indexed domain writes
// the wildcard map, so its length is the count.
func (rs *ruleSet) size() int {
	return len(rs.wildcard)
}

// policyFilter decides whether a matched rule may be returned. perClient is false
// for the global view, where only the operator's disable switches apply.
type policyFilter struct {
	disabled  map[string]bool
	policies  []string
	perClient bool
}

func (f policyFilter) accept(rule string) bool {
	// The forced-direct plane is neither an opt-in category nor a switch: proxying
	// a UDP media plane or a port nothing listens on does not degrade the service,
	// it removes it. Checked before the disable map so it cannot be turned off by
	// name either.
	if isForcedDirect(rule) {
		return true
	}
	if f.disabled[rule] {
		return false
	}
	if !f.perClient {
		return true
	}
	// The operator's own lists are not opt-in categories.
	switch rule {
	case RuleCustomDirect, RuleCustomBlock, RuleCustomProxy:
		return true
	}
	return policyAllows(f.policies, rule)
}

// Matcher resolves a domain to an action against five indexed rule sets. Reads
// take the read lock, so rules can be replaced at runtime while queries are served.
//
// downloads is the odd one out: it holds no action of its own, only the names the
// bulk-download veto may pull back out of proxied. See downloads.go.
type Matcher struct {
	mu            sync.RWMutex
	disabledRules map[string]bool
	direct        *ruleSet
	realtime      *ruleSet
	blocked       *ruleSet
	proxied       *ruleSet
	downloads     *ruleSet
	customRecords map[string]string // domain -> IP override

	// catalog is the active preset data: nil means the embedded baseline
	// (presets.NameMap). The preset-update channel swaps it in whole — never
	// mutating — so readers under the read lock always see one coherent catalog.
	catalog map[string][]string
}

func NewMatcher() *Matcher {
	m := &Matcher{
		disabledRules: make(map[string]bool),
		direct:        newRuleSet(),
		realtime:      newRuleSet(),
		blocked:       newRuleSet(),
		proxied:       newRuleSet(),
		downloads:     newRuleSet(),
		customRecords: make(map[string]string),
	}
	// Blocking categories start off, and so does the download veto. A resolver that
	// begins sinkholing names because a config key was absent is worse than one that
	// forwards them; a resolver that begins relaying game installs because a key was
	// absent bills the operator for them. Both the dashboard defaults and
	// config.example.json ship these disabled.
	for name := range defaultOffPresets {
		m.disabledRules[name] = true
	}
	m.LoadDefaultPresets()
	return m
}

// GetAllPresets returns the built-in preset catalog as display-name → domains.
// The data lives in presets/*.json (embedded by the presets package); this shim
// keeps every existing caller working while the channel format owns the truth.
func GetAllPresets() map[string][]string {
	return presets.NameMap()
}

// activeCatalog is the catalog the matcher indexes: the channel-applied
// override when one is installed, otherwise the embedded baseline.
// Caller holds mu (rebuild) or is in a read path that took it.
func (m *Matcher) activeCatalog() map[string][]string {
	if m.catalog != nil {
		return m.catalog
	}
	return GetAllPresets()
}

// SetCatalog installs a channel-delivered preset catalog and reindexes. Pass
// nil to return to the embedded baseline. The map is adopted as-is — the
// updater builds a fresh one per apply and never mutates it afterwards.
func (m *Matcher) SetCatalog(catalog map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.catalog = catalog
	m.rebuildPresetsLocked()
}

// CatalogVersion reports how many domains each active preset carries, so the
// updater can health-check a swap without exposing internals.
func (m *Matcher) CatalogSize() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cat := m.activeCatalog()
	out := make(map[string]int, len(cat))
	for name, domains := range cat {
		out[name] = len(domains)
	}
	return out
}

// LoadDefaultPresets rebuilds the built-in preset indexes. It discards custom rule
// lists; a caller holding both should use SetCustomRules, which restores the
// presets and the custom rules together.
func (m *Matcher) LoadDefaultPresets() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rebuildPresetsLocked()
}

// rebuildPresetsLocked indexes every built-in preset from scratch. Caller holds mu.
func (m *Matcher) rebuildPresetsLocked() {
	m.proxied = newRuleSet()
	m.blocked = newRuleSet()
	m.downloads = newRuleSet()

	presets := m.activeCatalog()
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		target := m.proxied
		switch {
		case blockPresets[name]:
			target = m.blocked
		case name == RuleDownloads:
			// Not an action index. These names stay in whichever game preset already
			// proxies them; this set only records that the veto may pull them out
			// again. Indexing them into m.proxied as well would proxy a CDN whose own
			// game preset the operator had switched off.
			target = m.downloads
		}
		for _, d := range presets[name] {
			target.index(d, name, false)
		}
	}

	// Names the proxy has no path for are forced direct. Rebuilt here rather than
	// once at startup so that every path which restores the presets — the
	// dashboard's save, a config reload — restores this guard with them.
	m.realtime = newRuleSet()
	for _, g := range forcedDirectGroups {
		for _, d := range g.domains {
			m.realtime.index(d, g.rule, true)
		}
	}
}

// resolveRuleName normalizes a rule identifier to the canonical preset display
// name that the rule index is keyed by. It accepts both dashboard policy keys
// ("enable_riot") and preset display names ("Riot Games & Valorant"), so a caller
// that only has the key cannot silently toggle a rule that never matches.
func resolveRuleName(rule string) string {
	r := strings.TrimSpace(rule)
	if name, ok := PresetRuleKeys[r]; ok {
		return name
	}
	return r
}

// IsBlockingRule reports whether a rule sinkholes the domains it matches rather than
// proxying them. Accepts a policy key or a preset display name.
//
// It exists so callers that need the safe default for a category — the dashboard's
// initial rules map, the config template — derive it from blockPresets instead of
// hardcoding the pair of names. A hardcoded list means a third blocking category
// added later defaults to ON in the UI while the matcher keeps it OFF, and the first
// save silently switches on sinkholing the operator never asked for.
func IsBlockingRule(rule string) bool {
	return blockPresets[resolveRuleName(rule)]
}

// DefaultRuleEnabled reports whether a category is on for a fresh install, which is
// what NewMatcher itself does. Accepts a policy key or a preset display name.
//
// IsBlockingRule used to be enough for this, because sinkholing was the only reason
// to ship a category off. The download veto is the second reason and is not a
// blocking rule, so a caller still deriving its default from IsBlockingRule would
// offer it as ON while the matcher held it OFF — and the operator's first save of an
// unrelated toggle would post that ON back and start relaying game installs nobody
// asked to pay for.
func DefaultRuleEnabled(rule string) bool {
	return !defaultOffPresets[resolveRuleName(rule)]
}

// SetRuleEnabled toggles a rule on/off in memory. Accepts a policy key or a preset
// display name.
func (m *Matcher) SetRuleEnabled(ruleKey string, enabled bool) {
	name := resolveRuleName(ruleKey)
	if name == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if enabled {
		delete(m.disabledRules, name)
	} else {
		m.disabledRules[name] = true
	}
}

// IsRuleEnabled reports whether a rule (policy key or preset name) is active.
func (m *Matcher) IsRuleEnabled(rule string) bool {
	name := resolveRuleName(rule)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !m.disabledRules[name]
}

// normalizeDomain lowercases a name and strips the trailing root label. DNS names
// are case-insensitive, and the rule index is keyed without the root dot.
func normalizeDomain(domain string) string {
	d := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	return strings.ToLower(d)
}

// Match resolves a domain against the global rule set.
func (m *Matcher) Match(domain string) (Action, string) {
	return m.match(domain, nil)
}

// MatchForClient resolves a domain honoring a client's own policy selection. An
// empty selection inherits the global rules.
func (m *Matcher) MatchForClient(domain string, clientPolicies []string) (Action, string) {
	return m.match(domain, clientPolicies)
}

// match is the single implementation behind both entry points, so the global and
// per-client paths cannot drift apart in precedence or in rule handling.
func (m *Matcher) match(domain string, policies []string) (Action, string) {
	d := normalizeDomain(domain)
	if d == "" {
		return ActionDirect, "Direct"
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	f := policyFilter{
		disabled:  m.disabledRules,
		policies:  policies,
		perClient: hasPolicy(policies),
	}

	// Precedence: the operator's whitelist, then blocks, then the forced-direct
	// real-time plane, then the bulk-download veto, then proxy rules.
	//
	// Blocks outrank the real-time set on purpose. An operator who typed a name
	// into Custom Block asked for it to stop resolving, which is a stronger
	// statement than "do not proxy this"; the real-time set only has to beat the
	// presets, and it does.
	if name, ok := m.direct.lookup(d, f); ok {
		return ActionDirect, name
	}
	if name, ok := m.blocked.lookup(d, f); ok {
		return ActionBlock, name
	}
	if name, ok := m.realtime.lookup(d, f); ok {
		return ActionDirect, name
	}
	// The download veto (downloads.go). Read with acceptAll, because the question is
	// whether this name is bulk payload — a fact about the name, not a setting — and
	// then answered with the ordinary filter, because whether the operator or this
	// client wants that payload relayed is exactly what the filter decides. Off means
	// direct: the CDN resolves to its real address and the install uses the
	// subscriber's own line.
	//
	// A veto and nothing more. If it does not fire, the loop below proxies the name
	// under whichever game preset owns it, unchanged.
	if name, ok := m.downloads.lookup(d, acceptAll); ok && !f.accept(name) {
		return ActionDirect, name
	}
	if name, ok := m.proxied.lookup(d, f); ok {
		return ActionProxy, name
	}
	return ActionDirect, "Direct"
}

// GetCustomRecord returns the custom DNS answer configured for a domain, if any.
func (m *Matcher) GetCustomRecord(domain string) (string, bool) {
	d := normalizeDomain(domain)
	m.mu.RLock()
	defer m.mu.RUnlock()
	ip, ok := m.customRecords[d]
	return ip, ok
}

// RuleCounts is the number of distinct rule domains indexed per action. It exists
// so documentation and tests can state real index sizes instead of estimates. The
// direct figure covers both the operator's whitelist and the forced-direct
// real-time set, since a name in either resolves DIRECT.
//
// The download set is absent on purpose: it carries no action of its own, and every
// name in it is already counted under the game preset that proxies it.
func (m *Matcher) RuleCounts() (direct, blocked, proxied int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.direct.size() + m.realtime.size(), m.blocked.size(), m.proxied.size()
}

// hasPolicy reports whether a client's selection carries at least one real entry.
// A list holding only blanks is treated as no selection at all, so it inherits the
// global rules: len(policies) > 0 alone meant a single stray empty string — a UI or
// migration artifact — silently stripped every category from a subscriber's plan
// and left them resolving everything DIRECT.
func hasPolicy(policies []string) bool {
	for _, p := range policies {
		if strings.TrimSpace(p) != "" {
			return true
		}
	}
	return false
}

// policyAllows reports whether a client's policy selection authorizes ruleName.
// Entries may be policy keys ("enable_riot") or preset display names.
//
// MatchForClient used to build a map[string]bool from the policy list on every
// query — three heap allocations on the DNS hot path, for a list that is never
// longer than the number of presets and is usually a handful of entries. A scan
// against the reverse name→key map allocates nothing.
func policyAllows(policies []string, ruleName string) bool {
	key := presetKeyByName[ruleName]
	for _, p := range policies {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == ruleName || p == key {
			return true
		}
	}
	return false
}

// SetCustomRules atomically rebuilds the operator's custom rule lists and custom A
// records while restoring the built-in presets. Safe for concurrent use and can be
// called repeatedly at runtime.
func (m *Matcher) SetCustomRules(customProxied, customBlocked, customDirect []string, customRecords map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rebuildPresetsLocked()

	m.direct = newRuleSet()
	for _, d := range customDirect {
		m.direct.index(d, RuleCustomDirect, true)
	}
	// Custom entries overwrite a preset covering the same domain: the operator
	// typed this one in, so it must win even when the preset it collides with is
	// currently switched off.
	for _, d := range customBlocked {
		m.blocked.index(d, RuleCustomBlock, true)
	}
	for _, d := range customProxied {
		m.proxied.index(d, RuleCustomProxy, true)
		// Same reasoning applied to the forced-direct real-time set: an operator who
		// types one of those names into the proxy list has overridden the guard
		// knowingly, and the guard exists to correct the presets, not the operator.
		m.realtime.unindex(d)
		// And to the download veto, for the operator who wants one CDN relayed while
		// the rest stay on the subscriber's line — the reason Custom Proxy exists.
		// Without this, typing a download host into that list saved cleanly and
		// changed nothing, because the veto is consulted before the proxy index.
		m.downloads.unindex(d)
	}

	m.customRecords = make(map[string]string, len(customRecords))
	for d, ip := range customRecords {
		// The lookup side normalizes the queried name, so the key must be
		// normalized the same way: a configured "pin.example." never matched.
		d = normalizeDomain(d)
		ip = strings.TrimSpace(ip)
		if d != "" && ip != "" {
			m.customRecords[d] = ip
		}
	}
}

// PresetRuleKeys maps dashboard/frontend policy keys (enable_*) to the built-in
// preset rule names used by GetAllPresets(). Every preset must appear here: a
// preset with no key cannot be toggled from the config file or the dashboard, and
// cannot be selected as a per-client policy. "SoundCloud Music" was missing, so
// config.json's enable_soundcloud was read and silently discarded.
// PresetRuleKeys maps dashboard/frontend policy keys (enable_*) to the built-in
// preset rule names. Derived from the embedded preset files (presets/*.json) —
// adding a preset file is all it takes for the key to exist everywhere.
var PresetRuleKeys = func() map[string]string {
	m := make(map[string]string, len(presets.All()))
	for _, p := range presets.All() {
		m[p.Key] = p.Name
	}
	return m
}()

// presetKeyByName is the inverse of PresetRuleKeys, built once so a matched rule
// can be tested against a client's policy list without allocating.
var presetKeyByName = func() map[string]string {
	inv := make(map[string]string, len(PresetRuleKeys))
	for key, name := range PresetRuleKeys {
		inv[name] = key
	}
	return inv
}()

// policyCatalogOrder is the order a front-end lists the presets in.
//
// PresetRuleKeys cannot carry it: Go randomises map iteration, so a dropdown filled
// from it reshuffles every time it opens, and the entry an operator was reaching for
// is somewhere else by the time they click. Which order is not arbitrary either —
// this is what a reseller sells, so the titles that sell go first and the utility
// categories that sinkhole go last, where an accidental click is least likely.
//
// It must name every key in PresetRuleKeys and nothing else. TestPolicyCatalog
// enforces that, because the failure otherwise is silent in the direction that
// matters: a preset added to PresetRuleKeys and forgotten here simply cannot be
// selected as a per-client policy, and nothing in the UI says the list is short.
var policyCatalogOrder = func() []string {
	out := make([]string, 0, len(presets.All()))
	for _, p := range presets.All() {
		out = append(out, p.Key)
	}
	return out
}()

// PolicyCatalogEntry is one selectable policy as a front-end has to list it.
type PolicyCatalogEntry struct {
	Key   string `json:"key"`
	Label string `json:"label"`

	// Blocking marks a category that sinkholes what it matches instead of proxying
	// it. Attaching one to a client is the opposite kind of decision from attaching a
	// game — "FamilySafe Protection" takes domains away — so a list that does not say
	// which is which invites the mistake.
	Blocking bool `json:"blocking"`
}

// PolicyCatalog is every preset that can be toggled globally or attached to one
// client, in display order.
//
// It exists because both front-ends had this table transcribed into JavaScript by
// hand. A copy of a Go map in a JS literal cannot be checked by anything, and it had
// already drifted: four labels were shorter than the ones here, so the dashboard and
// the resolver named the same category differently. Worse in one direction — a preset
// added to PresetRuleKeys was invisible to the panel until someone remembered to
// retype it, which is how enable_soundcloud stayed unselectable.
func PolicyCatalog() []PolicyCatalogEntry {
	out := make([]PolicyCatalogEntry, 0, len(policyCatalogOrder))
	for _, key := range policyCatalogOrder {
		name, ok := PresetRuleKeys[key]
		if !ok {
			// Unreachable while TestPolicyCatalog passes. Skipped rather than emitted
			// with an empty label, because a row a client can select but the matcher
			// cannot resolve is a policy that silently allows nothing.
			continue
		}
		out = append(out, PolicyCatalogEntry{
			Key:      key,
			Label:    name,
			Blocking: blockPresets[name],
		})
	}
	return out
}
