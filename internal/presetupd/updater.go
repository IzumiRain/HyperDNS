// Package presetupd is the daemon side of the preset-update channel (v2.3.0):
// it fetches the signed manifest from the Pages channel, verifies it, downloads
// the changed policy files, swaps them into the matcher atomically, health-checks
// the result, persists the applied state for the next boot, and rolls back on
// any failure. The embedded presets/*.json baseline is the permanent fallback —
// a server that never reaches the channel keeps working forever.
package presetupd

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"hyperdns/internal/core/matcher"
	"hyperdns/presets"
)

// DefaultBaseURL is where the channel publishes. Operators running a private
// mirror can override it; the value is part of the persisted update settings.
const DefaultBaseURL = "https://izumirain.github.io/HyperDNS/presets/"

// ChannelPubKey is the ed25519 public key baked into the binary. The private
// half lives only in the GitHub Actions secret PRESET_SIGNING_KEY; nothing in
// this repository may sign a manifest.
var ChannelPubKey = mustDecodeKey("FuTyleDROe4KXN88d1iSV9NuWIULmEt0RmNPuha8tL8=")

func mustDecodeKey(b64 string) ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		panic("presetupd: invalid embedded channel public key")
	}
	return ed25519.PublicKey(raw)
}

// Manifest is presets/manifest.json as the channel publishes it. It is the only
// file the daemon always fetches; policy files are fetched lazily, only for
// entries whose version moved.
type Manifest struct {
	Schema      int             `json:"schema"`
	GeneratedAt string          `json:"generated_at"`
	BaseURL     string          `json:"base_url"`
	Signature   string          `json:"signature"` // "ed25519:<base64>"
	Policies    []ManifestEntry `json:"policies"`
}

// ManifestEntry pins one policy file's content to a version and a hash.
type ManifestEntry struct {
	ID        string `json:"id"`
	Version   int    `json:"version"`
	SHA256    string `json:"sha256"`
	UpdatedAt string `json:"updated_at"`
}

// signPayload is the canonical byte string the signature covers. Both sides
// build it identically: generated_at, then one line per policy sorted by ID.
// JSON re-serialisation is never signed directly — whitespace differences
// between producer and consumer would otherwise invalidate a good signature.
func (m *Manifest) signPayload() []byte {
	lines := make([]string, 0, len(m.Policies)+1)
	lines = append(lines, m.GeneratedAt)
	ids := make([]string, 0, len(m.Policies))
	for _, p := range m.Policies {
		ids = append(ids, p.ID)
	}
	sort.Strings(ids)
	byID := make(map[string]ManifestEntry, len(m.Policies))
	for _, p := range m.Policies {
		byID[p.ID] = p
	}
	for _, id := range ids {
		p := byID[id]
		lines = append(lines, fmt.Sprintf("%s:%d:%s", p.ID, p.Version, p.SHA256))
	}
	return []byte(strings.Join(lines, "\n"))
}

// Verify checks the manifest signature against the channel public key.
func (m *Manifest) Verify(pub ed25519.PublicKey) error {
	const prefix = "ed25519:"
	if !strings.HasPrefix(m.Signature, prefix) {
		return errors.New("manifest signature is missing or uses an unknown scheme")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(m.Signature, prefix))
	if err != nil {
		return fmt.Errorf("manifest signature is not valid base64: %w", err)
	}
	if !ed25519.Verify(pub, m.signPayload(), sig) {
		return errors.New("manifest signature verification failed")
	}
	return nil
}

// Sign builds the signature field for the manifest. It exists for the channel
// tooling (the deploy workflow) and for tests — the daemon never holds a private
// key, so nothing in the shipped binary can call this with the real one.
func Sign(m *Manifest, priv ed25519.PrivateKey) {
	m.Signature = "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m.signPayload()))
}

// DiffEntry is one policy whose channel version differs from what the daemon
// currently runs.
type DiffEntry struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	FromVersion  int    `json:"from_version"`
	ToVersion    int    `json:"to_version"`
	DomainsAdded int    `json:"domains_added"`
	DomainsTotal int    `json:"domains_total"`
}

// Status is what the dashboard and the TUI show about the update channel.
type Status struct {
	BaseURL         string         `json:"base_url"`
	AutoApply       bool           `json:"auto_apply"`
	CurrentVersions map[string]int `json:"current_versions"`
	LastCheck       string         `json:"last_check,omitempty"`
	LastApply       string         `json:"last_apply,omitempty"`
	LastError       string         `json:"last_error,omitempty"`
	OverrideActive  bool           `json:"override_active"`
}

// Result is the outcome of one Apply call.
type Result struct {
	Applied  []DiffEntry `json:"applied"`
	HealthOK bool        `json:"health_ok"`
	Message  string      `json:"message"`
}

// persistedState is what survives a restart: the full policy files as applied.
// Storing the files themselves — not just versions — keeps the override alive
// on a host that boots offline.
type persistedState struct {
	AppliedAt string           `json:"applied_at"`
	Policies  []presets.Preset `json:"policies"`
}

const settingsKey = "preset_override"

// store is the subset of *database.DB the updater needs. The interface keeps
// the package testable without a bbolt file and keeps the dependency arrow
// pointing at the type, not the package.
type store interface {
	SetSetting(key string, val any) error
	GetSetting(key string, target any) error
	HasSetting(key string) bool
}

// Updater owns the channel state for one daemon. All mutation goes through mu;
// the matcher swap itself is atomic from the matchers' own lock.
type Updater struct {
	baseURL string
	pub     ed25519.PublicKey
	client  *http.Client
	matcher *matcher.Matcher
	db      store
	logf    func(string, ...any)

	mu        sync.Mutex
	versions  map[string]int            // policy ID -> currently active version
	applied   map[string]presets.Preset // policy ID -> applied override file
	previous  map[string]presets.Preset // rollback target (last applied set)
	autoApply bool
	lastCheck time.Time
	lastApply time.Time
	lastError string
}

// New builds an updater against the embedded baseline. baseURL may be empty to
// use DefaultBaseURL; pub may be nil to use the embedded channel key.
func New(baseURL string, pub ed25519.PublicKey, m *matcher.Matcher, db store, logf func(string, ...any)) *Updater {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	if pub == nil {
		pub = ChannelPubKey
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	u := &Updater{
		baseURL: baseURL,
		pub:     pub,
		client:  &http.Client{Timeout: 30 * time.Second},
		matcher: m,
		db:      db,
		logf:    logf,
		applied: make(map[string]presets.Preset),
	}
	u.rebuildVersions()
	return u
}

// baselineByID indexes the embedded baseline by policy ID.
func baselineByID() map[string]presets.Preset {
	out := make(map[string]presets.Preset, len(presets.All()))
	for _, p := range presets.All() {
		out[p.ID] = p
	}
	return out
}

// rebuildVersions recomputes the active version map: baseline versions overlaid
// with whatever the updater has applied.
func (u *Updater) rebuildVersions() {
	u.versions = make(map[string]int, len(presets.All()))
	for _, p := range presets.All() {
		u.versions[p.ID] = p.Version
	}
	for id, p := range u.applied {
		u.versions[id] = p.Version
	}
}

// SetAutoApply flips the opt-in automatic daily apply. Persisted by the caller
// (the settings layer owns that record).
func (u *Updater) SetAutoApply(on bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.autoApply = on
}

// AutoApply reports the opt-in state.
func (u *Updater) AutoApply() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.autoApply
}

// Status reports the channel state for the dashboard/TUI.
func (u *Updater) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	vers := make(map[string]int, len(u.versions))
	for k, v := range u.versions {
		vers[k] = v
	}
	st := Status{
		BaseURL:         u.baseURL,
		AutoApply:       u.autoApply,
		CurrentVersions: vers,
		OverrideActive:  len(u.applied) > 0,
	}
	if !u.lastCheck.IsZero() {
		st.LastCheck = u.lastCheck.UTC().Format(time.RFC3339)
	}
	if !u.lastApply.IsZero() {
		st.LastApply = u.lastApply.UTC().Format(time.RFC3339)
	}
	st.LastError = u.lastError
	return st
}

func (u *Updater) fetch(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	// Preset files are kilobytes; a runaway mirror cannot fill memory.
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// FetchManifest downloads and verifies the manifest. It is the only network
// call Check makes.
func (u *Updater) FetchManifest(ctx context.Context) (*Manifest, error) {
	raw, err := u.fetch(ctx, "manifest.json")
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Schema != 1 {
		return nil, fmt.Errorf("manifest schema %d is not supported by this daemon", m.Schema)
	}
	if err := m.Verify(u.pub); err != nil {
		return nil, err
	}
	return &m, nil
}

// Check returns the policies whose channel version is ahead of the active one.
// A version that is equal or lower is never a downgrade target — a stale mirror
// cannot roll the server back to an older list.
func (u *Updater) Check(ctx context.Context) ([]DiffEntry, error) {
	m, err := u.FetchManifest(ctx)
	if err != nil {
		u.mu.Lock()
		u.lastError = err.Error()
		u.lastCheck = time.Now()
		u.mu.Unlock()
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastCheck = time.Now()
	u.lastError = ""
	base := baselineByID()
	var out []DiffEntry
	for _, e := range m.Policies {
		current, known := u.versions[e.ID]
		if !known {
			// A policy the binary does not know cannot be toggled or health-checked
			// meaningfully; it ships with the next release instead.
			u.logf("[presetupd] manifest lists unknown policy %q — skipped until a daemon release carries it", e.ID)
			continue
		}
		if e.Version > current {
			out = append(out, DiffEntry{
				ID:          e.ID,
				Name:        base[e.ID].Name,
				FromVersion: current,
				ToVersion:   e.Version,
			})
		}
	}
	return out, nil
}

// Apply downloads the changed policy files, verifies every byte against the
// manifest, swaps the matcher catalog, health-checks it, persists the override,
// and rolls everything back on any failure.
func (u *Updater) Apply(ctx context.Context) (*Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	m, err := u.FetchManifest(ctx)
	if err != nil {
		u.lastError = err.Error()
		return nil, err
	}

	base := baselineByID()
	// Recompute the diff under the lock so two applies cannot race.
	var toFetch []ManifestEntry
	for _, e := range m.Policies {
		if _, known := base[e.ID]; !known {
			continue
		}
		if e.Version > u.versions[e.ID] {
			toFetch = append(toFetch, e)
		}
	}
	if len(toFetch) == 0 {
		return &Result{HealthOK: true, Message: "already up to date"}, nil
	}

	// Download and verify everything BEFORE touching the matcher.
	fresh := make(map[string]presets.Preset, len(toFetch))
	for _, e := range toFetch {
		raw, err := u.fetch(ctx, e.ID+".json")
		if err != nil {
			u.lastError = err.Error()
			return nil, fmt.Errorf("fetch %s.json: %w", e.ID, err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			u.lastError = "sha256 mismatch for " + e.ID
			return nil, fmt.Errorf("sha256 mismatch for policy %q — refusing to apply", e.ID)
		}
		var p presets.Preset
		if err := json.Unmarshal(raw, &p); err != nil {
			u.lastError = err.Error()
			return nil, fmt.Errorf("parse %s.json: %w", e.ID, err)
		}
		if p.ID != e.ID || p.Version != e.Version || len(p.Domains) == 0 {
			u.lastError = "invalid policy file for " + e.ID
			return nil, fmt.Errorf("policy file %q does not match its manifest entry", e.ID)
		}
		if p.Name != base[e.ID].Name {
			u.lastError = "name change rejected for " + e.ID
			return nil, fmt.Errorf("policy %q changed its display name — domain-only updates cannot rename a preset", e.ID)
		}
		fresh[e.ID] = p
	}

	// Build the next catalog: embedded baseline as fallback, plus every applied
	// override (old and new). The map handed to the matcher is fresh per apply.
	next := make(map[string][]string, len(base))
	for _, p := range presets.All() {
		next[p.Name] = p.Domains
	}
	merged := make(map[string]presets.Preset, len(u.applied)+len(fresh))
	for id, p := range u.applied {
		merged[id] = p
	}
	for id, p := range fresh {
		merged[id] = p
	}
	for id, p := range merged {
		next[base[id].Name] = p.Domains
	}

	prevApplied := u.applied
	u.matcher.SetCatalog(next)

	// Health check: the swapped catalog must still answer the probes the baseline
	// answered. A failure here means the channel served something incoherent —
	// roll straight back to what was running before.
	if hErr := u.healthCheck(); hErr != nil {
		u.matcher.SetCatalog(u.catalogFrom(prevApplied))
		u.lastError = hErr.Error()
		return nil, fmt.Errorf("post-apply health check failed, rolled back: %w", hErr)
	}

	u.previous = prevApplied
	u.applied = merged
	u.rebuildVersions()
	u.lastApply = time.Now()
	u.lastError = ""

	if u.db != nil {
		st := persistedState{
			AppliedAt: u.lastApply.UTC().Format(time.RFC3339),
			Policies:  make([]presets.Preset, 0, len(merged)),
		}
		for _, p := range merged {
			st.Policies = append(st.Policies, p)
		}
		if err := u.db.SetSetting(settingsKey, st); err != nil {
			// The live swap already succeeded and the matcher is healthy; a failed
			// persist only means the override dies with the process. Log it loudly.
			u.logf("[presetupd] could not persist preset override: %v (override lost on restart)", err)
		}
	}

	res := &Result{HealthOK: true, Message: "applied"}
	for _, e := range toFetch {
		res.Applied = append(res.Applied, DiffEntry{
			ID: e.ID, Name: base[e.ID].Name, FromVersion: u.versions[e.ID], ToVersion: e.Version,
			DomainsTotal: len(fresh[e.ID].Domains),
		})
	}
	return res, nil
}

// catalogFrom rebuilds a matcher catalog from a set of applied overrides.
func (u *Updater) catalogFrom(applied map[string]presets.Preset) map[string][]string {
	if len(applied) == 0 {
		return nil // nil = embedded baseline in the matcher
	}
	base := baselineByID()
	out := make(map[string][]string, len(base))
	for _, p := range presets.All() {
		out[p.Name] = p.Domains
	}
	for id, p := range applied {
		if b, ok := base[id]; ok {
			out[b.Name] = p.Domains
		}
	}
	return out
}

// healthCheck proves the active catalog still resolves the names it must.
// Two always-on presets (Riot, Epic) cover the proxy path; the count check
// catches a catalog that silently shrank.
func (u *Updater) healthCheck() error {
	probes := []struct {
		domain string
		rule   string
	}{
		{"riotgames.com", "Riot Games & Valorant"},
		{"epicgames.com", "Epic Games & Fortnite"},
	}
	for _, pr := range probes {
		action, rule := u.matcher.Match(pr.domain)
		if action != matcher.ActionProxy || rule != pr.rule {
			return fmt.Errorf("probe %s matched (%v, %q), want (PROXY, %q)", pr.domain, action, rule, pr.rule)
		}
	}
	sizes := u.matcher.CatalogSize()
	total := 0
	for _, n := range sizes {
		total += n
	}
	if total < 500 {
		return fmt.Errorf("catalog carries only %d domains — the baseline ships 942; refusing a shrunk catalog", total)
	}
	return nil
}

// Rollback restores the previous applied set (or the embedded baseline if the
// current override was the first).
func (u *Updater) Rollback() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.matcher.SetCatalog(u.catalogFrom(u.previous))
	u.applied = u.previous
	u.previous = nil
	u.rebuildVersions()
	if u.db != nil {
		if len(u.applied) == 0 {
			if err := u.db.SetSetting(settingsKey, persistedState{}); err != nil {
				return err
			}
		} else {
			st := persistedState{AppliedAt: time.Now().UTC().Format(time.RFC3339)}
			for _, p := range u.applied {
				st.Policies = append(st.Policies, p)
			}
			if err := u.db.SetSetting(settingsKey, st); err != nil {
				return err
			}
		}
	}
	return nil
}

// LoadPersisted re-applies the stored override at boot. A corrupt or incoherent
// record is dropped — the embedded baseline is always a safe place to start.
func (u *Updater) LoadPersisted() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.db == nil || !u.db.HasSetting(settingsKey) {
		return nil
	}
	var st persistedState
	if err := u.db.GetSetting(settingsKey, &st); err != nil {
		u.logf("[presetupd] stored preset override unreadable, starting from embedded baseline: %v", err)
		return nil
	}
	if len(st.Policies) == 0 {
		return nil
	}
	base := baselineByID()
	for _, p := range st.Policies {
		if _, ok := base[p.ID]; !ok {
			u.logf("[presetupd] stored override references unknown policy %q — dropped", p.ID)
			continue
		}
		if len(p.Domains) == 0 || p.Name != base[p.ID].Name {
			u.logf("[presetupd] stored override for %q is incoherent — dropped", p.ID)
			continue
		}
		u.applied[p.ID] = p
	}
	if len(u.applied) > 0 {
		u.matcher.SetCatalog(u.catalogFrom(u.applied))
	}
	u.rebuildVersions()
	return nil
}
