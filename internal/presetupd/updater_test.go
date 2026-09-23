package presetupd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"hyperdns/internal/core/matcher"
	"hyperdns/presets"
)

// fakeStore is the in-memory DB seam for the updater tests.
type fakeStore struct {
	data map[string][]byte
}

func newFakeStore() *fakeStore { return &fakeStore{data: make(map[string][]byte)} }

func (s *fakeStore) SetSetting(key string, val any) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return err
	}
	s.data[key] = raw
	return nil
}

func (s *fakeStore) GetSetting(key string, target any) error {
	raw, ok := s.data[key]
	if !ok {
		return nil
	}
	return json.Unmarshal(raw, target)
}

func (s *fakeStore) HasSetting(key string) bool {
	_, ok := s.data[key]
	return ok
}

// channelServer serves a signed manifest and policy files from a test keypair.
type channelServer struct {
	t       *testing.T
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	files   map[string][]byte // path -> bytes
	baseURL string
	srv     *httptest.Server
}

func newChannelServer(t *testing.T) *channelServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cs := &channelServer{t: t, priv: priv, pub: pub, files: make(map[string][]byte)}
	cs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[1:]
		if raw, ok := cs.files[path]; ok {
			w.Write(raw)
			return
		}
		http.NotFound(w, r)
	}))
	cs.baseURL = cs.srv.URL + "/"
	return cs
}

func (cs *channelServer) close() { cs.srv.Close() }

// setPolicy registers a policy file and re-signs the manifest covering the
// given entries.
func (cs *channelServer) setPolicy(p presets.Preset) {
	raw, err := json.Marshal(p)
	if err != nil {
		cs.t.Fatalf("marshal policy: %v", err)
	}
	cs.files[p.ID+".json"] = raw
}

func (cs *channelServer) signManifest(entries []ManifestEntry) {
	m := &Manifest{
		Schema:      1,
		GeneratedAt: "2026-09-24T00:00:00Z",
		BaseURL:     cs.baseURL,
		Policies:    entries,
	}
	Sign(m, cs.priv)
	raw, err := json.Marshal(m)
	if err != nil {
		cs.t.Fatalf("marshal manifest: %v", err)
	}
	cs.files["manifest.json"] = raw
}

func entryFor(p presets.Preset) ManifestEntry {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return ManifestEntry{ID: p.ID, Version: p.Version, SHA256: hex.EncodeToString(sum[:]), UpdatedAt: "2026-09-24T00:00:00Z"}
}

// cloneWithDomains returns a copy of a baseline policy with a new version and
// an extra domain appended.
func cloneWithDomains(t *testing.T, id string, version int, extra ...string) presets.Preset {
	t.Helper()
	for _, p := range presets.All() {
		if p.ID == id {
			cp := p
			cp.Domains = append(append([]string{}, p.Domains...), extra...)
			cp.Version = version
			return cp
		}
	}
	t.Fatalf("no baseline policy with id %q", id)
	return presets.Preset{}
}

func newUpdater(t *testing.T, cs *channelServer, db store) *Updater {
	t.Helper()
	return New(cs.baseURL, cs.pub, matcher.NewMatcher(), db, func(string, ...any) {})
}

func TestCheckReportsOnlyNewerVersions(t *testing.T) {
	cs := newChannelServer(t)
	defer cs.close()

	updated := cloneWithDomains(t, "epic", 2, "newhost.epicgames.example")
	cs.setPolicy(updated)
	cs.signManifest([]ManifestEntry{entryFor(updated)})

	u := newUpdater(t, cs, newFakeStore())
	diff, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(diff) != 1 || diff[0].ID != "epic" || diff[0].FromVersion != 1 || diff[0].ToVersion != 2 {
		t.Fatalf("unexpected diff: %+v", diff)
	}
}

func TestApplySwapsCatalogAndPersists(t *testing.T) {
	cs := newChannelServer(t)
	defer cs.close()

	updated := cloneWithDomains(t, "epic", 2, "newhost.epicgames.example")
	cs.setPolicy(updated)
	cs.signManifest([]ManifestEntry{entryFor(updated)})

	db := newFakeStore()
	u := newUpdater(t, cs, db)
	res, err := u.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.HealthOK || len(res.Applied) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}

	action, rule := u.matcher.Match("newhost.epicgames.example")
	if action != matcher.ActionProxy || rule != "Epic Games & Fortnite" {
		t.Fatalf("new domain not proxied after apply: (%v, %q)", action, rule)
	}
	if !db.HasSetting(settingsKey) {
		t.Fatalf("override was not persisted")
	}
}

func TestApplyRejectsBadSignature(t *testing.T) {
	cs := newChannelServer(t)
	defer cs.close()

	updated := cloneWithDomains(t, "epic", 2, "evil.example")
	cs.setPolicy(updated)
	// Sign with a different key — the daemon's embedded key must not accept it.
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	m := &Manifest{Schema: 1, GeneratedAt: "2026-09-24T00:00:00Z", BaseURL: cs.baseURL,
		Policies: []ManifestEntry{entryFor(updated)}}
	Sign(m, wrongPriv)
	raw, _ := json.Marshal(m)
	cs.files["manifest.json"] = raw

	u := newUpdater(t, cs, newFakeStore())
	if _, err := u.Apply(context.Background()); err == nil {
		t.Fatalf("Apply accepted a manifest signed by the wrong key")
	}
	action, _ := u.matcher.Match("evil.example")
	if action == matcher.ActionProxy {
		t.Fatalf("unsigned catalog reached the matcher")
	}
}

func TestApplyRejectsSHA256Mismatch(t *testing.T) {
	cs := newChannelServer(t)
	defer cs.close()

	updated := cloneWithDomains(t, "epic", 2, "evil.example")
	cs.setPolicy(updated)
	entry := entryFor(updated)
	entry.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	cs.signManifest([]ManifestEntry{entry})

	u := newUpdater(t, cs, newFakeStore())
	if _, err := u.Apply(context.Background()); err == nil {
		t.Fatalf("Apply accepted a file whose hash does not match the manifest")
	}
	action, _ := u.matcher.Match("evil.example")
	if action == matcher.ActionProxy {
		t.Fatalf("hash-mismatched catalog reached the matcher")
	}
}

func TestApplyRejectsDowngrade(t *testing.T) {
	cs := newChannelServer(t)
	defer cs.close()

	// First apply version 2...
	v2 := cloneWithDomains(t, "epic", 2, "v2.example")
	cs.setPolicy(v2)
	cs.signManifest([]ManifestEntry{entryFor(v2)})
	u := newUpdater(t, cs, newFakeStore())
	if _, err := u.Apply(context.Background()); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// ...then a stale mirror serves version 1 again. It must not roll back.
	v1 := cloneWithDomains(t, "epic", 1)
	cs.setPolicy(v1)
	cs.signManifest([]ManifestEntry{entryFor(v1)})
	diff, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(diff) != 0 {
		t.Fatalf("downgrade offered: %+v", diff)
	}
	if action, _ := u.matcher.Match("v2.example"); action != matcher.ActionProxy {
		t.Fatalf("downgrade silently rolled the catalog back")
	}
}

func TestRollbackRestoresBaseline(t *testing.T) {
	cs := newChannelServer(t)
	defer cs.close()

	updated := cloneWithDomains(t, "epic", 2, "newhost.epicgames.example")
	cs.setPolicy(updated)
	cs.signManifest([]ManifestEntry{entryFor(updated)})

	u := newUpdater(t, cs, newFakeStore())
	if _, err := u.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := u.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if action, _ := u.matcher.Match("newhost.epicgames.example"); action == matcher.ActionProxy {
		t.Fatalf("rollback left the override active")
	}
	// Baseline behavior intact:
	if action, rule := u.matcher.Match("epicgames.com"); action != matcher.ActionProxy || rule != "Epic Games & Fortnite" {
		t.Fatalf("baseline broken after rollback: (%v, %q)", action, rule)
	}
}

func TestLoadPersistedReappliesAfterRestart(t *testing.T) {
	cs := newChannelServer(t)
	defer cs.close()

	updated := cloneWithDomains(t, "epic", 2, "newhost.epicgames.example")
	cs.setPolicy(updated)
	cs.signManifest([]ManifestEntry{entryFor(updated)})

	db := newFakeStore()
	u1 := newUpdater(t, cs, db)
	if _, err := u1.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Fresh updater over the same store = a daemon restart.
	u2 := newUpdater(t, cs, db)
	if err := u2.LoadPersisted(); err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	if action, _ := u2.matcher.Match("newhost.epicgames.example"); action != matcher.ActionProxy {
		t.Fatalf("persisted override did not survive the restart")
	}
}

func TestFetchManifestRefusesHTTP404(t *testing.T) {
	cs := newChannelServer(t)
	defer cs.close()
	// No manifest registered — 404 must not be parsed as a catalog.
	u := newUpdater(t, cs, newFakeStore())
	if _, err := u.FetchManifest(context.Background()); err == nil {
		t.Fatalf("404 manifest was accepted")
	}
}
