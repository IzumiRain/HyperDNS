package service

import (
	"path/filepath"
	"testing"

	"hyperdns/internal/core/matcher"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

func newGroupTestDeps(t *testing.T) (*database.DB, *matcher.Matcher) {
	t.Helper()
	dir := t.TempDir()
	cipher, err := crypto.LoadOrGenerateMasterKey(filepath.Join(dir, "g.key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	db, err := database.Open(filepath.Join(dir, "g.db"), cipher)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, matcher.NewMatcher()
}

func TestCustomGroupServiceCreateAppliesToMatcher(t *testing.T) {
	db, m := newGroupTestDeps(t)
	svc := NewCustomGroupService(db, m)

	g, err := svc.Create("Bundle", "block", []string{"Ads.Test", "ads.test", " "}, true)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Domains are normalised: lowercased, de-duplicated, blanks dropped.
	if len(g.Domains) != 1 || g.Domains[0] != "ads.test" {
		t.Fatalf("domains not normalised: %v", g.Domains)
	}
	if action, _ := m.Match("ads.test"); action != matcher.ActionBlock {
		t.Fatalf("group did not reach the matcher as a block")
	}
}

func TestCustomGroupServiceRejectsBadInput(t *testing.T) {
	db, m := newGroupTestDeps(t)
	svc := NewCustomGroupService(db, m)

	if _, err := svc.Create("", "proxy", []string{"a.test"}, true); err == nil {
		t.Error("empty name accepted")
	}
	if _, err := svc.Create("X", "teleport", []string{"a.test"}, true); err == nil {
		t.Error("invalid action accepted")
	}
	if _, err := svc.Create("X", "proxy", []string{"  "}, true); err == nil {
		t.Error("group with no usable domain accepted")
	}
}

func TestCustomGroupServiceUpdateAndDelete(t *testing.T) {
	db, m := newGroupTestDeps(t)
	svc := NewCustomGroupService(db, m)

	g, err := svc.Create("Bundle", "proxy", []string{"a.test"}, true)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Update to a block action on a new domain. Block is distinguishable from the
	// matcher's default (an unmatched name resolves DIRECT), so "active" and
	// "gone" are not the same verdict.
	if _, err := svc.Update(g.ID, "Bundle2", "block", []string{"b.test"}, true); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if action, _ := m.Match("b.test"); action != matcher.ActionBlock {
		t.Fatalf("update did not re-apply to the matcher")
	}
	// Old domain is gone from the group — no longer proxied.
	if action, _ := m.Match("a.test"); action == matcher.ActionProxy {
		t.Fatalf("old domain still proxied after update")
	}
	if err := svc.Delete(g.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if action, _ := m.Match("b.test"); action == matcher.ActionBlock {
		t.Fatalf("group still active after delete")
	}
	if err := svc.Delete("nonexistent"); err == nil {
		t.Error("deleting an unknown id should error")
	}
}

func TestCustomGroupServiceReloadsFromDBAtStartup(t *testing.T) {
	db, m1 := newGroupTestDeps(t)
	svc1 := NewCustomGroupService(db, m1)
	if _, err := svc1.Create("Persisted", "block", []string{"x.test"}, true); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A second service over the same DB is a restart: the group must re-apply.
	m2 := matcher.NewMatcher()
	_ = NewCustomGroupService(db, m2)
	if action, _ := m2.Match("x.test"); action != matcher.ActionBlock {
		t.Fatalf("group did not survive a restart")
	}
}
