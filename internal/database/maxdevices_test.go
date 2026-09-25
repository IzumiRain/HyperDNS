package database

import (
	"path/filepath"
	"testing"

	"hyperdns/internal/crypto"
)

func newMaxDevDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	cipher, err := crypto.LoadOrGenerateMasterKey(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	db, err := Open(filepath.Join(dir, "d.db"), cipher)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestNormalizeMaxDevices(t *testing.T) {
	cases := map[int]int{-3: 1, 0: 1, 1: 1, 3: 3, 5: 5, 6: 5, 99: 5}
	for in, want := range cases {
		if got := NormalizeMaxDevices(in); got != want {
			t.Errorf("NormalizeMaxDevices(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestRegisterIPMultiDeviceEviction: a 3-device account keeps the three most
// recent addresses and evicts the oldest when a fourth arrives.
func TestRegisterIPMultiDeviceEviction(t *testing.T) {
	db := newMaxDevDB(t)
	c := Client{ID: "c1", Token: "t1", MaxDevices: 3, Enabled: true, RegisterSecret: "s"}
	if err := db.SaveClient(c); err != nil {
		t.Fatalf("save: %v", err)
	}

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if _, _, err := db.RegisterIPForClient("c1", ip); err != nil {
			t.Fatalf("register %s: %v", ip, err)
		}
	}
	got, _ := db.GetClient("c1")
	if len(got.AllowedIPs) != 3 {
		t.Fatalf("want 3 IPs, got %v", got.AllowedIPs)
	}

	// The fourth evicts the oldest (1.1.1.1).
	if _, _, err := db.RegisterIPForClient("c1", "4.4.4.4"); err != nil {
		t.Fatalf("register 4th: %v", err)
	}
	got, _ = db.GetClient("c1")
	if len(got.AllowedIPs) != 3 {
		t.Fatalf("want 3 IPs after eviction, got %v", got.AllowedIPs)
	}
	for _, ip := range got.AllowedIPs {
		if ip == "1.1.1.1" {
			t.Errorf("oldest address was not evicted: %v", got.AllowedIPs)
		}
	}
	if got.AllowedIPs[len(got.AllowedIPs)-1] != "4.4.4.4" {
		t.Errorf("newest address is not last: %v", got.AllowedIPs)
	}
}

// TestRegisterIPDefaultSingleDevice: MaxDevices 0 behaves as the old single-IP
// path — each new address replaces the last.
func TestRegisterIPDefaultSingleDevice(t *testing.T) {
	db := newMaxDevDB(t)
	c := Client{ID: "c2", Token: "t2", Enabled: true, RegisterSecret: "s"} // MaxDevices 0
	if err := db.SaveClient(c); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, _, err := db.RegisterIPForClient("c2", "1.1.1.1"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, _, err := db.RegisterIPForClient("c2", "2.2.2.2"); err != nil {
		t.Fatalf("register: %v", err)
	}
	got, _ := db.GetClient("c2")
	if len(got.AllowedIPs) != 1 || got.AllowedIPs[0] != "2.2.2.2" {
		t.Fatalf("default single-device broke: %v", got.AllowedIPs)
	}
}

// TestRegisterIPConflictStillRefusedWithMultiDevice: the C-04 cross-account
// guard survives multi-device — an address held by a different account is still
// refused.
func TestRegisterIPConflictStillRefusedWithMultiDevice(t *testing.T) {
	db := newMaxDevDB(t)
	if err := db.SaveClient(Client{ID: "a", Token: "ta", MaxDevices: 3, Enabled: true, RegisterSecret: "s", AllowedIPs: []string{"9.9.9.9"}}); err != nil {
		t.Fatalf("save a: %v", err)
	}
	if err := db.SaveClient(Client{ID: "b", Token: "tb", MaxDevices: 3, Enabled: true, RegisterSecret: "s"}); err != nil {
		t.Fatalf("save b: %v", err)
	}
	_, _, err := db.RegisterIPForClient("b", "9.9.9.9")
	if err == nil {
		t.Fatal("binding another account's address should be refused")
	}
}
