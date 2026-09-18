package database

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// The six runtime-mutable fields of ServerSettings are written by HTTP handlers in
// two different packages and read on the REST authorization hot path. A Go string
// is a pointer plus a length, written non-atomically, so an unsynchronised read
// during a rotation can observe a value that was never assigned — and that value
// is then compared against a caller-supplied API key. These tests pin the accessor
// layer that closes it.
//
// The race detector is unavailable in this environment (no C toolchain), so the
// concurrent cases below are stress substitutes, not proof of race-freedom: they
// assert that every value a reader observes is one that was really assigned and
// that memory and storage never disagree. Run them under `go test -race` once a
// compiler is available.

// errFakePersist stands in for a failed database write.
var errFakePersist = errors.New("simulated persist failure")

func TestNilReceiverAccessorsAreSafe(t *testing.T) {
	var s *ServerSettings // a daemon wired up wrong, or a partially built test double

	if got := s.GetAPIKey(); got != "" {
		t.Errorf("GetAPIKey on a nil receiver = %q, want empty", got)
	}
	// "" is not "0.0.0.0", and the REST middleware treats anything but "0.0.0.0"
	// as "loopback only". A missing configuration must fail closed, not open.
	if got := s.GetAPIBind(); got != "" {
		t.Errorf("GetAPIBind on a nil receiver = %q, want empty so the gate stays shut", got)
	}
	if got := s.GetPublicIP(); got != "" {
		t.Errorf("GetPublicIP on a nil receiver = %q, want empty", got)
	}
	if ip, bind := s.Endpoint(); ip != "" || bind != "" {
		t.Errorf("Endpoint on a nil receiver = %q/%q, want empty", ip, bind)
	}
	if user, verifier, weak := s.AdminCredentials(); user != "" || verifier != "" || weak {
		t.Errorf("AdminCredentials on a nil receiver = %q/%q/%v, want empty", user, verifier, weak)
	}
	if snap := s.Snapshot(); snap != (ServerSettingsSnapshot{}) {
		t.Errorf("Snapshot on a nil receiver = %+v, want the zero value", snap)
	}

	// A nil receiver is a wiring bug, so it must be reported rather than silently
	// swallowed — and neither callback may run against nothing.
	mutated, persisted := false, false
	err := s.UpdateAndPersist(
		func(*MutableSettings) { mutated = true },
		func(*ServerSettings) error { persisted = true; return nil },
	)
	if !errors.Is(err, ErrSettingsNil) {
		t.Errorf("UpdateAndPersist on a nil receiver returned %v, want ErrSettingsNil", err)
	}
	if mutated || persisted {
		t.Errorf("callbacks ran on a nil receiver (mutate=%v persist=%v)", mutated, persisted)
	}

	// Same contract for the port writer. Its callback is handed a freshly built
	// record to store, so running it against a nil receiver would persist a record
	// with an empty admin password verifier over a good one.
	persisted = false
	if err := s.PersistWebPort(9090, func(*ServerSettings) error { persisted = true; return nil }); !errors.Is(err, ErrSettingsNil) {
		t.Errorf("PersistWebPort on a nil receiver returned %v, want ErrSettingsNil", err)
	}
	if persisted {
		t.Error("PersistWebPort ran its persist callback on a nil receiver, which would " +
			"store a record built from nothing")
	}
}

// fullSettings is a populated ServerSettings, built by pointer because copying one
// by value would copy its mutex — which is what `go vet`'s copylocks check exists
// to catch.
func fullSettings() *ServerSettings {
	return &ServerSettings{
		PublicIP:           "203.0.113.9",
		BindHost:           "0.0.0.0",
		WebPort:            8080,
		AdminUsername:      "admin",
		AdminPassword:      "pbkdf2-sha256$600000$c2FsdHNhbHQ$aGFzaGhhc2g",
		AdminPasswordWeak:  true,
		APIKey:             "hdns_live_0123456789abcdef",
		APIBind:            "127.0.0.1",
		AdminPath:          "a1b2c3d4e5f67890",
		SessionIdleMinutes: 30,
		TrustedProxyCIDRs:  []string{"10.0.0.0/8"},
	}
}

func TestSnapshotCarriesNoPasswordVerifier(t *testing.T) {
	s := fullSettings()
	_, verifier, _ := s.AdminCredentials()

	// The verifier used to be serialised into three responses, because it was a
	// field of the struct the settings page rendered. The type feeding that page
	// must not carry it at all; checking the field name is what turns putting it
	// back into a failing test instead of a quiet regression.
	st := reflect.TypeOf(s.Snapshot())
	for i := range st.NumField() {
		if st.Field(i).Name == "AdminPassword" {
			t.Fatal("ServerSettingsSnapshot declares AdminPassword; the verifier must never reach a response")
		}
	}

	v := reflect.ValueOf(s.Snapshot())
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), verifier) {
			t.Errorf("snapshot field %s carries the password verifier", st.Field(i).Name)
		}
	}
}

func TestSnapshotReportsTheCurrentValues(t *testing.T) {
	s := fullSettings()

	want := ServerSettingsSnapshot{
		PublicIP:           "203.0.113.9",
		BindHost:           "0.0.0.0",
		WebPort:            8080,
		AdminUsername:      "admin",
		AdminPasswordWeak:  true,
		APIKey:             "hdns_live_0123456789abcdef",
		APIBind:            "127.0.0.1",
		AdminPath:          "a1b2c3d4e5f67890",
		SessionIdleMinutes: 30,
	}
	if got := s.Snapshot(); got != want {
		t.Errorf("Snapshot() = %+v, want %+v", got, want)
	}
}

func TestUpdateAndPersistAppliesBeforeItStores(t *testing.T) {
	s := fullSettings()

	// persist runs with the lock held and is documented as receiving the struct
	// with the new values already in place — that is what lets it be a plain
	// db.SetSetting("server", s), which marshals the fields directly. It reads them
	// raw here for the same reason: calling an accessor would deadlock.
	var seenKey, seenBind string
	err := s.UpdateAndPersist(
		func(m *MutableSettings) {
			m.APIKey = "hdns_live_rotated"
			m.APIBind = "0.0.0.0"
		},
		func(cur *ServerSettings) error {
			seenKey, seenBind = cur.APIKey, cur.APIBind
			return nil
		},
	)
	if err != nil {
		t.Fatalf("UpdateAndPersist: %v", err)
	}
	if seenKey != "hdns_live_rotated" || seenBind != "0.0.0.0" {
		t.Errorf("persist saw %q/%q, want the new values already applied", seenKey, seenBind)
	}
	if got := s.GetAPIKey(); got != "hdns_live_rotated" {
		t.Errorf("GetAPIKey after a successful update = %q", got)
	}
	if got := s.GetAPIBind(); got != "0.0.0.0" {
		t.Errorf("GetAPIBind after a successful update = %q", got)
	}
	// Fields the callback did not touch must survive it: a bind-only save that
	// blanked the advertised IP is exactly the bug the copy-then-apply shape avoids.
	if got := s.GetPublicIP(); got != "203.0.113.9" {
		t.Errorf("public_ip = %q after an unrelated update, want it untouched", got)
	}
}

func TestUpdateAndPersistRestoresEveryFieldOnFailure(t *testing.T) {
	s := fullSettings()
	want := s.Snapshot()
	_, wantVerifier, _ := s.AdminCredentials()

	err := s.UpdateAndPersist(
		func(m *MutableSettings) {
			m.PublicIP = "198.51.100.1"
			m.APIBind = "0.0.0.0"
			m.APIKey = "hdns_live_rotated"
			m.AdminUsername = "root"
			m.AdminPassword = "pbkdf2-sha256$600000$bmV3c2FsdA$bmV3aGFzaA"
			m.AdminPasswordWeak = false
		},
		func(*ServerSettings) error { return errFakePersist },
	)
	if !errors.Is(err, errFakePersist) {
		t.Fatalf("UpdateAndPersist returned %v, want the persist error unwrapped", err)
	}

	// A failed write that leaves the new credential in memory is worse than a
	// failed write: the operator's integrations work until the next restart and
	// then fail together.
	if got := s.Snapshot(); got != want {
		t.Errorf("after a failed persist Snapshot() = %+v, want %+v", got, want)
	}
	if _, got, _ := s.AdminCredentials(); got != wantVerifier {
		t.Errorf("password verifier = %q after a failed persist, want it restored", got)
	}
}

func TestUpdateAndPersistToleratesNilCallbacks(t *testing.T) {
	s := fullSettings()
	want := s.Snapshot()

	if err := s.UpdateAndPersist(nil, nil); err != nil {
		t.Fatalf("UpdateAndPersist(nil, nil) = %v, want nil", err)
	}
	if got := s.Snapshot(); got != want {
		t.Errorf("settings changed with no mutate callback: %+v", got)
	}

	// A caller that only wants the in-memory value changed — the TUI's own edits,
	// say — passes no persist function and must not be told the write failed.
	if err := s.UpdateAndPersist(func(m *MutableSettings) { m.PublicIP = "198.51.100.1" }, nil); err != nil {
		t.Fatalf("UpdateAndPersist with no persist callback = %v, want nil", err)
	}
	if got := s.GetPublicIP(); got != "198.51.100.1" {
		t.Errorf("public_ip = %q, want the mutated value", got)
	}
}

// The lost update the hand-rolled rollbacks could not fix: rotation A remembers
// the pre-A key, rotation B applies and persists successfully, then A's persist
// fails and A restores its remembered value over B's. Memory then serves a key the
// database has never heard of. Because UpdateAndPersist holds the write lock across
// mutate, persist and rollback, B cannot begin until A has finished either way — so
// the invariant is that the in-memory key always equals the last one stored.
func TestConcurrentRotationsKeepMemoryAndStorageInAgreement(t *testing.T) {
	const (
		writers = 8
		rounds  = 250
		seed    = "hdns_live_seed"
	)
	s := &ServerSettings{APIKey: seed, APIBind: "127.0.0.1"}

	var mu sync.Mutex
	stored := seed

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range rounds {
				key := fmt.Sprintf("hdns_live_%d_%d", w, i)
				// Every fourth write fails. A run where they all succeed would pass
				// even with the broken rollback in place.
				fail := i%4 == 3
				_ = s.UpdateAndPersist(
					func(m *MutableSettings) { m.APIKey = key },
					func(cur *ServerSettings) error {
						if fail {
							return errFakePersist
						}
						mu.Lock()
						stored = cur.APIKey
						mu.Unlock()
						return nil
					},
				)
			}
		}(w)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if got := s.GetAPIKey(); got != stored {
		t.Errorf("in-memory key %q does not match the last stored key %q", got, stored)
	}
}

// A reader must never see a value that was not assigned. Without the accessors a
// read racing a write can observe the new string pointer with the old length —
// bytes that were never a key — and the REST middleware compares exactly this
// against what the caller sent. The detector is unavailable here, so this asserts
// the observable consequence instead: every value seen is one that was written, and
// Endpoint's pair is never mixed from two different moments.
func TestReadersOnlyObserveAssignedValues(t *testing.T) {
	pairs := [2][2]string{
		{"203.0.113.9", "127.0.0.1"},
		{"198.51.100.1", "0.0.0.0"},
	}
	keys := [2]string{"hdns_live_aaaaaaaaaaaaaaaa", "hdns_live_bb"} // deliberately different lengths

	s := &ServerSettings{PublicIP: pairs[0][0], APIBind: pairs[0][1], APIKey: keys[0]}

	done := make(chan struct{})
	var writer, readers sync.WaitGroup

	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			p := pairs[i%2]
			_ = s.UpdateAndPersist(func(m *MutableSettings) {
				m.PublicIP, m.APIBind, m.APIKey = p[0], p[1], keys[i%2]
			}, nil)
		}
	}()

	for r := range 4 {
		readers.Add(1)
		go func(r int) {
			defer readers.Done()
			for range 20000 {
				ip, bind := s.Endpoint()
				if ip != pairs[0][0] && ip != pairs[1][0] {
					t.Errorf("reader %d saw public_ip %q, which was never assigned", r, ip)
					return
				}
				// Endpoint takes one lock for both fields precisely so a caller
				// reporting them together cannot describe two different moments.
				if (ip == pairs[0][0]) != (bind == pairs[0][1]) {
					t.Errorf("reader %d saw the mixed pair %q/%q", r, ip, bind)
					return
				}
				if k := s.GetAPIKey(); k != keys[0] && k != keys[1] {
					t.Errorf("reader %d saw api_key %q, which was never assigned", r, k)
					return
				}
			}
		}(r)
	}

	// The readers set the duration of the test; the writer runs until they are done.
	readers.Wait()
	close(done)
	writer.Wait()
}
