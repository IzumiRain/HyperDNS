package database

import (
	"reflect"
	"testing"
)

// PersistWebPort writes a record the daemon will read back on its next start, and
// it builds that record with a field-by-field literal because ServerSettings holds
// a mutex and cannot be copied by value. A literal cannot notice a field somebody
// adds to the struct later, and the consequence of missing one is not a cosmetic
// gap in a settings page:
//
//   - AdminPassword omitted → the next start finds no password, generates one,
//     prints it to the log, and the operator is locked out of the panel whose port
//     they were changing.
//   - APIKey omitted → every bot and billing hook gets 401 after the restart.
//   - PublicIP omitted → the resolver answers proxied domains with "", and every
//     redirect breaks.
//
// Each of those is a silent, delayed failure that only appears on the restart the
// operator was told to perform, which is the worst possible moment to discover it.
// So the field list is checked by reflection rather than by eye.

// TestPersistWebPortCarriesEveryField fails when a field of ServerSettings is not
// copied into the stored record.
//
// The mechanism is a fully populated source struct and a zero-value check on the
// clone: reflection walks the type, so a field added tomorrow is covered the moment
// it exists. It also compares the values, which catches the other half — a field
// copied into the wrong slot.
func TestPersistWebPortCarriesEveryField(t *testing.T) {
	src := fullSettings()

	// Every exported field of fullSettings must be non-zero for the check below to
	// mean anything: a field left at its zero value in the fixture would pass the
	// clone's zero-value test no matter what PersistWebPort does. This is the guard
	// on the guard.
	//
	// The walk goes through the pointer — TypeFor and ValueOf(src).Elem() — rather
	// than through *src. Dereferencing here would copy the struct's mutex, which is
	// the copylocks violation `go vet` reports, and the vet run is part of this
	// package's gate.
	typ := reflect.TypeFor[ServerSettings]()
	sv := reflect.ValueOf(src).Elem()
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if sv.Field(i).IsZero() {
			t.Fatalf("the fullSettings fixture leaves %s at its zero value, so this test "+
				"cannot tell a copied field from a dropped one — populate it", f.Name)
		}
	}

	const newPort = 9443
	var stored *ServerSettings
	if err := src.PersistWebPort(newPort, func(rec *ServerSettings) error {
		stored = rec
		return nil
	}); err != nil {
		t.Fatalf("PersistWebPort returned %v", err)
	}
	if stored == nil {
		t.Fatal("PersistWebPort never called its persist callback, so nothing was stored")
	}

	tv := reflect.ValueOf(stored).Elem()
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		got, want := tv.Field(i).Interface(), sv.Field(i).Interface()

		if f.Name == "WebPort" {
			if got != newPort {
				t.Errorf("the stored record has WebPort %v, want the new port %d — "+
					"PersistWebPort is writing the old one", got, newPort)
			}
			continue
		}
		// Slice fields cannot be compared with == (a runtime panic); reflect
		// does the deep comparison for them.
		if f.Type.Kind() == reflect.Slice {
			if !reflect.DeepEqual(got, want) {
				t.Errorf("the stored record has %s = %#v, want %#v. A field the clone does "+
					"not mention is dropped from the database on the next write, and it comes back as "+
					"the zero value on the restart the operator was just told to perform.",
					f.Name, got, want)
			}
			continue
		}
		if got != want {
			t.Errorf("the stored record has %s = %#v, want %#v. A field the clone does not "+
				"mention is dropped from the database on the next write, and it comes back as "+
				"the zero value on the restart the operator was just told to perform.",
				f.Name, got, want)
		}
	}
}

// TestPersistWebPortLeavesTheRunningRecordAlone is the whole point of the method.
//
// The listener is already bound by the time an operator can reach this menu, so
// there is no assignment that moves it. Writing the new value into the live struct
// would leave the process serving the old port while the console banner, the
// subscriber portal URLs and the 1-click register links — all of which read
// WebPort directly — advertised the new one. Every subscriber handed such a link
// would get a connection refused.
func TestPersistWebPortLeavesTheRunningRecordAlone(t *testing.T) {
	s := fullSettings()
	before := s.Snapshot()

	if err := s.PersistWebPort(9443, func(*ServerSettings) error { return nil }); err != nil {
		t.Fatalf("PersistWebPort returned %v", err)
	}

	if after := s.Snapshot(); after != before {
		t.Errorf("PersistWebPort changed the live settings: %+v became %+v. The port it "+
			"stores takes effect on the next start; mutating the running value only makes "+
			"the daemon misreport the port it is actually listening on.", before, after)
	}
	// The verifier is outside Snapshot on purpose, so it needs its own look.
	if _, verifier, _ := s.AdminCredentials(); verifier != fullSettings().AdminPassword {
		t.Errorf("PersistWebPort altered the in-memory password verifier (%q) — the running "+
			"process would stop accepting the password it accepted a moment ago", verifier)
	}
}

// TestPersistWebPortReportsAFailedWrite keeps a failed write from reading as a
// success.
//
// The operator's next action after this returns is `systemctl restart hyperdns`.
// If the write failed and they were told it succeeded, they restart expecting the
// panel on a new port and find it on the old one — with no error anywhere to
// explain why.
func TestPersistWebPortReportsAFailedWrite(t *testing.T) {
	s := fullSettings()

	if err := s.PersistWebPort(9443, func(*ServerSettings) error { return errFakePersist }); err == nil {
		t.Fatal("PersistWebPort swallowed a failed database write and returned nil")
	}
	// Nothing to roll back — the live struct was never touched — but the value the
	// daemon is serving on must still be the one it was serving on before.
	if s.Snapshot().WebPort != 8080 {
		t.Errorf("the live WebPort is %d after a failed write, want the unchanged 8080",
			s.Snapshot().WebPort)
	}
}

// TestPersistWebPortWithNoCallbackDoesNothing covers the wiring mistake rather
// than the operator error: a nil persist is a caller that forgot to pass the
// database writer, and answering nil would report a change nobody stored.
func TestPersistWebPortWithNoCallbackDoesNothing(t *testing.T) {
	s := fullSettings()
	if err := s.PersistWebPort(9443, nil); err != nil {
		t.Errorf("PersistWebPort(port, nil) returned %v, want nil", err)
	}
	if s.Snapshot().WebPort != 8080 {
		t.Error("PersistWebPort mutated the live WebPort when handed no persist callback")
	}
}
