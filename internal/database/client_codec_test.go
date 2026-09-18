package database

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A Client field has to be added in three places — the struct, encClient, and both
// halves of the codec — and forgetting any of them drops the value on the next save
// with no error anywhere. The failure is invisible until an operator notices that a
// setting they changed came back as it was.
//
// These tests fill every field reflectively rather than by hand, so a field added
// later is covered without anybody remembering to extend them: an unhandled type
// fails loudly, and a handled type that the codec does not carry comes back as a
// zero and is reported by name.

// clientFieldFixupHint is what a failure has to tell whoever reads it, because the
// fix is never in this file.
const clientFieldFixupHint = "add it to encClient, to the packClient literal and to the unpackClient return in client_repo.go"

// fillClient sets every exported field of a Client to a distinctive non-zero
// value. Distinct per field, so a codec that carries the right number of fields but
// crosses two of them is caught as well.
func fillClient(t *testing.T, c *Client) {
	t.Helper()

	v := reflect.ValueOf(c).Elem()
	typ := v.Type()
	base := time.Date(2026, 3, 31, 12, 34, 56, 789000000, time.UTC)
	timeType := reflect.TypeFor[time.Time]()
	strSliceType := reflect.TypeFor[[]string]()

	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		fv := v.Field(i)
		n := i + 1

		switch {
		case f.Type == timeType:
			// Whole seconds plus a nanosecond component, in UTC: JSON carries
			// RFC 3339 with nanoseconds, so anything finer would fail for a reason
			// that has nothing to do with the codec.
			fv.Set(reflect.ValueOf(base.AddDate(0, 0, n)))
		case f.Type == strSliceType:
			fv.Set(reflect.ValueOf([]string{fmt.Sprintf("%s-%d", strings.ToLower(f.Name), n)}))
		case f.Type.Kind() == reflect.String:
			fv.SetString(fmt.Sprintf("%s-%d", strings.ToLower(f.Name), n))
		case f.Type.Kind() == reflect.Uint64:
			fv.SetUint(uint64(n) * 1_000)
		case f.Type.Kind() == reflect.Float64:
			fv.SetFloat(float64(n) + 0.25)
		case f.Type.Kind() == reflect.Bool:
			fv.SetBool(true)
		default:
			t.Fatalf("Client.%s is a %s, a type this test cannot fill.\n"+
				"Teach fillClient about it, then make sure the codec carries it: %s",
				f.Name, f.Type, clientFieldFixupHint)
		}

		if fv.IsZero() {
			t.Fatalf("fillClient left Client.%s (%s) at its zero value, so the codec could drop it undetected",
				f.Name, f.Type)
		}
	}
}

// diffClientFields reports every field the round trip failed to carry, by name.
func diffClientFields(t *testing.T, want, got Client, via string) {
	t.Helper()

	wv := reflect.ValueOf(want)
	gv := reflect.ValueOf(got)
	typ := wv.Type()
	timeType := reflect.TypeFor[time.Time]()

	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		w, g := wv.Field(i), gv.Field(i)

		equal := false
		if f.Type == timeType {
			// Equal rather than DeepEqual: a time that survived JSON has no monotonic
			// reading, and a location pointer can differ while the instant does not.
			equal = w.Interface().(time.Time).Equal(g.Interface().(time.Time))
		} else {
			equal = reflect.DeepEqual(w.Interface(), g.Interface())
		}
		if equal {
			continue
		}
		if g.IsZero() {
			t.Errorf("%s dropped Client.%s: stored %v, read back the zero value.\n%s",
				via, f.Name, w.Interface(), clientFieldFixupHint)
			continue
		}
		t.Errorf("%s changed Client.%s: stored %v, read back %v", via, f.Name, w.Interface(), g.Interface())
	}
}

// The codec on its own, with no bbolt in the way, so a failure points at
// packClient/unpackClient rather than at storage.
func TestClientCodecCarriesEveryField(t *testing.T) {
	db := clientsFixture(t)

	var want Client
	fillClient(t, &want)

	blob, err := db.packClient(want)
	if err != nil {
		t.Fatalf("packClient: %v", err)
	}
	got, err := db.unpackClient(blob)
	if err != nil {
		t.Fatalf("unpackClient: %v", err)
	}
	diffClientFields(t, want, *got, "the client codec")
}

// And the same through the public path an operator's edit actually takes, because
// SaveClient may fill a field in before packing and GetClient is what every caller
// reads through.
func TestSaveClientCarriesEveryField(t *testing.T) {
	db := clientsFixture(t)

	var want Client
	fillClient(t, &want)

	if err := db.SaveClient(want); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	got, err := db.GetClient(want.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	diffClientFields(t, want, *got, "a save and reload")

	// A traffic flush rewrites the record through the same codec, so it must not be
	// a way to lose a field either — it is the most frequent write on a busy box.
	if unapplied, err := db.AddClientTraffic(map[string]uint64{want.ID: 500}); err != nil || len(unapplied) != 0 {
		t.Fatalf("AddClientTraffic = %v, %v", unapplied, err)
	}
	flushed, err := db.GetClient(want.ID)
	if err != nil {
		t.Fatalf("GetClient after a flush: %v", err)
	}
	afterFlush := want
	afterFlush.TrafficUsedBytes = want.TrafficUsedBytes + 500
	diffClientFields(t, afterFlush, *flushed, "a traffic flush")
}

// The recurring-quota fields are stored beside the limit they govern rather than
// inside the sealed blob, so a reset boundary can be computed with no master key
// loaded. That is a deliberate exposure decision, and it only holds while they
// carry nothing about who the subscriber is.
func TestTrafficCycleFieldsAreStoredInTheClear(t *testing.T) {
	db := clientsFixture(t)

	anchor := time.Date(2026, 1, 31, 8, 0, 0, 0, time.UTC)
	if err := db.SaveClient(Client{
		ID: "cycle-1", Name: "Monthly Subscriber", Token: "hdns_sub_monthly", Enabled: true,
		TrafficLimitGB: 50, TrafficResetCycle: "monthly", TrafficResetAnchor: anchor,
		TrafficResetCount: 3, TrafficPrevCycleBytes: 42_000_000,
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	enc := rawClient(t, db, "cycle-1")
	if enc.TrafficResetCycle != "monthly" {
		t.Errorf("stored cycle = %q, want it readable without the key", enc.TrafficResetCycle)
	}
	if !enc.TrafficResetAnchor.Equal(anchor) {
		t.Errorf("stored anchor = %v, want %v", enc.TrafficResetAnchor, anchor)
	}
	if enc.TrafficResetCount != 3 {
		t.Errorf("stored count = %d, want 3", enc.TrafficResetCount)
	}
	if enc.TrafficPrevCycleBytes != 42_000_000 {
		t.Errorf("stored previous-period usage = %d, want 42000000", enc.TrafficPrevCycleBytes)
	}
	// The point of sealing the rest still has to hold in the same record.
	if enc.NameEnc == "Monthly Subscriber" || enc.Token != "" {
		t.Error("a cleartext quota field came with a cleartext secret")
	}
}

// Every account written before v1.5.0 has to keep behaving exactly as it did: the
// zero value of all four fields is "no cycle", which is the old behaviour, so no
// stored record needs rewriting on upgrade.
func TestLegacyRecordHasNoTrafficCycle(t *testing.T) {
	db := clientsFixture(t)

	nameEnc, err := db.cipher.EncryptString("Pre-cycle Customer")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	putRawClient(t, db, encClient{
		ID: "old-cycle", NameEnc: nameEnc, Token: "hdns_sub_precycle", Enabled: true,
		TrafficLimitGB: 10, TrafficUsedBytes: 9_000,
	})

	got, err := db.GetClient("old-cycle")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.TrafficResetCycle != "" {
		t.Errorf("a legacy record decoded with cycle %q", got.TrafficResetCycle)
	}
	if !got.TrafficResetAnchor.IsZero() || got.TrafficResetCount != 0 || got.TrafficPrevCycleBytes != 0 {
		t.Errorf("a legacy record decoded with a cycle state: anchor=%v count=%d prev=%d",
			got.TrafficResetAnchor, got.TrafficResetCount, got.TrafficPrevCycleBytes)
	}
	// The usage it had must survive untouched, or the upgrade would hand back
	// allowance the subscriber already spent.
	if got.TrafficUsedBytes != 9_000 || got.TrafficLimitGB != 10 {
		t.Errorf("legacy quota state changed: used=%d limit=%v", got.TrafficUsedBytes, got.TrafficLimitGB)
	}
}
