package bootstrap_test

import (
	"errors"
	"reflect"
	"testing"

	"hyperdns/internal/bootstrap"
)

type settingsStoreStub struct {
	present map[string]bool
	values  map[string]any
	exists  map[string]error
	loads   map[string]error
	calls   []string
	writes  int
}

func (s *settingsStoreStub) SettingExists(key string) (bool, error) {
	s.calls = append(s.calls, "exists:"+key)
	if err := s.exists[key]; err != nil {
		return false, err
	}
	return s.present[key], nil
}

func (s *settingsStoreStub) GetSetting(key string, target any) error {
	s.calls = append(s.calls, "get:"+key)
	if err := s.loads[key]; err != nil {
		return err
	}
	switch dst := target.(type) {
	case *testSetting:
		*dst = s.values[key].(testSetting)
	default:
		return errors.New("unexpected target")
	}
	return nil
}

type testSetting struct {
	Value string
}

func TestLoadPresentSettings(t *testing.T) {
	t.Run("absent records leave defaults untouched", func(t *testing.T) {
		store := &settingsStoreStub{present: map[string]bool{}, exists: map[string]error{}, loads: map[string]error{}}
		target := testSetting{Value: "default"}
		err := bootstrap.LoadPresentSettings(store, bootstrap.SettingSpec{Key: "server", Target: &target})
		if err != nil {
			t.Fatalf("LoadPresentSettings: %v", err)
		}
		if target.Value != "default" {
			t.Fatalf("target = %#v, want defaults untouched", target)
		}
		if want := []string{"exists:server"}; !reflect.DeepEqual(store.calls, want) {
			t.Fatalf("calls = %v, want %v", store.calls, want)
		}
		if store.writes != 0 {
			t.Fatalf("writes = %d, want 0", store.writes)
		}
	})

	t.Run("valid present records load in order", func(t *testing.T) {
		store := &settingsStoreStub{
			present: map[string]bool{"server": true, "dns": true},
			values:  map[string]any{"server": testSetting{Value: "stored-server"}, "dns": testSetting{Value: "stored-dns"}},
			exists:  map[string]error{}, loads: map[string]error{},
		}
		server, dns := testSetting{}, testSetting{}
		err := bootstrap.LoadPresentSettings(store,
			bootstrap.SettingSpec{Key: "server", Target: &server},
			bootstrap.SettingSpec{Key: "dns", Target: &dns},
		)
		if err != nil {
			t.Fatalf("LoadPresentSettings: %v", err)
		}
		if server.Value != "stored-server" || dns.Value != "stored-dns" {
			t.Fatalf("loaded server=%#v dns=%#v", server, dns)
		}
		want := []string{"exists:server", "get:server", "exists:dns", "get:dns"}
		if !reflect.DeepEqual(store.calls, want) {
			t.Fatalf("calls = %v, want %v", store.calls, want)
		}
		if store.writes != 0 {
			t.Fatalf("writes = %d, want 0", store.writes)
		}
	})

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "invalid JSON", err: errors.New("invalid character")},
		{name: "wrong-key encrypted", err: errors.New("could not decrypt setting (wrong master key?)")},
	} {
		t.Run(tc.name+" fails fast without writes", func(t *testing.T) {
			store := &settingsStoreStub{
				present: map[string]bool{"server": true, "dns": true},
				values:  map[string]any{"dns": testSetting{Value: "must-not-load"}},
				exists:  map[string]error{}, loads: map[string]error{"server": tc.err},
			}
			server, dns := testSetting{Value: "default"}, testSetting{Value: "default"}
			err := bootstrap.LoadPresentSettings(store,
				bootstrap.SettingSpec{Key: "server", Target: &server},
				bootstrap.SettingSpec{Key: "dns", Target: &dns},
			)
			if !errors.Is(err, tc.err) {
				t.Fatalf("error = %v, want wrapped %v", err, tc.err)
			}
			want := []string{"exists:server", "get:server"}
			if !reflect.DeepEqual(store.calls, want) {
				t.Fatalf("calls = %v, want fail-fast %v", store.calls, want)
			}
			if dns.Value != "default" || store.writes != 0 {
				t.Fatalf("later target=%#v writes=%d; failed load must have no side effects", dns, store.writes)
			}
		})
	}

	t.Run("transaction error fails fast without reads or writes", func(t *testing.T) {
		txErr := errors.New("view transaction failed")
		store := &settingsStoreStub{
			present: map[string]bool{"dns": true}, values: map[string]any{},
			exists: map[string]error{"server": txErr}, loads: map[string]error{},
		}
		server, dns := testSetting{}, testSetting{}
		err := bootstrap.LoadPresentSettings(store,
			bootstrap.SettingSpec{Key: "server", Target: &server},
			bootstrap.SettingSpec{Key: "dns", Target: &dns},
		)
		if !errors.Is(err, txErr) {
			t.Fatalf("error = %v, want wrapped %v", err, txErr)
		}
		if want := []string{"exists:server"}; !reflect.DeepEqual(store.calls, want) {
			t.Fatalf("calls = %v, want %v", store.calls, want)
		}
		if store.writes != 0 {
			t.Fatalf("writes = %d, want 0", store.writes)
		}
	})
}
