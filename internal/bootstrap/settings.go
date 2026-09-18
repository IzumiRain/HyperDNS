package bootstrap

import "fmt"

// SettingsStore is the read-only settings surface needed during bootstrap.
// Implementations must not treat a read error as absence.
type SettingsStore interface {
	SettingExists(key string) (bool, error)
	GetSetting(key string, target any) error
}

// SettingsWriter is the write surface a boot migration needs. It is separate
// from SettingsStore so callers that only read cannot accidentally migrate.
type SettingsWriter interface {
	SettingsStore
	SetSetting(key string, val any) error
}

// SettingSpec pairs a persisted setting key with the default-populated target
// that should receive it when the record exists.
type SettingSpec struct {
	Key    string
	Target any
}

// LoadPresentSettings loads each authoritative record in order. It stops at the
// first existence or decode error, before callers perform bootstrap writes.
func LoadPresentSettings(store SettingsStore, specs ...SettingSpec) error {
	if store == nil {
		return fmt.Errorf("settings store is nil")
	}
	for _, spec := range specs {
		present, err := store.SettingExists(spec.Key)
		if err != nil {
			return fmt.Errorf("inspect setting %q: %w", spec.Key, err)
		}
		if !present {
			continue
		}
		if err := store.GetSetting(spec.Key, spec.Target); err != nil {
			return fmt.Errorf("load setting %q: %w", spec.Key, err)
		}
	}
	return nil
}
