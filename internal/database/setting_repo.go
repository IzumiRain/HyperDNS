package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	bolt "go.etcd.io/bbolt"
)

// settingEnvelopePrefix marks a settings value whose JSON body is encrypted with
// the master key. Detection is by prefix rather than by a schema field because a
// legacy record is a bare JSON document, and no JSON document can begin with 'h'
// — so the two forms can never be confused, and a database written by an older
// build stays readable.
const settingEnvelopePrefix = "hdns:enc:v1:"

// encodeSetting marshals a value and, when a master key is available, seals it.
//
// Until v1.5.0 the settings bucket was the one place in the database that stored
// its contents in the clear: the admin password hash, the REST API key and the
// TLS paths all sat in plain JSON inside data.db, so a copied backup or a stray
// `strings data.db` handed them over even though the file was advertised as
// encrypted. The client bucket had been sealed since the beginning; this closes
// the gap rather than adding a new guarantee.
func (db *DB) encodeSetting(val any) ([]byte, error) {
	data, err := json.Marshal(val)
	if err != nil {
		return nil, err
	}
	if db.cipher == nil {
		// No key: storing cleartext is strictly better than refusing to save, and
		// the read path accepts it.
		return data, nil
	}
	sealed, err := db.cipher.EncryptString(string(data))
	if err != nil {
		return nil, fmt.Errorf("could not encrypt setting: %w", err)
	}
	return append([]byte(settingEnvelopePrefix), sealed...), nil
}

// decodeSetting unmarshals a stored value, transparently unsealing an encrypted
// envelope. A value with no envelope is read as-is, which is what makes an
// upgrade from an older database a no-op rather than a lockout.
func (db *DB) decodeSetting(data []byte, target any) error {
	if !bytes.HasPrefix(data, []byte(settingEnvelopePrefix)) {
		return json.Unmarshal(data, target)
	}
	body := string(data[len(settingEnvelopePrefix):])
	if db.cipher == nil {
		return fmt.Errorf("setting is encrypted but no master key is loaded")
	}
	plain, err := db.cipher.DecryptString(body)
	if err != nil {
		// Almost always the wrong master.key. Say which, because the fix is to
		// restore the original key, not to delete the database.
		return fmt.Errorf("could not decrypt setting (wrong master key?): %w", err)
	}
	return json.Unmarshal([]byte(plain), target)
}

// SetSetting saves any structured value as JSON in bucketSettings, encrypted with
// the master key.
func (db *DB) SetSetting(key string, val any) error {
	data, err := db.encodeSetting(val)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if b == nil {
			return fmt.Errorf("settings bucket is missing")
		}
		return b.Put([]byte(key), data)
	})
}

// GetSetting loads a structured value from bucketSettings. An absent key leaves
// target untouched and reports no error, so callers can layer a config file
// default underneath; use HasSetting to tell absent from zero.
func (db *DB) GetSetting(key string, target any) error {
	return db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(key))
		if data == nil {
			return nil
		}
		return db.decodeSetting(data, target)
	})
}

// authoritativeSettingTargets contains the concrete schemas consumed during
// startup. Their fields may evolve, but their top-level representation remains
// an object. allow_all is the only authoritative scalar setting.
var authoritativeSettingTargets = map[string]func() any{
	"server":       func() any { return &ServerSettings{} },
	"dns":          func() any { return &DNSSettings{} },
	"sniproxy":     func() any { return &SNIProxySettings{} },
	"tls":          func() any { return &TLSSettings{} },
	"subscription": func() any { return &SubscriptionSettings{} },
	"auth":         func() any { return &AuthSettings{} },
	"access": func() any {
		return &struct {
			DoHTokens []string `json:"doh_tokens"`
		}{}
	},
}

func validateSettingSchema(key string, raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("empty JSON value")
	}
	if key == "allow_all" {
		if !bytes.Equal(trimmed, []byte("true")) && !bytes.Equal(trimmed, []byte("false")) {
			return fmt.Errorf("expected a JSON boolean")
		}
		return nil
	}
	if target, known := authoritativeSettingTargets[key]; known {
		if trimmed[0] != '{' {
			return fmt.Errorf("expected a JSON object")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return fmt.Errorf("expected a JSON object: %w", err)
		}
		if object == nil {
			return fmt.Errorf("expected a non-null JSON object")
		}
		if err := json.Unmarshal(trimmed, target()); err != nil {
			return fmt.Errorf("invalid authoritative setting fields: %w", err)
		}
	}
	return nil
}

// ValidateSettings parses every stored setting and, for encrypted envelopes,
// proves it can be opened with the loaded key. It performs no writes. Known
// authoritative records are also decoded into their concrete startup schemas.
func (db *DB) ValidateSettings() error {
	if db == nil || db.bolt == nil {
		return fmt.Errorf("database is not open")
	}
	return db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, data []byte) error {
			var raw json.RawMessage
			if err := db.decodeSetting(data, &raw); err != nil {
				return fmt.Errorf("validate setting %q: %w", k, err)
			}
			if err := validateSettingSchema(string(k), raw); err != nil {
				return fmt.Errorf("validate setting %q: %w", k, err)
			}
			return nil
		})
	})
}

// SettingExists reports whether a setting key is present and preserves any
// transaction error. Bootstrap callers must not confuse an unreadable store with
// an absent record and proceed to write defaults over it.
func (db *DB) SettingExists(key string) (bool, error) {
	found := false
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if b != nil {
			found = b.Get([]byte(key)) != nil
		}
		return nil
	})
	return found, err
}

// HasSetting reports whether a key has ever been persisted. GetSetting cannot
// distinguish "absent" from "present but zero", so callers that need config-file
// values to act as a first-run default must gate on this. It is appropriate only
// where a transaction error is equivalent to absence.
func (db *DB) HasSetting(key string) bool {
	found, err := db.SettingExists(key)
	return err == nil && found
}

// encryptLegacySettings seals any settings value that is still stored in the
// clear, in one transaction.
//
// It runs on every open and is idempotent: a value that already carries the
// envelope is left byte-for-byte alone. A value that cannot be resealed is also
// left alone and reported, because a readable cleartext record is better than a
// half-written one — the daemon keeps working and the operator is told.
func (db *DB) encryptLegacySettings() (int, error) {
	if db.cipher == nil {
		return 0, nil
	}

	var legacy [][]byte
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if !bytes.HasPrefix(v, []byte(settingEnvelopePrefix)) {
				// The key is only valid for the life of the transaction, so copy it.
				legacy = append(legacy, append([]byte(nil), k...))
			}
			return nil
		})
	}); err != nil {
		return 0, err
	}
	if len(legacy) == 0 {
		return 0, nil
	}

	converted := 0
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if b == nil {
			return nil
		}
		for _, k := range legacy {
			v := b.Get(k)
			if v == nil || bytes.HasPrefix(v, []byte(settingEnvelopePrefix)) {
				continue
			}
			sealed, err := db.cipher.EncryptString(string(v))
			if err != nil {
				log.Printf("[DB] Could not encrypt the stored setting %q: %v; it stays in cleartext.", k, err)
				continue
			}
			if err := b.Put(k, append([]byte(settingEnvelopePrefix), sealed...)); err != nil {
				return err
			}
			converted++
		}
		return nil
	})
	return converted, err
}
