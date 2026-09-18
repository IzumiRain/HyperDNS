package database

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// Policies are stored as plain JSON, deliberately.
//
// Everything else in the database that a copied data.db would expose is sealed:
// the subscriber's name, bound IP and subscription token, and the settings records
// (admin verifier, REST API key). A policy holds none of that — it is a preset
// toggle plus, at most, a list of domains the operator chose to proxy, block or
// send direct. That is the same information the shipped presets already publish in
// the binary and in docs/PRESET_CATALOG.md, so sealing it would buy nothing while
// adding a format migration and a decrypt on every rule reload, which happens on
// the DNS hot path at startup.
//
// The line to hold: if a policy ever carries a credential, an endpoint URL with a
// token in it, or anything naming a specific subscriber, it stops being
// configuration and has to be sealed like the client record is.

// SavePolicy stores or updates a policy preset
func (db *DB) SavePolicy(p Policy) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPolicies)
		return b.Put([]byte(p.Key), data)
	})
}

// GetPolicy retrieves a policy by key
func (db *DB) GetPolicy(key string) (*Policy, error) {
	var p Policy
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPolicies)
		data := b.Get([]byte(key))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &p)
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPolicies returns all stored policy rules.
//
// The slice is initialised rather than left nil so that the HTTP layer encodes an
// empty result as [] and not null. A fresh install has no overrides at all, and
// `policies: null` made every integration that walked the field — data.policies
// .forEach in the dashboard, a for-loop in Python — fail on the one case that is
// not an error.
func (db *DB) ListPolicies() ([]Policy, error) {
	list := []Policy{}
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPolicies)
		return b.ForEach(func(k, v []byte) error {
			var p Policy
			if err := json.Unmarshal(v, &p); err == nil {
				list = append(list, p)
			}
			return nil
		})
	})
	return list, err
}
