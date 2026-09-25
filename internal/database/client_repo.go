package database

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrClientNotFound = errors.New("client not found")
	ErrClientExpired  = errors.New("client account has expired")
	// ErrClientSuspended is the toggle-off state an operator set deliberately, as
	// distinct from expiry which is the calendar. The portal registration path
	// refuses both (Phase B, Mantis C-01), but a subscriber reading the error
	// deserves to know which one hit them.
	ErrClientSuspended = errors.New("client account is suspended")
	// ErrQuotaExceeded mirrors the resolver's own enforcement decision on the
	// registration path (Phase B, Mantis C-02): an account whose allowance is
	// spent can read its portal but cannot move its binding until the cycle
	// resets or the operator intervenes.
	ErrQuotaExceeded = errors.New("client traffic quota is exhausted")
	// ErrDuplicateIPConflict reports that the address being bound is already
	// the registered address of a different subscription (Phase B, C-04). The
	// HTTP layer answers 409; neither account is disabled — CGNAT makes shared
	// addresses ordinary, and auto-suspending paying subscribers over one is
	// the cure killing the patient.
	ErrDuplicateIPConflict = errors.New("address already registered to another subscription")
	// ErrSecretMismatch is what the registration API reports when the supplied
	// register secret does not match (Phase B, Mantis C-03). The HTTP layer
	// deliberately maps this onto the same answer as an unknown token, so a
	// prober cannot tell a valid token with a wrong secret from a dead one.
	ErrSecretMismatch = errors.New("registration secret does not match")
)

// lastSeenWriteInterval bounds how often a repeat visit from an address that is
// already registered is written back.
//
// The subscription portal is a public URL whose only credential is the token in
// the path, so a subscriber — or a bot holding one valid token — can refresh it
// as fast as it likes. Every visit used to force a bbolt write transaction, an
// fsync, purely to move LastSeen forward by a second. A minute of granularity is
// finer than the dashboard displays and costs nothing an operator can see.
const lastSeenWriteInterval = time.Minute

// encClient is the on-disk shape of a client account.
//
// Token/TokenEnc/TokenMAC carry one value in three possible forms. Until v1.5.0
// the subscription token — the credential a subscriber pastes into their client,
// and the thing a reseller actually sells — was written to `token` in the clear,
// so a copied data.db handed over every live subscription even though the name
// and IP next to it were sealed. It is now sealed into TokenEnc, with TokenMAC
// as the lookup fingerprint (see crypto.Cipher.BlindIndex). Token is still read
// so a database written by an older build keeps working, and is still written
// when no master key is loaded, because refusing to save is worse.
type encClient struct {
	ID                string    `json:"id"`
	UUID              string    `json:"uuid"`
	NameEnc           string    `json:"name_enc"`
	Token             string    `json:"token,omitempty"`
	TokenEnc          string    `json:"token_enc,omitempty"`
	TokenMAC          string    `json:"token_mac,omitempty"`
	RegisterSecretEnc string    `json:"register_secret_enc,omitempty"`
	AllowedIPEnc      string    `json:"allowed_ip_enc"`
	TrafficLimitGB    float64   `json:"traffic_limit_gb"`
	TrafficUsedBytes  uint64    `json:"traffic_used_bytes"`
	ExpiresAt         time.Time `json:"expires_at"`
	CreatedAt         time.Time `json:"created_at"`
	LastSeen          time.Time `json:"last_seen"`
	TotalQueries      uint64    `json:"total_queries"`
	Enabled           bool      `json:"enabled"`
	Note              string    `json:"note"`
	CustomPolicies    []string  `json:"custom_policies"`

	// The recurring-quota fields are stored in the clear beside the limit they
	// govern. A cycle name and two counters say nothing about who the subscriber is
	// or where they connect from, which is what the sealed fields exist to protect,
	// and keeping them readable means a reset boundary can be computed without a
	// master key being loaded.
	TrafficResetCycle     string    `json:"traffic_reset_cycle"`
	TrafficResetAnchor    time.Time `json:"traffic_reset_anchor"`
	TrafficResetCount     uint64    `json:"traffic_reset_count"`
	TrafficPrevCycleBytes uint64    `json:"traffic_prev_cycle_bytes"`

	// MaxDevices is the number of IPs this subscription may hold at once (v2.5).
	// A plain small integer that names no subscriber and no address, so it is
	// stored in the clear beside the quota counters. 0 reads as the default of 1.
	MaxDevices int `json:"max_devices,omitempty"`
}

// plainToken returns the plaintext subscription token of a stored record,
// whichever form it was written in. A record sealed with a different master key
// reports the failure rather than silently reading as tokenless: a tokenless
// record is an account nobody can authenticate to, and saving one back would
// destroy the subscriber's credential for good.
func (db *DB) plainToken(enc *encClient) (string, error) {
	if enc.TokenEnc == "" {
		return enc.Token, nil
	}
	plain, err := db.cipher.DecryptString(enc.TokenEnc)
	if err != nil {
		return "", fmt.Errorf("could not decrypt the token of client %q (wrong master key?): %w", enc.ID, err)
	}
	return plain, nil
}

func GenerateUUID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	buf[6] = (buf[6] & 0x0f) | 0x40 // Version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

// (db *DB).generateDeterministicUUID derives a stable UUID from the record's ID
// and secret token when the record carries none. It is an HMAC-SHA256 under the
// master key's HKDF-derived blind-index subkey — the same key the token lookup
// MAC uses — so the commitment is keyed and offline brute-force of the token
// from a published UUID would require the master key itself (v2.1.0 A-02
// remediation; the previous form was an MD5 over a source-published salt,
// giving every observer of a portal-rendered UUID a free oracle).
//
// Records that already carry a UUID keep it unchanged; only derivations
// performed after this change use the new construction.
func (db *DB) generateDeterministicUUID(id, token string) string {
	if db == nil || db.cipher == nil {
		return GenerateUUID()
	}
	mac := db.cipher.BlindIndex(id + ":" + token)
	// Fold the MAC into UUIDv4-shaped bytes: 16 bytes of hash, version/variant
	// bits set, hex-formatted exactly as the previous scheme's output was.
	sum := sha256.Sum256([]byte(mac))
	var h [16]byte
	copy(h[:], sum[:16])
	h[6] = (h[6] & 0x0f) | 0x40
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

func (db *DB) packClient(c Client) ([]byte, error) {
	// Every secret in the record is sealed, so there is no half-encrypted shape to
	// fall back to. Refusing here says why, instead of failing further down with
	// "cipher is uninitialized" from inside the AES layer.
	if db.cipher == nil {
		return nil, errors.New("cannot store a client while no master key is loaded")
	}

	if c.UUID == "" {
		if c.ID != "" && c.Token != "" {
			c.UUID = db.generateDeterministicUUID(c.ID, c.Token)
		} else {
			c.UUID = GenerateUUID()
		}
	}

	nameEnc, err := db.cipher.EncryptString(c.Name)
	if err != nil {
		return nil, err
	}

	ipData, err := json.Marshal(c.AllowedIPs)
	if err != nil {
		return nil, err
	}
	if c.AllowedIPs == nil {
		ipData = []byte(`[]`)
	}
	ipEnc, err := db.cipher.EncryptString(string(ipData))
	if err != nil {
		return nil, err
	}

	tokenEnc, err := db.cipher.EncryptString(c.Token)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt the token of client %q: %w", c.ID, err)
	}

	// The register secret is sealed beside the token: it is the second
	// credential of the IP-registration API (Phase B, Mantis C-03).
	var secretEnc string
	if c.RegisterSecret != "" {
		secretEnc, err = db.cipher.EncryptString(c.RegisterSecret)
		if err != nil {
			return nil, fmt.Errorf("could not encrypt the register secret of client %q: %w", c.ID, err)
		}
	}

	enc := encClient{
		ID:                c.ID,
		UUID:              c.UUID,
		NameEnc:           nameEnc,
		TokenEnc:          tokenEnc,
		TokenMAC:          db.cipher.BlindIndex(c.Token),
		RegisterSecretEnc: secretEnc,
		AllowedIPEnc:      ipEnc,
		TrafficLimitGB:    c.TrafficLimitGB,
		TrafficUsedBytes:  c.TrafficUsedBytes,
		ExpiresAt:         c.ExpiresAt,
		CreatedAt:         c.CreatedAt,
		LastSeen:          c.LastSeen,
		TotalQueries:      c.TotalQueries,
		Enabled:           c.Enabled,
		Note:              c.Note,
		CustomPolicies:    c.CustomPolicies,

		TrafficResetCycle:     c.TrafficResetCycle,
		TrafficResetAnchor:    c.TrafficResetAnchor,
		TrafficResetCount:     c.TrafficResetCount,
		TrafficPrevCycleBytes: c.TrafficPrevCycleBytes,
		MaxDevices:            c.MaxDevices,
	}

	return json.Marshal(enc)
}

func (db *DB) unpackClient(data []byte) (*Client, error) {
	var enc encClient
	if err := json.Unmarshal(data, &enc); err != nil {
		return nil, err
	}

	name, err := db.cipher.DecryptString(enc.NameEnc)
	if err != nil {
		name = "Decryption Failed"
	}

	token, err := db.plainToken(&enc)
	if err != nil {
		return nil, err
	}

	var ips []string
	if enc.AllowedIPEnc != "" {
		decIPs, err := db.cipher.DecryptString(enc.AllowedIPEnc)
		if err == nil {
			_ = json.Unmarshal([]byte(decIPs), &ips)
		}
	}
	if ips == nil {
		ips = []string{}
	}

	uuid := enc.UUID
	if uuid == "" {
		// Derived from the plaintext token, so a record that had no UUID keeps the
		// same one after the token is sealed.
		uuid = db.generateDeterministicUUID(enc.ID, token)
	}

	customPolicies := enc.CustomPolicies
	if customPolicies == nil {
		customPolicies = []string{}
	}

	// Decrypt the register secret. An empty value is the legacy shape — records
	// written before Phase B have none, and the client service backfills one.
	registerSecret := ""
	if enc.RegisterSecretEnc != "" {
		if plain, err := db.cipher.DecryptString(enc.RegisterSecretEnc); err == nil {
			registerSecret = plain
		}
	}

	return &Client{
		ID:               enc.ID,
		UUID:             uuid,
		Name:             name,
		Token:            token,
		AllowedIPs:       ips,
		RegisterSecret:   registerSecret,
		TrafficLimitGB:   enc.TrafficLimitGB,
		TrafficUsedBytes: enc.TrafficUsedBytes,
		ExpiresAt:        enc.ExpiresAt,
		CreatedAt:        enc.CreatedAt,
		LastSeen:         enc.LastSeen,
		TotalQueries:     enc.TotalQueries,
		Enabled:          enc.Enabled,
		Note:             enc.Note,
		CustomPolicies:   customPolicies,

		TrafficResetCycle:     enc.TrafficResetCycle,
		TrafficResetAnchor:    enc.TrafficResetAnchor,
		TrafficResetCount:     enc.TrafficResetCount,
		TrafficPrevCycleBytes: enc.TrafficPrevCycleBytes,
		MaxDevices:            enc.MaxDevices,
	}, nil
}

// ValidateClients proves every stored client record can be parsed and every
// authoritative encrypted field can be opened with the loaded master key. It is
// read-only and is intended to run before any startup migration is authorized.
func (db *DB) ValidateClients() error {
	if db == nil || db.bolt == nil {
		return errors.New("database is not open")
	}
	return db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, data []byte) error {
			if err := db.validateClient(k, data); err != nil {
				return fmt.Errorf("validate client %q: %w", k, err)
			}
			return nil
		})
	})
}

func (db *DB) validateClient(bucketKey, data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("record must be a JSON object")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return fmt.Errorf("decode record: %w", err)
	}
	if object == nil {
		return errors.New("record must be a non-null JSON object")
	}
	var enc encClient
	if err := json.Unmarshal(trimmed, &enc); err != nil {
		return fmt.Errorf("decode record: %w", err)
	}
	if enc.ID == "" {
		return errors.New("client ID is empty")
	}
	if enc.ID != string(bucketKey) {
		return fmt.Errorf("stored ID %q does not match bucket key %q", enc.ID, bucketKey)
	}
	if enc.NameEnc == "" {
		return errors.New("encrypted client name is missing")
	}
	switch {
	case enc.Token != "" && enc.TokenEnc != "":
		return errors.New("both legacy and encrypted token forms are present")
	case enc.Token == "" && enc.TokenEnc == "":
		return errors.New("client token is missing")
	case enc.TokenEnc != "" && enc.TokenMAC == "":
		return errors.New("encrypted client token fingerprint is missing")
	case enc.TokenEnc == "" && enc.TokenMAC != "":
		return errors.New("client token fingerprint has no encrypted token")
	}
	if db.cipher == nil {
		return errors.New("client record requires a master key")
	}
	for name, sealed := range map[string]string{
		"name": enc.NameEnc, "token": enc.TokenEnc, "allowed IPs": enc.AllowedIPEnc, "register secret": enc.RegisterSecretEnc,
	} {
		if sealed == "" {
			continue
		}
		plain, err := db.cipher.DecryptString(sealed)
		if err != nil {
			return fmt.Errorf("decrypt %s (wrong master key?): %w", name, err)
		}
		if name == "name" && plain == "" {
			return errors.New("client name is empty")
		}
		if name == "token" {
			if plain == "" {
				return errors.New("client token is empty")
			}
			wantMAC := db.cipher.BlindIndex(plain)
			if subtle.ConstantTimeCompare([]byte(enc.TokenMAC), []byte(wantMAC)) != 1 {
				return errors.New("encrypted client token fingerprint does not match")
			}
		}
		if name == "allowed IPs" {
			var ips []string
			if err := json.Unmarshal([]byte(plain), &ips); err != nil {
				return fmt.Errorf("decode allowed IPs: %w", err)
			}
			if ips == nil {
				return errors.New("decode allowed IPs: expected a JSON string array")
			}
		}
	}
	return nil
}

// SaveClient stores or updates a client with transparent AES-256-GCM encryption.
func (db *DB) SaveClient(c Client) error {
	if c.UUID == "" {
		if c.ID != "" && c.Token != "" {
			c.UUID = db.generateDeterministicUUID(c.ID, c.Token)
		} else {
			c.UUID = GenerateUUID()
		}
	}

	data, err := db.packClient(c)
	if err != nil {
		return err
	}

	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.Put([]byte(c.ID), data)
	})
}

// GetClient retrieves and decrypts a client by ID.
func (db *DB) GetClient(id string) (*Client, error) {
	var client *Client
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get([]byte(id))
		if data == nil {
			return ErrClientNotFound
		}
		var err error
		client, err = db.unpackClient(data)
		return err
	})
	return client, err
}

// ListClients retrieves and decrypts all clients.
//
// Initialised, not nil, for the same reason as ListPolicies: an empty subscriber
// list must encode as [] so that a caller can iterate the field unconditionally.
func (db *DB) ListClients() ([]Client, error) {
	list := []Client{}
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.ForEach(func(k, v []byte) error {
			c, err := db.unpackClient(v)
			if err != nil {
				// Skipping silently would make a wrong master.key look like an empty
				// database, and the operator would go looking for a backup they do not
				// need. Say what happened and keep listing the rest.
				log.Printf("[DB] Could not read the stored client %q: %v", k, err)
				return nil
			}
			if c != nil {
				list = append(list, *c)
			}
			return nil
		})
	})
	return list, err
}

// FindClientByToken finds a client by subscription token.
//
// The scan never decrypts: it compares the stored lookup fingerprint against the
// fingerprint of the candidate token, computed once. Decrypting every stored
// record to locate one match made the public registration endpoint a
// CPU-exhaustion primitive, costing an AES-GCM open per stored client on every
// request — which is exactly why the sealed token carries a fingerprint at all.
// A legacy record that still holds its token in the clear is matched directly, so
// a database written by an older build keeps authenticating.
func (db *DB) FindClientByToken(token string) (*Client, error) {
	if token == "" {
		return nil, ErrClientNotFound
	}
	want := []byte(token)
	wantMAC := []byte(db.cipher.BlindIndex(token))

	var found *Client
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.ForEach(func(_, v []byte) error {
			var probe struct {
				Token    string `json:"token"`
				TokenMAC string `json:"token_mac"`
			}
			if json.Unmarshal(v, &probe) != nil {
				return nil
			}
			// Constant-time compare so response timing cannot reveal how many
			// leading characters of a guessed token were correct.
			switch {
			case probe.TokenMAC != "" && len(wantMAC) > 0:
				if subtle.ConstantTimeCompare([]byte(probe.TokenMAC), wantMAC) != 1 {
					return nil
				}
			case probe.Token != "":
				if subtle.ConstantTimeCompare([]byte(probe.Token), want) != 1 {
					return nil
				}
			default:
				return nil
			}
			c, uerr := db.unpackClient(v)
			if uerr != nil {
				return uerr
			}
			found = c
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrClientNotFound
	}
	return found, nil
}

// FindClientByIP checks if an IP belongs to any active, non-expired client account.
func (db *DB) FindClientByIP(ip string) (*Client, bool) {
	clients, err := db.ListClients()
	if err != nil {
		return nil, false
	}
	now := time.Now()
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
			continue
		}
		if slices.Contains(c.AllowedIPs, ip) {
			return &c, true
		}
	}
	return nil, false
}

// RegisterClientIP strictly updates/replaces the client IP (1 IP per account)
func (db *DB) RegisterClientIP(token string, newIP string) (*Client, bool, error) {
	client, err := db.FindClientByToken(token)
	if err != nil {
		return nil, false, err
	}
	return db.registerIP(client, newIP)
}

// RegisterIPForClient performs the same registration for a caller that has
// already resolved the account — the service layer keeps an in-memory token
// index — so no bucket scan is needed.
func (db *DB) RegisterIPForClient(id string, newIP string) (*Client, bool, error) {
	client, err := db.GetClient(id)
	if err != nil {
		return nil, false, err
	}
	return db.registerIP(client, newIP)
}

func (db *DB) registerIP(client *Client, newIP string) (*Client, bool, error) {
	now := time.Now()
	if !client.ExpiresAt.IsZero() && now.After(client.ExpiresAt) {
		client.Enabled = false
		_ = db.SaveClient(*client)
		// This used to return os.ErrDeadlineExceeded, which forced callers to
		// import os to recognise an expired account and is indistinguishable
		// from a genuine I/O deadline.
		return client, false, ErrClientExpired
	}

	// Phase B gates (Mantis C-01/C-02): the registration path must refuse an
	// account the operator suspended and an account whose allowance is spent.
	// Both used to sail straight through — a suspended subscriber kept moving
	// their binding, and re-enabling one later silently adopted whatever
	// binding they had last chosen.
	if !client.Enabled {
		return client, false, ErrClientSuspended
	}
	if client.TrafficLimitGB > 0 {
		used := client.TrafficUsedBytes
		if uint64(client.TrafficLimitGB*1024*1024*1024) <= used {
			return client, false, ErrQuotaExceeded
		}
	}

	alreadyPresent := false
	for _, ip := range client.AllowedIPs {
		if ip == newIP {
			alreadyPresent = true
			break
		}
	}

	// A repeat visit from an address already bound changes nothing the resolver or
	// the operator can observe except LastSeen (and its recency in the list), so a
	// visit inside the write window does not earn an fsync.
	if alreadyPresent && len(client.AllowedIPs) > 0 && client.AllowedIPs[len(client.AllowedIPs)-1] == newIP &&
		now.Sub(client.LastSeen) < lastSeenWriteInterval {
		return client, true, nil
	}

	// Phase B (Mantis C-04): refuse to bind an address that is already the
	// registered address of a DIFFERENT live subscription. The scan is one pass
	// over the accounts bucket on a bind — the write path this guards is
	// rate-limited by human behaviour, not by a resolver hot loop — and it is
	// the only place an IP->account uniqueness claim can be made honestly,
	// because bbolt has no secondary index to consult. Deliberately NOT
	// deactivating either account: CGNAT makes shared addresses routine, and
	// the caller surfaces a 409 with instructions instead.
	if existing, owner := db.findOwnerOfIP(newIP, client.ID); existing {
		return client, alreadyPresent, fmt.Errorf("%w: already bound to account %s", ErrDuplicateIPConflict, owner)
	}

	// Multi-device binding (v2.5): keep up to MaxDevices addresses, most-recent
	// last. A repeat of an address already held moves it to the end; a new one
	// past the limit evicts the oldest (front). MaxDevices 0 reads as 1, so an
	// upgraded record with no value behaves exactly as the old single-IP path.
	limit := NormalizeMaxDevices(client.MaxDevices)
	list := make([]string, 0, len(client.AllowedIPs)+1)
	for _, ip := range client.AllowedIPs {
		if ip != newIP { // drop the old position of a repeat; re-appended below
			list = append(list, ip)
		}
	}
	list = append(list, newIP)
	if len(list) > limit {
		list = list[len(list)-limit:]
	}
	client.AllowedIPs = list
	client.LastSeen = now

	err := db.SaveClient(*client)
	return client, alreadyPresent, err
}

// MaxDevicesCeiling is the largest simultaneous-device count an operator may set
// (v2.5). Chosen small on purpose: the subscription is one household or one
// reseller customer, not a public relay, and a low ceiling keeps the CGNAT-shared
// address case (Mantis C-04) from being papered over with a huge limit.
const MaxDevicesCeiling = 5

// NormalizeMaxDevices clamps a stored/typed value into 1..MaxDevicesCeiling. 0
// (the zero value on an upgraded record) resolves to 1, preserving the old
// single-address behaviour for accounts created before the field existed.
func NormalizeMaxDevices(n int) int {
	if n <= 0 {
		return 1
	}
	if n > MaxDevicesCeiling {
		return MaxDevicesCeiling
	}
	return n
}

// findOwnerOfIP walks the accounts bucket for a record whose registered address
// is ip, belonging to a different client than excludeID. Returns whether such a
// record exists and its account name (best-effort, for the error message).
func (db *DB) findOwnerOfIP(ip string, excludeID string) (bool, string) {
	owner := ""
	found := false
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, data []byte) error {
			if found {
				return nil
			}
			c, err := db.unpackClient(data)
			if err != nil || c.ID == excludeID {
				return nil
			}
			for _, bound := range c.AllowedIPs {
				if bound == ip {
					found = true
					owner = c.Name
					return nil
				}
			}
			return nil
		})
	})
	return found, owner
}

// AddClientTraffic adds each delta to the stored usage of its account inside a
// single write transaction, and returns the deltas it could not apply so the
// caller can keep accounting for them.
//
// One transaction rather than one per account is what makes a flush affordable:
// bbolt fsyncs on commit, so persisting a thousand metered subscribers one at a
// time meant a thousand fsyncs, and quota enforcement read a stale figure for the
// whole time that took. Each record is still read inside the transaction before
// its delta is added, so a limit change or a reset that landed in the meantime is
// not clobbered by a stale copy.
//
// An account that no longer exists is dropped rather than reported: its bytes have
// nowhere to go and retrying them forever is not an operator-actionable error.
func (db *DB) AddClientTraffic(deltas map[string]uint64) (map[string]uint64, error) {
	if len(deltas) == 0 {
		return nil, nil
	}

	unapplied := make(map[string]uint64)
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		if b == nil {
			return errors.New("clients bucket is missing")
		}
		for id, n := range deltas {
			if n == 0 {
				continue
			}
			raw := b.Get([]byte(id))
			if raw == nil {
				continue // deleted account
			}
			client, err := db.unpackClient(raw)
			if err != nil || client == nil {
				// Unreadable with the current master key. Hand the bytes back
				// rather than writing a record we could not fully decode.
				unapplied[id] = n
				continue
			}
			client.TrafficUsedBytes += n
			packed, err := db.packClient(*client)
			if err != nil {
				unapplied[id] = n
				continue
			}
			if err := b.Put([]byte(id), packed); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// The transaction rolled back, so nothing was written.
		return deltas, err
	}
	if len(unapplied) == 0 {
		return nil, nil
	}
	return unapplied, nil
}

// DeleteClient removes a client by ID, and reports ErrClientNotFound when there was
// nothing stored under that ID.
//
// bolt's Delete is deliberately silent about a missing key — it returns nil whether it
// removed a record or found none — so a handler that only forwarded its error answered
// "deleted": true for an ID that never existed. That is wrong in a way an operator acts
// on: a reseller who mistypes an ID is told the subscriber is gone, and a script that
// deletes by a stale ID reports success while the real record stays live. The existence
// check runs inside the same write transaction as the delete, so a concurrent delete of
// the same ID cannot make both callers believe they were the one who removed it.
func (db *DB) DeleteClient(id string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		if b.Get([]byte(id)) == nil {
			return ErrClientNotFound
		}
		return b.Delete([]byte(id))
	})
}

// encryptLegacyClientTokens seals any subscription token still stored in the
// clear, in one transaction.
//
// It runs on every open and is idempotent: a record that already carries a sealed
// token is left byte-for-byte alone. A record that cannot be resealed is also left
// alone and reported — a readable token is better than a destroyed one, and the
// read path accepts both forms — so a single bad record cannot take the resolver
// down with it.
func (db *DB) encryptLegacyClientTokens() (int, error) {
	if db.cipher == nil {
		return 0, nil
	}

	// Collect first, write second: mutating a bucket while iterating it is not
	// something bbolt promises anything about.
	var legacy [][]byte
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var probe struct {
				Token    string `json:"token"`
				TokenEnc string `json:"token_enc"`
			}
			if json.Unmarshal(v, &probe) != nil {
				return nil
			}
			if probe.TokenEnc == "" && probe.Token != "" {
				// The key is only valid for the life of the transaction.
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
		b := tx.Bucket(bucketClients)
		if b == nil {
			return nil
		}
		for _, k := range legacy {
			v := b.Get(k)
			if v == nil {
				continue
			}
			var enc encClient
			if err := json.Unmarshal(v, &enc); err != nil {
				log.Printf("[DB] Could not parse the stored client %q: %v; its token stays in cleartext.", k, err)
				continue
			}
			if enc.TokenEnc != "" || enc.Token == "" {
				continue
			}

			sealed, err := db.cipher.EncryptString(enc.Token)
			if err != nil {
				log.Printf("[DB] Could not encrypt the token of client %q: %v; it stays in cleartext.", k, err)
				continue
			}
			// Pin the identity before the plaintext it was derived from disappears.
			// Nothing else in the record changes.
			if enc.UUID == "" {
				enc.UUID = db.generateDeterministicUUID(enc.ID, enc.Token)
			}
			enc.TokenEnc = sealed
			enc.TokenMAC = db.cipher.BlindIndex(enc.Token)
			enc.Token = ""

			next, err := json.Marshal(enc)
			if err != nil {
				log.Printf("[DB] Could not re-encode the stored client %q: %v; its token stays in cleartext.", k, err)
				continue
			}
			if err := b.Put(k, next); err != nil {
				return err
			}
			converted++
		}
		return nil
	})
	return converted, err
}
