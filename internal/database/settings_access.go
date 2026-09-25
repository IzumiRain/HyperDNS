package database

import "errors"

// Runtime mutation of ServerSettings.
//
// One *ServerSettings is shared by pointer between main, the DNS handler, the web
// panel, the REST API and the TUI. Six of its fields are rewritten while the
// daemon is serving, by HTTP handlers living in two different packages:
//
//	APIKey              /api/settings/regenerate-api-key  (internal/web)
//	APIKey              /api/v1/api-key                   (internal/api)
//	PublicIP, APIBind   /api/settings                     (internal/web)
//	admin credentials   /api/config/server                (internal/web)
//
// and every one of them is read from some other goroutine. The REST
// authorization gate reads APIBind and APIKey on every single request; the TUI
// reads APIKey and PublicIP from the console goroutine; the dashboard's login
// path reads the credentials.
//
// A Go string is a pointer plus a length, and the two words are not written
// atomically. A read racing a write can therefore observe the new pointer with
// the old length — a value that was never assigned, aliasing whatever bytes
// happen to follow the new string in memory. Here that value is compared against
// a caller-supplied API key, so the failure mode is not a cosmetic glitch in a
// settings page.
//
// internal/web used to guard this with a mutex private to itself, which by
// construction could not cover internal/api writing through the same pointer.
// The lock lives with the fields instead, so both callers share it.
//
// Two rules keep this sound:
//
//  1. Pass *ServerSettings, never ServerSettings. A by-value copy would copy the
//     mutex, which `go vet` reports as copylocks and which would silently give the
//     copy its own lock.
//  2. Startup is exempt. main and applyConfigFile assign these fields directly,
//     before any listener exists and while only one goroutine is running. Adding
//     locks there would document a race that cannot happen.

// ErrSettingsNil is returned by UpdateAndPersist when it is called on a nil
// *ServerSettings, which means the daemon was wired up wrong rather than that the
// update failed.
var ErrSettingsNil = errors.New("server settings are not initialised")

// ServerSettingsSnapshot is a consistent copy of the settings a caller may
// display, taken under one lock acquisition so the fields agree with each other.
//
// AdminPassword is deliberately absent. It holds a PBKDF2 verifier, and the only
// legitimate use for it is verification, which has its own accessor; leaving it
// out of the type that feeds the settings page is what stops it from being
// serialised into a response again.
type ServerSettingsSnapshot struct {
	PublicIP          string
	BindHost          string
	WebPort           int
	AdminUsername     string
	AdminPasswordWeak bool
	APIKey            string
	APIBind           string
	AdminPath         string
	// SessionIdleMinutes is the configured dashboard idle window (Phase D);
	// GetSessionIdleMinutes applies the clamping rules.
	SessionIdleMinutes int
}

// MutableSettings is the subset of ServerSettings that changes at runtime, handed
// to UpdateAndPersist's callback as a plain copy.
//
// The callback is given this rather than the *ServerSettings itself for one
// reason: it runs with the write lock held, so a callback holding the real struct
// could deadlock the daemon by calling any accessor on it. This type has no
// methods to call.
type MutableSettings struct {
	PublicIP          string
	APIBind           string
	APIKey            string
	AdminUsername     string
	AdminPassword     string
	AdminPasswordWeak bool
	AdminPath         string
	// SessionIdleMinutes is the dashboard idle window in minutes (Phase D);
	// the accessor GetSessionIdleMinutes applies the clamping rules.
	SessionIdleMinutes int
}

// GetSessionIdleMinutes returns the configured dashboard idle window in
// minutes, clamped into [5, 1440]; 0 (not configured) keeps the 15-minute
// default the panel contract names.
func (s *ServerSettings) GetSessionIdleMinutes() int {
	s.mu.RLock()
	mins := s.SessionIdleMinutes
	s.mu.RUnlock()
	if mins == 0 {
		return 15
	}
	if mins < 5 {
		return 5
	}
	if mins > 1440 {
		return 1440
	}
	return mins
}

// GetAPIKey returns the master REST key in force, or "" if settings are missing.
func (s *ServerSettings) GetAPIKey() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.APIKey
}

// GetAPIBind returns the REST authorization gate: "0.0.0.0" to accept any peer,
// anything else to accept loopback only.
//
// A nil receiver returns "", which the gate reads as "loopback only" — the strict
// answer, which is the right way for a missing configuration to fail.
func (s *ServerSettings) GetAPIBind() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.APIBind
}

// GetAdminPath returns the hidden admin path segment in force, or "" when
// the record pre-dates v2.1 and no path has been generated yet.
func (s *ServerSettings) GetAdminPath() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AdminPath
}

// GetPublicIP returns the address the daemon advertises to subscribers.
func (s *ServerSettings) GetPublicIP() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PublicIP
}

// Endpoint returns PublicIP and APIBind together, for callers that report both
// and would otherwise take two locks and risk describing two different moments.
func (s *ServerSettings) Endpoint() (publicIP, apiBind string) {
	if s == nil {
		return "", ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PublicIP, s.APIBind
}

// AdminCredentials returns the stored username, the password verifier, and
// whether that password predates the current strength policy.
//
// The verifier is returned so it can be fed to crypto.VerifyPassword; it must not
// be written to a response, logged, or compared against anything by hand.
func (s *ServerSettings) AdminCredentials() (username, verifier string, weak bool) {
	if s == nil {
		return "", "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AdminUsername, s.AdminPassword, s.AdminPasswordWeak
}

// Snapshot copies the displayable settings under a single lock.
func (s *ServerSettings) Snapshot() ServerSettingsSnapshot {
	if s == nil {
		return ServerSettingsSnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ServerSettingsSnapshot{
		PublicIP:           s.PublicIP,
		BindHost:           s.BindHost,
		WebPort:            s.WebPort,
		AdminUsername:      s.AdminUsername,
		AdminPasswordWeak:  s.AdminPasswordWeak,
		APIKey:             s.APIKey,
		APIBind:            s.APIBind,
		AdminPath:          s.AdminPath,
		SessionIdleMinutes: s.SessionIdleMinutes,
	}
}

// UpdateAndPersist applies mutate to a copy of the runtime-mutable fields, writes
// the result back, and calls persist — all under one write lock. If persist
// returns an error every field is restored, so the running process and the
// database cannot end up disagreeing about a credential.
//
// Doing the rollback here, rather than in each handler, fixes a lost update the
// handlers could not fix themselves: two concurrent rotations A and B, where A
// remembers the pre-A key, B persists successfully, and then A's persist fails and
// A restores its remembered value over B's. Because the lock spans mutate,
// persist and rollback, B cannot start until A has finished either way.
//
// persist receives the *ServerSettings with the new values already in place and
// the lock held; it is expected to marshal and store it (db.SetSetting) and must
// not call back into any accessor here.
func (s *ServerSettings) UpdateAndPersist(mutate func(*MutableSettings), persist func(*ServerSettings) error) error {
	if s == nil {
		return ErrSettingsNil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	before := MutableSettings{
		PublicIP:           s.PublicIP,
		APIBind:            s.APIBind,
		APIKey:             s.APIKey,
		AdminUsername:      s.AdminUsername,
		AdminPassword:      s.AdminPassword,
		AdminPasswordWeak:  s.AdminPasswordWeak,
		AdminPath:          s.AdminPath,
		SessionIdleMinutes: s.SessionIdleMinutes,
	}

	after := before
	if mutate != nil {
		mutate(&after)
	}
	s.applyLocked(after)

	if persist == nil {
		return nil
	}
	if err := persist(s); err != nil {
		s.applyLocked(before)
		return err
	}
	return nil
}

// applyLocked writes a MutableSettings back into the struct. Caller holds mu.
func (s *ServerSettings) applyLocked(m MutableSettings) {
	s.PublicIP = m.PublicIP
	s.APIBind = m.APIBind
	s.APIKey = m.APIKey
	s.AdminUsername = m.AdminUsername
	s.AdminPassword = m.AdminPassword
	s.AdminPasswordWeak = m.AdminPasswordWeak
	s.AdminPath = m.AdminPath
	s.SessionIdleMinutes = m.SessionIdleMinutes
}

// PersistWebPort stores a new dashboard port without changing the port this
// process is serving on.
//
// This is the opposite contract to UpdateAndPersist, and the difference is not
// stylistic. WebPort is bound once, by net.Listen, before this method can ever be
// called; there is no way to move a live listener by assigning to a struct field.
// Writing the new value into the running settings would therefore change nothing
// about what answers requests and everything about what the daemon *says* answers
// them — the console banner, the subscriber portal URLs and the 1-click register
// links all read WebPort directly, and every one of them would start printing a
// port with nothing behind it. So the live struct is left exactly as it is and
// only the stored record moves. The caller tells the operator to restart.
//
// The clone is built field by field rather than by copying the struct, because
// ServerSettings carries a mutex and copying it is what `go vet` reports as
// copylocks. That makes an added field an omission this method cannot notice, and
// the omission is not cosmetic: dropping AdminPassword from the stored record
// would have the next start find no password, generate one, and print it to the
// log — locking the operator out of the panel they were trying to move.
// TestPersistWebPortCarriesEveryField walks the type by reflection and fails on a
// field this literal does not mention, which is the only thing that keeps the
// list honest.
func (s *ServerSettings) PersistWebPort(port int, persist func(*ServerSettings) error) error {
	if s == nil {
		return ErrSettingsNil
	}
	if persist == nil {
		return nil
	}

	// A read lock, not a write lock: nothing here mutates s. It is held across the
	// clone so the credentials, key and advertised IP written to the record agree
	// with each other, exactly as Snapshot does.
	s.mu.RLock()
	defer s.mu.RUnlock()

	return persist(&ServerSettings{
		PublicIP:           s.PublicIP,
		PublicIPv6:         s.PublicIPv6,
		BindHost:           s.BindHost,
		WebPort:            port,
		AdminUsername:      s.AdminUsername,
		AdminPassword:      s.AdminPassword,
		AdminPasswordWeak:  s.AdminPasswordWeak,
		APIKey:             s.APIKey,
		APIBind:            s.APIBind,
		AdminPath:          s.AdminPath,
		SessionIdleMinutes: s.SessionIdleMinutes,
		TrustedProxyCIDRs:  s.TrustedProxyCIDRs,
	})
}
