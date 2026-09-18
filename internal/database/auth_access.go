package database

import (
	"errors"
	"strings"
	"sync"
)

// The authentication record (v2.1 Phase 6): two-factor configuration and the
// LDAP directory settings, stored as the "auth" settings key — which the
// settings envelope seals with the master key, so the TOTP secret and the LDAP
// bind password are encrypted at rest without this file doing anything.
//
// The snapshot rule is the one the other records follow, with sharper teeth:
// this record carries two live credentials, and NEITHER may serialise into any
// response. The dashboard learns booleans ("2FA enabled", "enrollment in
// progress") and the otpauth URI exactly once, at enrollment, when the secret
// must reach the phone. After that the secret is write-only.

// ErrAuthSettingsNil is returned when a nil record is handed a method that
// needs one, which means the daemon was wired up wrong.
var ErrAuthSettingsNil = errors.New("auth settings are not initialised")

// AuthSettings is the persisted "auth" record.
type AuthSettings struct {
	mu sync.RWMutex

	// TOTP / 2FA.
	TOTPEnabled     bool   `json:"totp_enabled"`
	TOTPSecret      string `json:"totp_secret"`       // base32, encrypted at rest by the settings envelope
	TOTPPending     string `json:"totp_pending"`      // enrollment secret until a code confirms it
	TOTPConfirmedAt string `json:"totp_confirmed_at"` // RFC3339; empty until first confirmation

	// LDAP.
	LDAPEnabled      bool   `json:"ldap_enabled"`
	LDAPServerURL    string `json:"ldap_server_url"` // ldaps://host:636 preferred
	LDAPBindDN       string `json:"ldap_bind_dn"`
	LDAPBindPassword string `json:"ldap_bind_password"` // encrypted at rest; NEVER serialised
	LDAPBaseDN       string `json:"ldap_base_dn"`
	LDAPUserAttr     string `json:"ldap_user_attr"` // "uid", "sAMAccountName", …
	// LDAPLoginMode: "local" (default), "ldap", or "both".
	LDAPLoginMode string `json:"ldap_login_mode"`
}

// AuthSnapshot is what leaves the process. Both credentials are structurally
// absent — the fields do not exist on the type, so no handler can leak them by
// marshalling carelessly. TestAuthSnapshotCarriesNoSecrets walks the type to
// keep that true.
type AuthSnapshot struct {
	TOTPEnabled    bool   `json:"totp_enabled"`
	TOTPConfigured bool   `json:"totp_configured"` // a confirmed secret exists
	TOTPEnrolling  bool   `json:"totp_enrolling"`  // a pending enrollment is open
	OTPAuthURI     string `json:"otpauth_uri"`     // set ONLY during enrollment
	LDAPEnabled    bool   `json:"ldap_enabled"`
	LDAPServerURL  string `json:"ldap_server_url"`
	LDAPBindDN     string `json:"ldap_bind_dn"`
	LDAPBaseDN     string `json:"ldap_base_dn"`
	LDAPUserAttr   string `json:"ldap_user_attr"`
	LDAPLoginMode  string `json:"ldap_login_mode"`
	LDAPReachable  *bool  `json:"ldap_reachable"` // nil = never probed
}

// Snapshot copies the displayable auth state under one lock.
func (a *AuthSettings) Snapshot() AuthSnapshot {
	if a == nil {
		return AuthSnapshot{LDAPLoginMode: "local"}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	s := AuthSnapshot{
		TOTPEnabled:    a.TOTPEnabled,
		TOTPConfigured: a.TOTPConfirmedAt != "" && a.TOTPSecret != "",
		TOTPEnrolling:  a.TOTPPending != "",
		LDAPEnabled:    a.LDAPEnabled,
		LDAPServerURL:  a.LDAPServerURL,
		LDAPBindDN:     a.LDAPBindDN,
		LDAPBaseDN:     a.LDAPBaseDN,
		LDAPUserAttr:   a.LDAPUserAttr,
		LDAPLoginMode:  a.ldapModeLocked(),
	}
	// The otpauth URI is only ever published while an enrollment is open — the
	// one moment the secret has to reach the phone. A confirmed record never
	// hands it back, not even to the operator who enrolled it.
	if s.TOTPEnrolling && a.TOTPPending != "" {
		s.OTPAuthURI = "present" // the handler builds the real URI; the snapshot carries no secret
	}
	return s
}

// ldapModeLocked normalises the stored mode. Caller holds mu.
func (a *AuthSettings) ldapModeLocked() string {
	switch strings.ToLower(strings.TrimSpace(a.LDAPLoginMode)) {
	case "ldap":
		return "ldap"
	case "both":
		return "both"
	default:
		return "local"
	}
}

// GetTOTPSecret returns the confirmed enrollment secret, for verification only.
func (a *AuthSettings) GetTOTPSecret() string {
	if a == nil {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.TOTPConfirmedAt == "" {
		return ""
	}
	return a.TOTPSecret
}

// GetPendingSecret returns the enrollment secret awaiting confirmation.
func (a *AuthSettings) GetPendingSecret() string {
	if a == nil {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.TOTPPending
}

// TOTPEnabledNow reports whether 2FA is in force: an enabled flag backed by a
// confirmed secret. A flag with no secret is a half-applied state and must not
// gate logins.
func (a *AuthSettings) TOTPEnabledNow() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.TOTPEnabled && a.TOTPConfirmedAt != "" && a.TOTPSecret != ""
}

// LDAPConfigNow returns the directory configuration in force, ready for the
// authenticator. The second result is false when LDAP is not both enabled and
// configured, which is the caller's signal to fall back to local credentials.
func (a *AuthSettings) LDAPConfigNow() (LDAPConfigSnapshot, bool) {
	if a == nil {
		return LDAPConfigSnapshot{}, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.LDAPEnabled || strings.TrimSpace(a.LDAPServerURL) == "" || strings.TrimSpace(a.LDAPBaseDN) == "" {
		return LDAPConfigSnapshot{}, false
	}
	return LDAPConfigSnapshot{
		ServerURL:    a.LDAPServerURL,
		BindDN:       a.LDAPBindDN,
		BindPassword: a.LDAPBindPassword,
		BaseDN:       a.LDAPBaseDN,
		UserAttr:     a.LDAPUserAttr,
	}, true
}

// LDAPConfigSnapshot is the fields the authenticator needs, handed across the
// package boundary. It is never serialised anywhere.
type LDAPConfigSnapshot struct {
	ServerURL    string
	BindDN       string
	BindPassword string
	BaseDN       string
	UserAttr     string
}

// GetLDAPLoginMode returns the normalised mode: "local", "ldap", or "both".
func (a *AuthSettings) GetLDAPLoginMode() string {
	if a == nil {
		return "local"
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ldapModeLocked()
}

// StoredBindPassword returns the raw bind password for the one caller that
// must preserve it across a partial save (the LDAP settings handler when the
// form arrived without a new password). It must never be written to a
// response or a log.
func (a *AuthSettings) StoredBindPassword() string {
	if a == nil {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.LDAPBindPassword
}

// SetTOTPPending opens (or re-opens) an enrollment: a fresh secret is drawn,
// stored in the pending slot, and handed back so the handler can build the
// otpauth URI. An enrollment on an already-enabled record is refused — disabling
// 2FA first is the deliberate extra step that stops a one-click downgrade.
func (a *AuthSettings) SetTOTPPending(secret string, persist func(*AuthSettings) error) error {
	if a == nil {
		return ErrAuthSettingsNil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.TOTPEnabled && a.TOTPConfirmedAt != "" {
		return errors.New("two-factor is already active; disable it before enrolling again")
	}
	a.TOTPPending = secret
	if persist == nil {
		return nil
	}
	return persist(a)
}

// ConfirmTOTP verifies a code against the pending secret and, on success,
// promotes it: enabled on, secret set, pending cleared, timestamp recorded.
// A wrong code leaves the enrollment open and changes nothing.
func (a *AuthSettings) ConfirmTOTP(code, confirmedAt string, verify func(secret, code string) bool, persist func(*AuthSettings) error) (bool, error) {
	if a == nil {
		return false, ErrAuthSettingsNil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.TOTPPending == "" {
		return false, errors.New("no enrollment is open")
	}
	if !verify(a.TOTPPending, code) {
		return false, nil
	}
	a.TOTPEnabled = true
	a.TOTPSecret = a.TOTPPending
	a.TOTPPending = ""
	a.TOTPConfirmedAt = confirmedAt
	if persist == nil {
		return true, nil
	}
	if err := persist(a); err != nil {
		// Roll the promotion back so the record matches what was stored.
		a.TOTPEnabled = false
		a.TOTPSecret = ""
		a.TOTPConfirmedAt = ""
		return false, err
	}
	return true, nil
}

// DisableTOTP turns 2FA off and erases the material. The caller must have
// already re-authenticated the operator and verified a current one-time code —
// this method is the "how", never the "whether".
func (a *AuthSettings) DisableTOTP(persist func(*AuthSettings) error) error {
	if a == nil {
		return ErrAuthSettingsNil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	enabled, secret, pending, confirmed := a.TOTPEnabled, a.TOTPSecret, a.TOTPPending, a.TOTPConfirmedAt
	a.TOTPEnabled = false
	a.TOTPSecret = ""
	a.TOTPPending = ""
	a.TOTPConfirmedAt = ""
	if persist == nil {
		return nil
	}
	if err := persist(a); err != nil {
		// Roll the erasure back. With the runtime cleared but the store still
		// saying "enabled", every fresh login would skip the second factor
		// until the next restart re-read the record — a failed request that
		// quietly turned 2FA off is worse than a disable that reported its
		// own failure.
		a.TOTPEnabled, a.TOTPSecret, a.TOTPPending, a.TOTPConfirmedAt = enabled, secret, pending, confirmed
		return err
	}
	return nil
}

// SetLDAP applies the directory settings under the write lock with rollback.
// The bind password is stored as given — the settings envelope encrypts it at
// rest — and an empty bind DN/password pair is a legal anonymous-bind setup.
func (a *AuthSettings) SetLDAP(enabled bool, serverURL, bindDN, bindPassword, baseDN, userAttr, loginMode string, persist func(*AuthSettings) error) error {
	if a == nil {
		return ErrAuthSettingsNil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	before := [7]string{a.LDAPServerURL, a.LDAPBindDN, a.LDAPBindPassword, a.LDAPBaseDN, a.LDAPUserAttr, a.LDAPLoginMode}
	beforeEnabled := a.LDAPEnabled

	a.LDAPEnabled = enabled
	a.LDAPServerURL = strings.TrimSpace(serverURL)
	a.LDAPBindDN = strings.TrimSpace(bindDN)
	a.LDAPBindPassword = bindPassword
	a.LDAPBaseDN = strings.TrimSpace(baseDN)
	a.LDAPUserAttr = strings.TrimSpace(userAttr)
	a.LDAPLoginMode = strings.ToLower(strings.TrimSpace(loginMode))

	if persist == nil {
		return nil
	}
	if err := persist(a); err != nil {
		a.LDAPEnabled = beforeEnabled
		a.LDAPServerURL, a.LDAPBindDN, a.LDAPBindPassword, a.LDAPBaseDN, a.LDAPUserAttr, a.LDAPLoginMode = before[0], before[1], before[2], before[3], before[4], before[5]
		return err
	}
	return nil
}
