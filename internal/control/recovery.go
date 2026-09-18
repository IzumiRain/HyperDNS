package control

import (
	"log"
	"net/http"
	"strings"
	"unicode/utf8"

	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

type serverSettingsStore interface {
	PersistServerSettings(*database.ServerSettings) error
}

type sessionRevoker interface {
	DeleteAll()
}

// AdminRecovery performs the root-local credential reset. Transport
// authorization is deliberately outside this type; only the Unix control server
// can expose it.
type AdminRecovery struct {
	settings *database.ServerSettings
	auth     *database.AuthSettings
	sessions sessionRevoker
	store    serverSettingsStore
	audit    *log.Logger
}

func NewAdminRecovery(
	settings *database.ServerSettings,
	authSettings *database.AuthSettings,
	sessions sessionRevoker,
	store serverSettingsStore,
	audit *log.Logger,
) *AdminRecovery {
	return &AdminRecovery{
		settings: settings,
		auth:     authSettings,
		sessions: sessions,
		store:    store,
		audit:    audit,
	}
}

func (r *AdminRecovery) Reset(req ResetAdminRequest) error {
	if err := validateAdminIdentity(req.Username, req.Password); err != nil {
		return err
	}
	if r == nil || r.settings == nil || r.store == nil {
		return NewError(http.StatusServiceUnavailable, "unavailable", "admin recovery is unavailable", nil)
	}

	verifier, err := crypto.HashPassword(req.Password)
	if err != nil {
		return NewError(http.StatusInternalServerError, "hash_failed", "could not prepare replacement credentials", nil)
	}
	if err := r.settings.UpdateAndPersist(
		func(m *database.MutableSettings) {
			m.AdminUsername = req.Username
			m.AdminPassword = verifier
			m.AdminPasswordWeak = false
		},
		r.store.PersistServerSettings,
	); err != nil {
		return NewError(http.StatusInternalServerError, "persist_failed", "could not save replacement credentials", nil)
	}

	if r.sessions != nil {
		r.sessions.DeleteAll()
	}
	if r.audit != nil {
		r.audit.Print("root-local admin reset completed; all sessions revoked")
	}
	return nil
}

func validateAdminIdentity(username, password string) error {
	if username == "" || !utf8.ValidString(username) || strings.TrimSpace(username) != username || utf8.RuneCountInString(username) > 64 {
		return NewError(http.StatusBadRequest, "invalid_request", "admin username is invalid", nil)
	}
	if err := crypto.ValidatePasswordStrength(username, password); err != nil {
		return NewError(http.StatusBadRequest, "invalid_request", "admin password does not meet policy", nil)
	}
	return nil
}
