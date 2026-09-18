package control

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
)

type recoveryStoreStub struct {
	stored  *database.ServerSettings
	fail    error
	masters []byte
}

func (s *recoveryStoreStub) PersistServerSettings(settings *database.ServerSettings) error {
	if s.fail != nil {
		return s.fail
	}
	s.stored = cloneServerSettings(settings)
	return nil
}

func cloneServerSettings(s *database.ServerSettings) *database.ServerSettings {
	if s == nil {
		return nil
	}
	return &database.ServerSettings{
		PublicIP: s.PublicIP, BindHost: s.BindHost, WebPort: s.WebPort,
		AdminUsername: s.AdminUsername, AdminPassword: s.AdminPassword,
		AdminPasswordWeak: s.AdminPasswordWeak, APIKey: s.APIKey,
		APIBind: s.APIBind, AdminPath: s.AdminPath,
		SessionIdleMinutes: s.SessionIdleMinutes,
		TrustedProxyCIDRs:  append([]string(nil), s.TrustedProxyCIDRs...),
	}
}

func recoverySettings(t *testing.T) *database.ServerSettings {
	t.Helper()
	verifier, err := crypto.HashPasswordWithCost("Old-Password-91", 1000)
	if err != nil {
		t.Fatal(err)
	}
	return &database.ServerSettings{
		PublicIP: "203.0.113.8", BindHost: "127.0.0.1", WebPort: 8443,
		AdminUsername: "old-admin", AdminPassword: verifier,
		AdminPasswordWeak: true, APIKey: "hdns_live_keep_this_secret",
		APIBind: "127.0.0.1", AdminPath: "0123456789abcdef",
		SessionIdleMinutes: 47, TrustedProxyCIDRs: []string{"10.0.0.0/8"},
	}
}

func TestAdminRecoveryCommitsBeforeRevokingSessionsAndPreservesState(t *testing.T) {
	settings := recoverySettings(t)
	authSettings := &database.AuthSettings{
		TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP",
		TOTPConfirmedAt: "2026-01-02T03:04:05Z", LDAPEnabled: true,
		LDAPServerURL: "ldaps://directory.example:636", LDAPBindDN: "cn=bind",
		LDAPBindPassword: "ldap-bind-secret", LDAPBaseDN: "dc=example,dc=com",
		LDAPUserAttr: "uid", LDAPLoginMode: "both",
	}
	authBefore := authSettings.Snapshot()
	bindBefore := authSettings.StoredBindPassword()
	store := &recoveryStoreStub{masters: []byte("synthetic-master-key-fixture")}
	sessions := service.NewSessionManager(time.Hour)
	defer sessions.Close()
	sessions.Create()
	sessions.Create()
	var audit bytes.Buffer
	recovery := NewAdminRecovery(settings, authSettings, sessions, store, log.New(&audit, "", 0))

	if err := recovery.Reset(ResetAdminRequest{Username: "recovered-admin", Password: "Fresh-Phrase-92!"}); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	username, verifier, weak := settings.AdminCredentials()
	if username != "recovered-admin" || weak || !crypto.VerifyPassword(verifier, "Fresh-Phrase-92!") {
		t.Fatalf("credentials after reset = user %q weak=%v valid=%v", username, weak, crypto.VerifyPassword(verifier, "Fresh-Phrase-92!"))
	}
	if verifier == "Fresh-Phrase-92!" || !crypto.IsPasswordHash(verifier) {
		t.Fatal("replacement password was not stored as a verifier")
	}
	if store.stored == nil {
		t.Fatal("settings were not persisted")
	}
	storedUser, storedVerifier, storedWeak := store.stored.AdminCredentials()
	if storedUser != username || storedVerifier != verifier || storedWeak != weak {
		t.Fatal("stored credentials do not match committed runtime credentials")
	}
	if sessions.Count() != 0 {
		t.Fatalf("sessions after commit = %d, want 0", sessions.Count())
	}
	assertRecoveryStatePreserved(t, settings, authSettings, authBefore, bindBefore, store.masters)
	if got := audit.String(); !strings.Contains(got, "root-local admin reset") {
		t.Fatalf("audit = %q, want root-local reset event", got)
	} else {
		for _, secret := range []string{"old-admin", "recovered-admin", "Fresh-Phrase-92!", verifier, "JBSWY3DPEHPK3PXP", "ldap-bind-secret", "hdns_live_keep_this_secret"} {
			if strings.Contains(got, secret) {
				t.Fatalf("audit leaked sensitive value %q", secret)
			}
		}
	}
}

func assertRecoveryStatePreserved(t *testing.T, settings *database.ServerSettings, authSettings *database.AuthSettings, authBefore database.AuthSnapshot, bindBefore string, master []byte) {
	t.Helper()
	snap := settings.Snapshot()
	if snap.PublicIP != "203.0.113.8" || snap.BindHost != "127.0.0.1" || snap.WebPort != 8443 || snap.APIBind != "127.0.0.1" || snap.AdminPath != "0123456789abcdef" || snap.SessionIdleMinutes != 47 {
		t.Fatalf("unrelated server settings changed: %+v", snap)
	}
	if settings.GetAPIKey() != "hdns_live_keep_this_secret" || len(settings.TrustedProxyCIDRs) != 1 || settings.TrustedProxyCIDRs[0] != "10.0.0.0/8" {
		t.Fatal("API key or trusted proxies changed")
	}
	if got := authSettings.Snapshot(); got != authBefore || authSettings.StoredBindPassword() != bindBefore {
		t.Fatalf("auth settings changed: before=%+v after=%+v", authBefore, got)
	}
	if string(master) != "synthetic-master-key-fixture" {
		t.Fatal("synthetic master-key fixture changed")
	}
}

func TestAdminRecoveryPersistenceFailureRollsBackWithoutRevokingOrLeaking(t *testing.T) {
	settings := recoverySettings(t)
	before := settings.Snapshot()
	_, beforeVerifier, beforeWeak := settings.AdminCredentials()
	authSettings := &database.AuthSettings{TOTPEnabled: true, TOTPSecret: "TOTP-KEEP", TOTPConfirmedAt: "confirmed", LDAPBindPassword: "LDAP-KEEP", LDAPLoginMode: "both"}
	authBefore := authSettings.Snapshot()
	store := &recoveryStoreStub{fail: errors.New("storage rejected credential material Fresh-Phrase-92!"), masters: []byte("synthetic-master-key-fixture")}
	sessions := service.NewSessionManager(time.Hour)
	defer sessions.Close()
	token := sessions.Create()
	var audit bytes.Buffer
	recovery := NewAdminRecovery(settings, authSettings, sessions, store, log.New(&audit, "", 0))

	err := recovery.Reset(ResetAdminRequest{Username: "recovered-admin", Password: "Fresh-Phrase-92!"})
	opErr, ok := asError(err)
	if !ok || opErr.Status != http.StatusInternalServerError || opErr.Code != "persist_failed" {
		t.Fatalf("error = %T %v, want persist_failed", err, err)
	}
	if strings.Contains(err.Error(), "Fresh-Phrase-92!") || strings.Contains(audit.String(), "Fresh-Phrase-92!") {
		t.Fatal("persistence failure leaked the replacement credential")
	}
	if got := settings.Snapshot(); got != before {
		t.Fatalf("runtime settings changed: before=%+v after=%+v", before, got)
	}
	if _, got, weak := settings.AdminCredentials(); got != beforeVerifier || weak != beforeWeak {
		t.Fatal("runtime verifier or weak flag changed after failure")
	}
	if store.stored != nil {
		t.Fatal("failed persistence produced a stored settings snapshot")
	}
	if sessions.Count() != 1 || !sessions.Validate(token) {
		t.Fatal("sessions were revoked after failed persistence")
	}
	assertRecoveryStatePreserved(t, settings, authSettings, authBefore, "LDAP-KEEP", store.masters)
}

func TestAdminRecoveryValidatesBeforeMutation(t *testing.T) {
	tests := []ResetAdminRequest{
		{Username: "", Password: "Fresh-Phrase-92!"},
		{Username: " recovered", Password: "Fresh-Phrase-92!"},
		{Username: strings.Repeat("u", 65), Password: "Fresh-Phrase-92!"},
		{Username: "recovered", Password: "short"},
		{Username: "recovered", Password: "recovered"},
	}
	for _, req := range tests {
		settings := recoverySettings(t)
		before := settings.Snapshot()
		_, verifier, weak := settings.AdminCredentials()
		store := &recoveryStoreStub{masters: []byte("synthetic-master-key-fixture")}
		sessions := service.NewSessionManager(time.Hour)
		token := sessions.Create()
		recovery := NewAdminRecovery(settings, &database.AuthSettings{}, sessions, store, log.New(&bytes.Buffer{}, "", 0))

		err := recovery.Reset(req)
		opErr, ok := asError(err)
		if !ok || opErr.Code != "invalid_request" {
			t.Fatalf("request user=%q error = %T %v, want invalid_request", req.Username, err, err)
		}
		if got := settings.Snapshot(); got != before {
			t.Fatalf("invalid request mutated settings: %+v", got)
		}
		if _, got, gotWeak := settings.AdminCredentials(); got != verifier || gotWeak != weak {
			t.Fatal("invalid request mutated verifier")
		}
		if store.stored != nil || sessions.Count() != 1 || !sessions.Validate(token) {
			t.Fatal("invalid request reached persistence or session mutation")
		}
		sessions.Close()
	}
}
