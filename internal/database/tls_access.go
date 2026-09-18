package database

import "errors"

// Runtime mutation of TLSSettings.
//
// One *TLSSettings is shared by pointer between main, the web panel and the REST
// API. Two of its fields move while the daemon is serving — Domain and Email, both
// written by /api/tls/issue — and both are read from other goroutines, because the
// dashboard's config and status responses carry them.
//
// The hazard is the one set out at the top of settings_access.go: a Go string is a
// pointer plus a length, the two words are not written atomically, and a read
// racing a write can observe a pointer that never went with that length. Here the
// domain is what a certificate is requested for and what the subscriber portal
// tells people to point their devices at, so a torn read is not a cosmetic glitch
// on a settings page.
//
// Startup is exempt, as it is there: main and applyConfigFile assign these fields
// directly, before any listener exists and while one goroutine is running.

// ErrTLSSettingsNil is returned by SetACME when it is called on a nil
// *TLSSettings, which means the daemon was wired up wrong rather than that the
// update failed.
var ErrTLSSettingsNil = errors.New("tls settings are not initialised")

// TLSSnapshot is a consistent copy of TLSSettings taken under one lock
// acquisition. Its JSON shape matches TLSSettings field for field, because it is
// what the dashboard's /api/config and /api/status responses carry in place of the
// live struct.
type TLSSnapshot struct {
	Domain        string `json:"domain"`
	Email         string `json:"email"`
	CertPath      string `json:"cert_path"`
	KeyPath       string `json:"key_path"`
	AutoRenewACME bool   `json:"auto_renew_acme"`
	DoTDomain     string `json:"dot_domain"`
	PanelHTTPS    bool   `json:"panel_https"`
	RedirectPort  int    `json:"redirect_port"`
}

// Snapshot copies every field under a single lock.
func (t *TLSSettings) Snapshot() TLSSnapshot {
	if t == nil {
		return TLSSnapshot{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return TLSSnapshot{
		Domain:        t.Domain,
		Email:         t.Email,
		CertPath:      t.CertPath,
		KeyPath:       t.KeyPath,
		AutoRenewACME: t.AutoRenewACME,
		DoTDomain:     t.DoTDomain,
		PanelHTTPS:    t.PanelHTTPS,
		RedirectPort:  t.RedirectPort,
	}
}

// ACMEContact returns the domain a certificate is issued for together with the
// registration contact, so a caller that reports or renews with both cannot
// describe two different moments.
func (t *TLSSettings) ACMEContact() (domain, email string) {
	if t == nil {
		return "", ""
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Domain, t.Email
}

// GetDomain returns the domain in force, or "" when none is configured — which is
// how a caller learns the daemon has only its self-signed certificate.
func (t *TLSSettings) GetDomain() string {
	if t == nil {
		return ""
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Domain
}

// GetDoTDomain returns the custom DoH/DoT hostname, or "" when the transport
// listeners ride the panel domain.
func (t *TLSSettings) GetDoTDomain() string {
	if t == nil {
		return ""
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.DoTDomain
}

// SetDoTDomain applies the custom DoH/DoT hostname with the same
// rollback-on-persist-failure contract as SetACME.
func (t *TLSSettings) SetDoTDomain(domain string, persist func(*TLSSettings) error) error {
	if t == nil {
		return ErrTLSSettingsNil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	before := t.DoTDomain
	t.DoTDomain = domain
	if persist == nil {
		return nil
	}
	if err := persist(t); err != nil {
		t.DoTDomain = before
		return err
	}
	return nil
}

// SetACME applies domain and email, calls persist, and restores both if the write
// fails — all under one write lock, so the running process and the stored record
// cannot end up disagreeing about which name this daemon answers for. Two tabs
// saving at once therefore produce one winner rather than a half-applied pair.
//
// persist receives the *TLSSettings with the new values already in place and the
// lock held; it is expected to marshal and store it (db.SetSetting) and must not
// call back into any accessor here.
func (t *TLSSettings) SetACME(domain, email string, persist func(*TLSSettings) error) error {
	if t == nil {
		return ErrTLSSettingsNil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	beforeDomain, beforeEmail := t.Domain, t.Email
	t.Domain, t.Email = domain, email

	if persist == nil {
		return nil
	}
	if err := persist(t); err != nil {
		t.Domain, t.Email = beforeDomain, beforeEmail
		return err
	}
	return nil
}

// SetCertPaths points the record at a newly issued (or operator-supplied)
// certificate pair, with the same rollback-on-persist-failure contract as
// SetACME. Called by the embedded ACME flow after the pair is on disk and has
// passed ValidatePanelCertificate — the ordering that keeps a failed write
// from orphaning the daemon on paths nothing validates at boot.
func (t *TLSSettings) SetCertPaths(certPath, keyPath string, persist func(*TLSSettings) error) error {
	if t == nil {
		return ErrTLSSettingsNil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	beforeCert, beforeKey := t.CertPath, t.KeyPath
	t.CertPath, t.KeyPath = certPath, keyPath

	if persist == nil {
		return nil
	}
	if err := persist(t); err != nil {
		t.CertPath, t.KeyPath = beforeCert, beforeKey
		return err
	}
	return nil
}
