package database

import "errors"

// SubscriptionSettings access, mirroring settings_access.go and tls_access.go:
// one *SubscriptionSettings is shared by pointer between main, the web panel and
// the REST API, every field can move while portal pages are being rendered, and
// a Go string is a pointer plus a length that two racing readers can observe
// torn. All reads go through the lock.
//
// Persistence is deliberately explicit rather than a generic UpdateAndPersist:
// the subscription record is seeded once by migration (EnsureSubscriptionDefaults)
// and afterwards written whole by the settings handlers. A partial write that
// fails rolls back through Apply, which restores the previous snapshot under the
// same lock that made the change.

// SubscriptionSnapshot is a consistent copy of SubscriptionSettings taken under
// one lock acquisition. Every field is displayable — none is a credential — so
// the snapshot is what /api/config carries and what the settings UI renders.
type SubscriptionSnapshot struct {
	Enabled             bool   `json:"enabled"`
	ListenIP            string `json:"listen_ip"`
	Domain              string `json:"domain"`
	Port                int    `json:"port"`
	URIPath             string `json:"uri_path"`
	Title               string `json:"title"`
	ThemeCSS            string `json:"theme_css"`
	ThemeCSSSource      string `json:"theme_css_source"`
	ThemeCSSPath        string `json:"theme_css_path"`
	ThemeCSSURL         string `json:"theme_css_url"`
	CertPath            string `json:"cert_path"`
	KeyPath             string `json:"key_path"`
	UsePanelCertificate bool   `json:"use_panel_certificate"`
	// PortExplicit mirrors SubscriptionSettings.PortExplicit (models.go): the
	// operator chose this port, so panel-port changes must not follow-copy it.
	PortExplicit bool `json:"port_explicit"`
}

// Snapshot copies every field under a single lock. A nil receiver yields the
// zero snapshot with the defaults a fresh install would have been seeded with,
// so a caller before migration renders the same page a caller after it does.
func (s *SubscriptionSettings) Snapshot() SubscriptionSnapshot {
	if s == nil {
		return SubscriptionSnapshot{
			Enabled:             true,
			URIPath:             "/sub",
			Title:               "HyperDNS",
			UsePanelCertificate: true,
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return SubscriptionSnapshot{
		Enabled:             s.Enabled,
		ListenIP:            s.ListenIP,
		Domain:              s.Domain,
		Port:                s.Port,
		URIPath:             s.URIPath,
		Title:               s.Title,
		ThemeCSS:            s.ThemeCSS,
		ThemeCSSSource:      s.ThemeCSSSource,
		ThemeCSSPath:        s.ThemeCSSPath,
		ThemeCSSURL:         s.ThemeCSSURL,
		CertPath:            s.CertPath,
		KeyPath:             s.KeyPath,
		UsePanelCertificate: s.UsePanelCertificate,
		PortExplicit:        s.PortExplicit,
	}
}

// GetTitle returns the portal brand line in force, falling back to the product
// default when the record carries none.
func (s *SubscriptionSettings) GetTitle() string {
	if s == nil {
		return "HyperDNS"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Title == "" {
		return "HyperDNS"
	}
	return s.Title
}

// GetDomain returns the subscription host a generated link should name, or ""
// when the caller must fall back to the panel's own domain or public IP.
func (s *SubscriptionSettings) GetDomain() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Domain
}

// GetPort returns the port generated links advertise, or 0 when unset.
func (s *SubscriptionSettings) GetPort() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Port
}

// GetCertPath / GetKeyPath return the certificate pair a separate subscription
// domain is served with, or "" when the record reuses the panel's. They exist
// as accessors for the same reason as the rest: the settings struct can be
// rewritten by a save while a listener is being configured, and a bare field
// read would be a data race.
func (s *SubscriptionSettings) GetCertPath() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CertPath
}

func (s *SubscriptionSettings) GetKeyPath() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.KeyPath
}

// GetURIPath returns the portal mount point, normalised to begin with a slash
// and never to end with one (except the bare "/"), or "/sub" when unset.
func (s *SubscriptionSettings) GetURIPath() string {
	if s == nil {
		return "/sub"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.URIPath == "" {
		return "/sub"
	}
	p := s.URIPath
	if p[0] != '/' {
		p = "/" + p
	}
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}

// IsEnabled reports whether the subscriber surface is on. A nil record means
// "on": migration seeds the flag, and until that runs the historical behaviour
// (pages served) is the safer answer than retiring every subscriber link.
func (s *SubscriptionSettings) IsEnabled() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Enabled
}

// Apply swaps the whole record for the given snapshot under one write lock and
// hands the struct to persist with the lock held. If persist fails, every field
// is restored — the running process and the stored record cannot disagree about
// what the portal advertises.
func (s *SubscriptionSettings) Apply(next SubscriptionSnapshot, persist func(*SubscriptionSettings) error) error {
	if s == nil {
		return ErrSubscriptionSettingsNil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	before := SubscriptionSnapshot{
		Enabled:             s.Enabled,
		ListenIP:            s.ListenIP,
		Domain:              s.Domain,
		Port:                s.Port,
		URIPath:             s.URIPath,
		Title:               s.Title,
		ThemeCSS:            s.ThemeCSS,
		ThemeCSSSource:      s.ThemeCSSSource,
		ThemeCSSPath:        s.ThemeCSSPath,
		ThemeCSSURL:         s.ThemeCSSURL,
		CertPath:            s.CertPath,
		KeyPath:             s.KeyPath,
		UsePanelCertificate: s.UsePanelCertificate,
		PortExplicit:        s.PortExplicit,
	}

	s.Enabled = next.Enabled
	s.ListenIP = next.ListenIP
	s.Domain = next.Domain
	s.Port = next.Port
	s.URIPath = next.URIPath
	s.Title = next.Title
	s.ThemeCSS = next.ThemeCSS
	s.ThemeCSSSource = next.ThemeCSSSource
	s.ThemeCSSPath = next.ThemeCSSPath
	s.ThemeCSSURL = next.ThemeCSSURL
	s.CertPath = next.CertPath
	s.KeyPath = next.KeyPath
	s.UsePanelCertificate = next.UsePanelCertificate
	s.PortExplicit = next.PortExplicit

	if persist == nil {
		return nil
	}
	if err := persist(s); err != nil {
		s.Enabled = before.Enabled
		s.ListenIP = before.ListenIP
		s.Domain = before.Domain
		s.Port = before.Port
		s.URIPath = before.URIPath
		s.Title = before.Title
		s.ThemeCSS = before.ThemeCSS
		s.ThemeCSSSource = before.ThemeCSSSource
		s.ThemeCSSPath = before.ThemeCSSPath
		s.ThemeCSSURL = before.ThemeCSSURL
		s.CertPath = before.CertPath
		s.KeyPath = before.KeyPath
		s.UsePanelCertificate = before.UsePanelCertificate
		s.PortExplicit = before.PortExplicit
		return err
	}
	return nil
}

// EnsureSubscriptionDefaults seeds the subscription record on its first load:
// a pre-v2.1 database has no "subscription" record at all, and the panel's own
// domain, port and certificate are exactly what the subscriber links named
// before a separate origin existed. The seed runs once — the presence of the
// stored record stops it — so an operator's later edits are never rewritten by
// a restart, and the panel-domain copy is a starting point rather than a
// binding.
//
// panelDomain and panelPort describe the panel as it is configured right now;
// either may be empty/zero for a record that has not been migrated that far,
// and the seed leaves the corresponding field unset in that case.
func EnsureSubscriptionDefaults(s *SubscriptionSettings, panelDomain string, panelPort int, persist func(*SubscriptionSettings) error) (bool, error) {
	if s == nil {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.URIPath != "" || s.Title != "" || s.Domain != "" || s.Port != 0 {
		// The record was already seeded (or written by a newer build): leave it
		// exactly as it is. Reading must never rewrite an operator's choices.
		return false, nil
	}

	s.Enabled = true
	s.URIPath = "/sub"
	s.Title = "HyperDNS"
	s.UsePanelCertificate = true
	if panelDomain != "" {
		s.Domain = panelDomain
	}
	if panelPort > 0 {
		s.Port = panelPort
	}

	if persist == nil {
		return true, nil
	}
	return true, persist(s)
}

// ErrSubscriptionSettingsNil is returned by Apply on a nil *SubscriptionSettings,
// which means the daemon was wired up wrong rather than that the update failed.
var ErrSubscriptionSettingsNil = errors.New("subscription settings are not initialised")
