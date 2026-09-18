package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"hyperdns/internal/auth"
	"hyperdns/internal/control"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/netutil"
	"hyperdns/internal/service"
)

// daemonControl is the only production adapter between the daemon's live
// collaborators and the root-local control protocol. It deliberately owns no
// storage of its own: every operation below acts on the handles and services
// constructed by main.
type daemonControl struct {
	db        *database.DB
	clients   *service.ClientService
	stats     *service.StatsService
	cache     *cache.Cache
	upstreams *upstream.UpstreamPool
	settings  *database.ServerSettings
	auth      *database.AuthSettings
	sessions  *service.SessionManager
	lockouts  *service.LoginAttemptTracker
	benchmark *service.BenchmarkRunner
	audit     *log.Logger

	// dnsCfg / sniCfg / tlsCfg feed the shared port validator: a panel-port
	// change has to be checked against every listener this daemon binds on
	// its next start, not just against the 1..65535 range. tlsCfg carries the
	// redirect listener's port, which binds whenever the panel serves HTTPS.
	dnsCfg *database.DNSSettings
	sniCfg *database.SNIProxySettings
	tlsCfg *database.TLSSettings

	// subs carries the subscription record for the panel-port operation: a
	// record seeded from the panel origin holds a COPY of the old panel port,
	// and leaving that copy behind after a port change is a real outage —
	// after the restart the copied port no longer equals WebPort, so the
	// daemon binds a dedicated subscriber listener on the port the operator
	// just moved AWAY from (bindSubscriberListener) and every generated link
	// still names it.
	subs *database.SubscriptionSettings
}

func (d *daemonControl) ControlStatus() (control.Status, error) {
	if d == nil || d.stats == nil {
		return control.Status{}, errors.New("stats service is unavailable")
	}
	st := d.stats.GetLiveStats()
	clientCount := 0
	if d.clients != nil {
		clientCount = d.clients.Count()
	}
	return control.Status{
		TotalQueries:     st.TotalQueries,
		QPS:              st.QPS,
		ActiveRelays:     st.ActiveRelays,
		CacheItems:       st.CacheItems,
		CacheHits:        st.CacheHits,
		CacheMisses:      st.CacheMisses,
		UptimeSec:        st.UptimeSec,
		SystemCPUPercent: st.SystemCPUPercent,
		SystemMemUsedMB:  st.SystemMemUsedMB,
		SystemMemTotalMB: st.SystemMemTotalMB,
		SystemMemPercent: st.SystemMemPercent,
		ClientCount:      clientCount,
	}, nil
}

func (d *daemonControl) ControlListClients() ([]control.ClientView, error) {
	if d == nil || d.clients == nil {
		return nil, errors.New("client service is unavailable")
	}
	list, err := d.clients.ListClientViews()
	if err != nil {
		return nil, err
	}
	views := make([]control.ClientView, 0, len(list))
	for i := range list {
		views = append(views, controlClientView(list[i], false))
	}
	return views, nil
}

func (d *daemonControl) ControlCreateClient(req control.CreateClientRequest) (control.ClientView, error) {
	if d == nil || d.clients == nil {
		return control.ClientView{}, errors.New("client service is unavailable")
	}
	client, err := d.clients.ProvisionClient(service.CreateClientRequest{
		Name:              req.Name,
		Days:              req.Days,
		IP:                req.IP,
		TrafficLimitGB:    req.TrafficLimitGB,
		TrafficResetCycle: req.TrafficResetCycle,
		Note:              req.Note,
		CustomPolicies:    req.CustomPolicies,
	})
	if err != nil {
		return control.ClientView{}, err
	}
	return controlClientView(d.clients.ViewClient(client), true), nil
}

func (d *daemonControl) ControlDeleteClient(id string) error {
	if d == nil || d.clients == nil {
		return errors.New("client service is unavailable")
	}
	return d.clients.DeleteClient(id)
}

func controlClientView(v service.ClientView, includeCredentials bool) control.ClientView {
	// Do not marshal service.ClientView directly. It embeds database.Client,
	// which contains the bearer token and registration secret. Listing accounts
	// must never return either credential; a create response is the one deliberate
	// exception because the operator has to hand those values over once.
	out := control.ClientView{
		ID:                    v.ID,
		UUID:                  v.UUID,
		Name:                  v.Name,
		AllowedIPs:            append([]string(nil), v.AllowedIPs...),
		TrafficLimitGB:        v.TrafficLimitGB,
		TrafficUsedBytes:      v.TrafficUsedBytes,
		ExpiresAt:             v.ExpiresAt,
		CreatedAt:             v.CreatedAt,
		LastSeen:              v.LastSeen,
		TotalQueries:          v.TotalQueries,
		Enabled:               v.Enabled,
		Note:                  v.Note,
		CustomPolicies:        append([]string(nil), v.CustomPolicies...),
		TrafficResetCycle:     v.TrafficResetCycle,
		TrafficResetAnchor:    v.TrafficResetAnchor,
		TrafficResetCount:     v.TrafficResetCount,
		TrafficPrevCycleBytes: v.TrafficPrevCycleBytes,
		NextTrafficReset:      v.NextTrafficReset,
		QuotaExceeded:         v.QuotaExceeded,
	}
	if includeCredentials {
		out.SubscriptionToken = v.Token
		out.RegistrationSecret = v.RegisterSecret
	}
	return out
}

func (d *daemonControl) ControlSettings() control.SettingsView {
	if d == nil || d.settings == nil {
		return control.SettingsView{}
	}
	s := d.settings.Snapshot()
	out := control.SettingsView{
		PublicIP:           s.PublicIP,
		BindHost:           s.BindHost,
		WebPort:            s.WebPort,
		AdminUsername:      s.AdminUsername,
		APIKey:             s.APIKey,
		AdminPasswordWeak:  s.AdminPasswordWeak,
		APIBind:            s.APIBind,
		AdminPath:          s.AdminPath,
		SessionIdleMinutes: s.SessionIdleMinutes,
	}
	if d.auth != nil {
		a := d.auth.Snapshot()
		out.TOTPEnabled = a.TOTPEnabled
		out.LDAPEnabled = a.LDAPEnabled
		out.LDAPLoginMode = a.LDAPLoginMode
	}
	return out
}

func (d *daemonControl) ControlRotateAPIKey(req control.RotateAPIKeyRequest) (control.RotateAPIKeyResult, error) {
	if d == nil || d.settings == nil || d.db == nil {
		return control.RotateAPIKeyResult{}, errors.New("settings service is unavailable")
	}
	if !d.verifyCurrentPassword(req.CurrentPassword) {
		return control.RotateAPIKeyResult{}, control.NewError(403, "current_password_invalid", "current password is incorrect", nil)
	}
	if err := d.requireTOTP(req.TOTPCode); err != nil {
		return control.RotateAPIKeyResult{}, err
	}
	newKey := crypto.GenerateAPIKey()
	if err := d.settings.UpdateAndPersist(
		func(m *database.MutableSettings) { m.APIKey = newKey },
		func(s *database.ServerSettings) error { return d.db.SetSetting("server", s) },
	); err != nil {
		return control.RotateAPIKeyResult{}, control.NewError(500, "persist_failed", "could not save the new API key", nil)
	}
	if d.audit != nil {
		d.audit.Print("REST API key rotated through the local control plane")
	}
	return control.RotateAPIKeyResult{APIKey: newKey}, nil
}

func (d *daemonControl) ControlPersistPanelPort(port int) error {
	if d == nil || d.settings == nil || d.db == nil {
		return errors.New("settings service is unavailable")
	}
	if port < 1 || port > 65535 {
		return control.NewError(400, "invalid_port", "panel port is invalid", nil)
	}
	// The shared validator (v2.2.0): a port this daemon itself binds on its
	// next start is a fatal collision in service mode — log.Fatalf takes the
	// resolver down with the panel — so it is refused here, at the moment of
	// the change, instead of at the next boot. The probe catches what the
	// settings cannot see: something outside HyperDNS already holding the
	// port.
	snap := d.settings.Snapshot()
	_, _, err := netutil.ValidatePort(strconv.Itoa(port), snap.WebPort, d.dnsCfg, d.sniCfg, d.tlsCfg)
	if err != nil {
		return control.NewError(400, "invalid_port", "panel port refused: "+err.Error(), nil)
	}
	if err := netutil.ProbeBind(snap.BindHost, port); err != nil {
		return control.NewError(400, "port_busy", "something outside HyperDNS is already binding that port: "+err.Error(), nil)
	}
	if err := d.settings.PersistWebPort(port, func(s *database.ServerSettings) error {
		return d.db.SetSetting("server", s)
	}); err != nil {
		return control.NewError(500, "persist_failed", "could not save the panel port", nil)
	}

	// The subscription record holds a seeded copy of the panel port. When the
	// record is still riding the panel origin (no custom port was ever set
	// there), the copy must follow the panel to the new port — otherwise the
	// next boot sees subPort != WebPort and binds a subscriber listener on
	// the port the operator just left, serving it with the subscription
	// record's certificate to anyone who still has the old URL. A custom
	// port (deliberately different) is left alone.
	if d.subs != nil {
		// The copy follows the panel only while it is the seeded default (it
		// still equals the OLD panel port) and has never been a deliberate
		// choice: PortExplicit marks a port the operator set, and a marked
		// port is left exactly where they put it. A record with its own
		// distinct origin never carried the panel's port to begin with.
		subSnap := d.subs.Snapshot()
		if !subSnap.PortExplicit && subSnap.Port == snap.WebPort {
			subSnap.Port = port
			subSnap.PortExplicit = false
			if err := d.subs.Apply(subSnap, func(s *database.SubscriptionSettings) error {
				return d.db.SetSetting("subscription", s)
			}); err != nil {
				// The panel port itself saved; this is a secondary record.
				// Report it rather than fail the whole operation: the
				// operator knows the panel moved, and the next save of the
				// subscription card repairs the port.
				log.Printf("[Control] panel port saved but the subscription record's port copy could not follow: %v", err)
			}
		}
	}
	return nil
}

func (d *daemonControl) ControlClearLockouts(req control.ClearLockoutsRequest) (int, error) {
	if d == nil || d.lockouts == nil {
		return 0, errors.New("lockout service is unavailable")
	}
	if ip := strings.TrimSpace(req.IP); ip != "" {
		if net.ParseIP(ip) == nil {
			return 0, control.NewError(400, "invalid_ip", "lockout IP is invalid", nil)
		}
		if d.lockouts.Reset(ip) {
			return 1, nil
		}
		return 0, nil
	}
	return d.lockouts.ResetAll(), nil
}

func (d *daemonControl) ControlChangeAdmin(req control.ChangeAdminRequest) error {
	if d == nil || d.settings == nil || d.db == nil {
		return errors.New("settings service is unavailable")
	}
	currentUser, currentVerifier, _ := d.settings.AdminCredentials()
	if currentUser == "" {
		currentUser = "admin"
	}
	if !d.verifyVerifier(currentVerifier, req.CurrentPassword) {
		return control.NewError(403, "current_password_invalid", "current password is incorrect", nil)
	}
	if err := d.requireTOTP(req.TOTPCode); err != nil {
		return err
	}
	newUser := currentUser
	if req.Username != "" {
		newUser = strings.TrimSpace(req.Username)
		if newUser != req.Username || newUser == "" || len([]rune(newUser)) > 64 {
			return control.NewError(400, "invalid_request", "admin username is invalid", nil)
		}
	}
	newVerifier := currentVerifier
	changePassword := req.Password != ""
	if changePassword {
		if err := crypto.ValidatePasswordStrength(newUser, req.Password); err != nil {
			return control.NewError(400, "invalid_request", "admin password does not meet policy", nil)
		}
		var err error
		newVerifier, err = crypto.HashPassword(req.Password)
		if err != nil {
			return control.NewError(500, "hash_failed", "could not prepare replacement credentials", nil)
		}
	}
	if newUser == currentUser && !changePassword {
		return nil
	}
	if err := d.settings.UpdateAndPersist(
		func(m *database.MutableSettings) {
			m.AdminUsername = newUser
			if changePassword {
				m.AdminPassword = newVerifier
				m.AdminPasswordWeak = false
			}
		},
		func(s *database.ServerSettings) error { return d.db.SetSetting("server", s) },
	); err != nil {
		return control.NewError(500, "persist_failed", "could not save administrator settings", nil)
	}
	if changePassword && d.sessions != nil {
		d.sessions.DeleteAll()
	}
	if d.audit != nil {
		d.audit.Print("administrator credentials changed through the local control plane")
	}
	return nil
}

func (d *daemonControl) ControlResetAdmin(req control.ResetAdminRequest) error {
	if d == nil || d.settings == nil || d.db == nil {
		return errors.New("settings service is unavailable")
	}
	recovery := control.NewAdminRecovery(d.settings, d.auth, d.sessions,
		serverSettingsPersister{db: d.db}, d.audit)
	return recovery.Reset(req)
}

type serverSettingsPersister struct{ db *database.DB }

func (p serverSettingsPersister) PersistServerSettings(s *database.ServerSettings) error {
	if p.db == nil {
		return errors.New("database is unavailable")
	}
	return p.db.SetSetting("server", s)
}

func (d *daemonControl) verifyCurrentPassword(password string) bool {
	if d == nil || d.settings == nil {
		return false
	}
	_, verifier, _ := d.settings.AdminCredentials()
	return d.verifyVerifier(verifier, password)
}

func (d *daemonControl) verifyVerifier(verifier, password string) bool {
	// VerifyPassword handles both the current PBKDF2 format and legacy plaintext
	// records. The explicit constant-time fallback is retained for malformed
	// legacy values only so a bad record cannot accidentally authorize.
	if verifier == "" || password == "" {
		return false
	}
	if crypto.IsPasswordHash(verifier) {
		return crypto.VerifyPassword(verifier, password)
	}
	return subtle.ConstantTimeCompare([]byte(verifier), []byte(password)) == 1
}

func (d *daemonControl) requireTOTP(code string) error {
	if d == nil || d.auth == nil || !d.auth.TOTPEnabledNow() {
		return nil
	}
	if !auth.ValidateTOTP(d.auth.GetTOTPSecret(), code) {
		return control.NewError(401, "totp_required", "a valid one-time code is required", nil)
	}
	return nil
}

// Ensure the adapter still satisfies the narrow interfaces expected by the
// control package. These assertions intentionally live in production code so a
// future signature drift fails at compile time rather than at daemon startup.
var (
	_ control.Status = control.Status{}
	_ interface {
		ControlStatus() (control.Status, error)
		ControlListClients() ([]control.ClientView, error)
		ControlCreateClient(control.CreateClientRequest) (control.ClientView, error)
		ControlDeleteClient(string) error
	} = (*daemonControl)(nil)
	_ interface {
		ControlSettings() control.SettingsView
		ControlRotateAPIKey(control.RotateAPIKeyRequest) (control.RotateAPIKeyResult, error)
		ControlPersistPanelPort(int) error
		ControlClearLockouts(control.ClearLockoutsRequest) (int, error)
		ControlChangeAdmin(control.ChangeAdminRequest) error
		ControlResetAdmin(control.ResetAdminRequest) error
	} = (*daemonControl)(nil)
)

// Keep fmt imported in older Go toolchains where errors.As formatting in a
// wrapped adapter error is useful to callers during diagnostics.
var _ = fmt.Sprintf
