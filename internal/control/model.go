package control

import (
	"context"
	"errors"
	"time"
)

const (
	DefaultSocketPath     = "/run/hyperdns/control.sock"
	ProtocolVersion       = "v1"
	ProtocolVersionHeader = "X-HyperDNS-Control-Version"
)

// ErrUnsupported reports that this build has no root-local control transport.
// Only the non-Linux Server returns it; it is declared here, on the
// platform-neutral side, so a caller on any platform can recognise "this host
// cannot offer the management socket" and distinguish it from "the socket could
// not be secured on a host that should have one". The first is a capability
// limit the daemon runs without; the second is fatal.
var ErrUnsupported = errors.New("HyperDNS control server requires Linux Unix peer credentials")

// ErrRuntimeDir reports that the control runtime directory could not be
// created — an unprivileged run against /run/hyperdns, or a read-only /run.
// Same class as ErrUnsupported for the caller: a capability limit the daemon
// runs without (DNS, relay and panel are unaffected), not a fatal
// misconfiguration.
var ErrRuntimeDir = errors.New("HyperDNS control runtime directory is unavailable")

// Operations is the complete daemon-owned management boundary. It exposes DTOs,
// never database records or service implementations.
type Operations interface {
	Status(context.Context) (Status, error)
	ListClients(context.Context) ([]ClientView, error)
	CreateClient(context.Context, CreateClientRequest) (ClientView, error)
	DeleteClient(context.Context, string) error
	FlushCache(context.Context) error
	UpdatePresets(context.Context) (UpdatePresetsResult, error)
	StartBenchmark(context.Context) error
	Settings(context.Context) (SettingsView, error)
	RotateAPIKey(context.Context, RotateAPIKeyRequest) (RotateAPIKeyResult, error)
	PersistPanelPort(context.Context, int) error
	ClearLockouts(context.Context, ClearLockoutsRequest) (int, error)
	ChangeAdmin(context.Context, ChangeAdminRequest) error
	ResetAdmin(context.Context, ResetAdminRequest) error
}

// UpdatePresetsResult is the outcome of one channel check-and-apply driven
// from the console. Fields mirror the dashboard's JSON shape so the two
// surfaces read the same.
type UpdatePresetsResult struct {
	Applied   int    `json:"applied"`
	Message   string `json:"message"`
	LastError string `json:"last_error,omitempty"`
}

type Status struct {
	TotalQueries uint64  `json:"total_queries"`
	QPS          float64 `json:"qps"`
	ActiveRelays int64   `json:"active_relays"`
	CacheItems   int     `json:"cache_items"`
	CacheHits    uint64  `json:"cache_hits"`
	CacheMisses  uint64  `json:"cache_misses"`
	UptimeSec    int64   `json:"uptime_sec"`

	// Machine-wide load (internal/sysmetrics), for the console header and the
	// status view: the whole server's CPU and RAM, not the daemon's own.
	// Negative = the platform cannot answer.
	SystemCPUPercent float64 `json:"system_cpu_percent"`
	SystemMemUsedMB  float64 `json:"system_mem_used_mb"`
	SystemMemTotalMB float64 `json:"system_mem_total_mb"`
	SystemMemPercent float64 `json:"system_mem_percent"`

	// ClientCount is the number of provisioned subscriber accounts, read from
	// the same in-memory index the resolver matches against.
	ClientCount int `json:"client_count"`
}

type ClientView struct {
	ID                    string     `json:"id"`
	UUID                  string     `json:"uuid"`
	Name                  string     `json:"name"`
	AllowedIPs            []string   `json:"allowed_ips"`
	TrafficLimitGB        float64    `json:"traffic_limit_gb"`
	TrafficUsedBytes      uint64     `json:"traffic_used_bytes"`
	ExpiresAt             time.Time  `json:"expires_at"`
	CreatedAt             time.Time  `json:"created_at"`
	LastSeen              time.Time  `json:"last_seen"`
	TotalQueries          uint64     `json:"total_queries"`
	Enabled               bool       `json:"enabled"`
	Note                  string     `json:"note"`
	CustomPolicies        []string   `json:"custom_policies"`
	TrafficResetCycle     string     `json:"traffic_reset_cycle"`
	TrafficResetAnchor    time.Time  `json:"traffic_reset_anchor"`
	TrafficResetCount     uint64     `json:"traffic_reset_count"`
	TrafficPrevCycleBytes uint64     `json:"traffic_prev_cycle_bytes"`
	NextTrafficReset      *time.Time `json:"next_traffic_reset,omitempty"`
	QuotaExceeded         bool       `json:"quota_exceeded"`

	// Creation-only credentials. ListClients always leaves both empty.
	SubscriptionToken  string `json:"subscription_token,omitempty"`
	RegistrationSecret string `json:"registration_secret,omitempty"`
}

type CreateClientRequest struct {
	Name              string   `json:"name"`
	Days              int      `json:"days"`
	IP                string   `json:"ip,omitempty"`
	TrafficLimitGB    float64  `json:"traffic_limit_gb,omitempty"`
	TrafficResetCycle string   `json:"traffic_reset_cycle,omitempty"`
	Note              string   `json:"note,omitempty"`
	CustomPolicies    []string `json:"custom_policies,omitempty"`
}

type SettingsView struct {
	PublicIP      string `json:"public_ip"`
	BindHost      string `json:"bind_host"`
	WebPort       int    `json:"web_port"`
	AdminUsername string `json:"admin_username"`
	// APIKey is returned only over the root-local control socket. It is omitted
	// by the public web/API settings views; the TUI uses it for the explicit
	// "view/rotate" workflow.
	APIKey             string `json:"api_key,omitempty"`
	AdminPasswordWeak  bool   `json:"admin_password_weak"`
	APIBind            string `json:"api_bind"`
	AdminPath          string `json:"admin_path"`
	SessionIdleMinutes int    `json:"session_idle_minutes"`
	TOTPEnabled        bool   `json:"totp_enabled"`
	LDAPEnabled        bool   `json:"ldap_enabled"`
	LDAPLoginMode      string `json:"ldap_login_mode"`
}

type RotateAPIKeyRequest struct {
	CurrentPassword string `json:"current_password"`
	TOTPCode        string `json:"totp_code,omitempty"`
}

type RotateAPIKeyResult struct {
	APIKey string `json:"api_key"`
}

type PanelPortRequest struct {
	Port int `json:"port"`
}

type ClearLockoutsRequest struct {
	IP string `json:"ip,omitempty"`
}

type ChangeAdminRequest struct {
	CurrentPassword string `json:"current_password"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	TOTPCode        string `json:"totp_code,omitempty"`
}

type ResetAdminRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
