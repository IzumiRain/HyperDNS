package control

import (
	"context"
	"math"
	"net"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

type statusSource interface {
	ControlStatus() (Status, error)
}

type clientSource interface {
	ControlListClients() ([]ClientView, error)
	ControlCreateClient(CreateClientRequest) (ClientView, error)
	ControlDeleteClient(string) error
}

type cacheSource interface {
	Flush()
}

type benchmarkSource interface {
	Start() bool
}

type presetUpdateSource interface {
	UpdatePresets(ctx context.Context) UpdatePresetsResult
}

type settingsSource interface {
	ControlSettings() SettingsView
	ControlRotateAPIKey(RotateAPIKeyRequest) (RotateAPIKeyResult, error)
	ControlPersistPanelPort(int) error
	ControlClearLockouts(ClearLockoutsRequest) (int, error)
	ControlChangeAdmin(ChangeAdminRequest) error
	ControlResetAdmin(ResetAdminRequest) error
}

// DaemonDependencies are daemon-owned live collaborators. They are injected so
// control never opens storage or creates a second copy of mutable state.
type DaemonDependencies struct {
	Status    statusSource
	Clients   clientSource
	Cache     cacheSource
	Benchmark benchmarkSource
	Settings  settingsSource
	Presets   presetUpdateSource
}

// DaemonOperations implements the management boundary over the daemon's shared
// collaborators.
type DaemonOperations struct {
	status    statusSource
	clients   clientSource
	cache     cacheSource
	benchmark benchmarkSource
	settings  settingsSource
	presets   presetUpdateSource
}

func NewDaemonOperations(deps DaemonDependencies) *DaemonOperations {
	return &DaemonOperations{
		status:    deps.Status,
		clients:   deps.Clients,
		cache:     deps.Cache,
		benchmark: deps.Benchmark,
		settings:  deps.Settings,
	}
}

func (o *DaemonOperations) Status(context.Context) (Status, error) {
	if o == nil || o.status == nil {
		return Status{}, NewError(500, "unavailable", "status is unavailable", nil)
	}
	return o.status.ControlStatus()
}

func (o *DaemonOperations) ListClients(context.Context) ([]ClientView, error) {
	if o == nil || o.clients == nil {
		return nil, NewError(500, "unavailable", "client management is unavailable", nil)
	}
	return o.clients.ControlListClients()
}

func (o *DaemonOperations) CreateClient(_ context.Context, req CreateClientRequest) (ClientView, error) {
	if err := validateCreateClient(req); err != nil {
		return ClientView{}, err
	}
	if o == nil || o.clients == nil {
		return ClientView{}, NewError(http.StatusInternalServerError, "unavailable", "client management is unavailable", nil)
	}
	return o.clients.ControlCreateClient(req)
}

func (o *DaemonOperations) DeleteClient(_ context.Context, id string) error {
	if !validClientID.MatchString(id) {
		return NewError(http.StatusBadRequest, "invalid_id", "client ID is invalid", nil)
	}
	if o == nil || o.clients == nil {
		return NewError(http.StatusInternalServerError, "unavailable", "client management is unavailable", nil)
	}
	return o.clients.ControlDeleteClient(id)
}

func (o *DaemonOperations) UpdatePresets(ctx context.Context) (UpdatePresetsResult, error) {
	if o == nil || o.presets == nil {
		return UpdatePresetsResult{}, NewError(http.StatusServiceUnavailable, "unavailable", "the preset-update channel is unavailable", nil)
	}
	return o.presets.UpdatePresets(ctx), nil
}

func (o *DaemonOperations) FlushCache(context.Context) error {
	if o == nil || o.cache == nil {
		return NewError(http.StatusServiceUnavailable, "unavailable", "cache is unavailable", nil)
	}
	o.cache.Flush()
	return nil
}

func (o *DaemonOperations) StartBenchmark(context.Context) error {
	if o == nil || o.benchmark == nil {
		return NewError(http.StatusServiceUnavailable, "unavailable", "benchmark is unavailable", nil)
	}
	if !o.benchmark.Start() {
		return NewError(http.StatusConflict, "benchmark_running", "benchmark is already running", nil)
	}
	return nil
}

func (o *DaemonOperations) Settings(context.Context) (SettingsView, error) {
	if o == nil || o.settings == nil {
		return SettingsView{}, NewError(http.StatusServiceUnavailable, "unavailable", "settings are unavailable", nil)
	}
	return o.settings.ControlSettings(), nil
}

func (o *DaemonOperations) RotateAPIKey(_ context.Context, req RotateAPIKeyRequest) (RotateAPIKeyResult, error) {
	if o == nil || o.settings == nil {
		return RotateAPIKeyResult{}, NewError(http.StatusServiceUnavailable, "unavailable", "settings are unavailable", nil)
	}
	return o.settings.ControlRotateAPIKey(req)
}

func (o *DaemonOperations) PersistPanelPort(_ context.Context, port int) error {
	if port < 1 || port > 65535 {
		return NewError(http.StatusBadRequest, "invalid_port", "panel port is invalid", nil)
	}
	if o == nil || o.settings == nil {
		return NewError(http.StatusServiceUnavailable, "unavailable", "settings are unavailable", nil)
	}
	return o.settings.ControlPersistPanelPort(port)
}

func (o *DaemonOperations) ClearLockouts(_ context.Context, req ClearLockoutsRequest) (int, error) {
	req.IP = strings.TrimSpace(req.IP)
	if req.IP != "" && net.ParseIP(req.IP) == nil {
		return 0, NewError(http.StatusBadRequest, "invalid_ip", "lockout IP is invalid", nil)
	}
	if o == nil || o.settings == nil {
		return 0, NewError(http.StatusServiceUnavailable, "unavailable", "lockout management is unavailable", nil)
	}
	return o.settings.ControlClearLockouts(req)
}

func (o *DaemonOperations) ChangeAdmin(_ context.Context, req ChangeAdminRequest) error {
	if o == nil || o.settings == nil {
		return NewError(http.StatusServiceUnavailable, "unavailable", "settings are unavailable", nil)
	}
	return o.settings.ControlChangeAdmin(req)
}

func (o *DaemonOperations) ResetAdmin(_ context.Context, req ResetAdminRequest) error {
	if o == nil || o.settings == nil {
		return NewError(http.StatusServiceUnavailable, "unavailable", "settings are unavailable", nil)
	}
	return o.settings.ControlResetAdmin(req)
}

var validClientID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func validateCreateClient(req CreateClientRequest) error {
	if req.Name == "" || strings.TrimSpace(req.Name) != req.Name || utf8.RuneCountInString(req.Name) > 128 {
		return NewError(http.StatusBadRequest, "invalid_request", "client name is invalid", nil)
	}
	if req.Days < 0 || req.Days > 36500 {
		return NewError(http.StatusBadRequest, "invalid_request", "client duration is invalid", nil)
	}
	if math.IsNaN(req.TrafficLimitGB) || math.IsInf(req.TrafficLimitGB, 0) || req.TrafficLimitGB < 0 {
		return NewError(http.StatusBadRequest, "invalid_request", "traffic limit is invalid", nil)
	}
	switch strings.ToLower(strings.TrimSpace(req.TrafficResetCycle)) {
	case "", "daily", "weekly", "monthly":
	default:
		return NewError(http.StatusBadRequest, "invalid_request", "traffic reset cycle is invalid", nil)
	}
	if req.IP != "" && (strings.TrimSpace(req.IP) != req.IP || net.ParseIP(req.IP) == nil) {
		return NewError(http.StatusBadRequest, "invalid_request", "client IP is invalid", nil)
	}
	if len(req.Note) > 4096 || len(req.CustomPolicies) > 256 {
		return NewError(http.StatusBadRequest, "invalid_request", "client request is invalid", nil)
	}
	return nil
}
