package control

import (
	"context"
	"errors"
	"testing"
)

type statusSourceStub struct {
	value Status
	err   error
}

func (s statusSourceStub) ControlStatus() (Status, error) { return s.value, s.err }

func TestDaemonOperationsStatusAdaptsLiveSource(t *testing.T) {
	want := Status{
		TotalQueries: 41,
		QPS:          3.5,
		ActiveRelays: 2,
		CacheItems:   7,
		CacheHits:    19,
		CacheMisses:  5,
		UptimeSec:    63,
	}
	ops := NewDaemonOperations(DaemonDependencies{Status: statusSourceStub{value: want}})

	got, err := ops.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got != want {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
}

func TestDaemonOperationsStatusPropagatesSourceFailure(t *testing.T) {
	want := errors.New("stats unavailable")
	ops := NewDaemonOperations(DaemonDependencies{Status: statusSourceStub{err: want}})

	if _, err := ops.Status(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Status error = %v, want %v", err, want)
	}
}

type clientSourceStub struct {
	listed      []ClientView
	created     ClientView
	deleted     string
	createCalls int
}

func (s *clientSourceStub) ControlListClients() ([]ClientView, error) {
	return s.listed, nil
}
func (s *clientSourceStub) ControlCreateClient(CreateClientRequest) (ClientView, error) {
	s.createCalls++
	return s.created, nil
}
func (s *clientSourceStub) ControlDeleteClient(id string) error {
	s.deleted = id
	return nil
}

func TestDaemonOperationsClientBoundary(t *testing.T) {
	listed := ClientView{ID: "listed", Name: "safe"}
	created := ClientView{
		ID:                 "created",
		SubscriptionToken:  "one-time-token",
		RegistrationSecret: "one-time-secret",
	}
	source := &clientSourceStub{listed: []ClientView{listed}, created: created}
	ops := NewDaemonOperations(DaemonDependencies{Clients: source})

	gotList, err := ops.ListClients(context.Background())
	if err != nil || len(gotList) != 1 || gotList[0].ID != listed.ID || gotList[0].Name != listed.Name {
		t.Fatalf("ListClients = %+v, %v", gotList, err)
	}
	gotCreated, err := ops.CreateClient(context.Background(), CreateClientRequest{Name: "Subscriber", Days: 30})
	if err != nil || gotCreated.ID != created.ID || gotCreated.SubscriptionToken != created.SubscriptionToken || gotCreated.RegistrationSecret != created.RegistrationSecret {
		t.Fatalf("CreateClient = %+v, %v", gotCreated, err)
	}

	// Zero days is the documented lifetime account. ClientService stores it with a
	// zero ExpiresAt, so the control boundary must not reject what the TUI offers.
	if _, err := ops.CreateClient(context.Background(), CreateClientRequest{Name: "Lifetime Subscriber", Days: 0}); err != nil {
		t.Fatalf("CreateClient lifetime account: %v", err)
	}
	if err := ops.DeleteClient(context.Background(), "client-1"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if source.deleted != "client-1" {
		t.Fatalf("deleted ID = %q", source.deleted)
	}
}

func TestDaemonOperationsRejectsInvalidClientRequestsBeforeMutation(t *testing.T) {
	tests := []struct {
		name string
		req  CreateClientRequest
	}{
		{"empty name", CreateClientRequest{Name: "", Days: 1}},
		{"surrounding whitespace", CreateClientRequest{Name: " subscriber ", Days: 1}},
		{"negative days", CreateClientRequest{Name: "subscriber", Days: -1}},
		{"excessive days", CreateClientRequest{Name: "subscriber", Days: 36501}},
		{"negative quota", CreateClientRequest{Name: "subscriber", Days: 1, TrafficLimitGB: -1}},
		{"invalid cycle", CreateClientRequest{Name: "subscriber", Days: 1, TrafficResetCycle: "yearly"}},
		{"invalid ip", CreateClientRequest{Name: "subscriber", Days: 1, IP: "not-an-ip"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &clientSourceStub{}
			ops := NewDaemonOperations(DaemonDependencies{Clients: source})
			_, err := ops.CreateClient(context.Background(), tt.req)
			opErr, ok := asError(err)
			if !ok || opErr.Code != "invalid_request" {
				t.Fatalf("error = %T %v, want invalid_request", err, err)
			}
			if source.createCalls != 0 {
				t.Fatal("invalid request reached mutation source")
			}
		})
	}
}

func TestDaemonOperationsRejectsInvalidClientIDBeforeMutation(t *testing.T) {
	for _, id := range []string{"", "../server", "client/other", " client-1", "client?secret"} {
		t.Run(id, func(t *testing.T) {
			source := &clientSourceStub{}
			ops := NewDaemonOperations(DaemonDependencies{Clients: source})
			err := ops.DeleteClient(context.Background(), id)
			opErr, ok := asError(err)
			if !ok || opErr.Code != "invalid_id" {
				t.Fatalf("error = %T %v, want invalid_id", err, err)
			}
			if source.deleted != "" {
				t.Fatalf("invalid ID reached mutation source: %q", source.deleted)
			}
		})
	}
}

type cacheStub struct{ flushes int }

func (s *cacheStub) Flush() { s.flushes++ }

type benchmarkStub struct{ calls int }

func (s *benchmarkStub) Start() bool {
	s.calls++
	return s.calls == 1
}

func TestDaemonOperationsFlushesSharedCache(t *testing.T) {
	cache := &cacheStub{}
	ops := NewDaemonOperations(DaemonDependencies{Cache: cache})
	if err := ops.FlushCache(context.Background()); err != nil {
		t.Fatalf("FlushCache: %v", err)
	}
	if cache.flushes != 1 {
		t.Fatalf("flushes = %d, want 1", cache.flushes)
	}
}

func TestDaemonOperationsUsesSharedBenchmarkGate(t *testing.T) {
	benchmark := &benchmarkStub{}
	ops := NewDaemonOperations(DaemonDependencies{Benchmark: benchmark})
	if err := ops.StartBenchmark(context.Background()); err != nil {
		t.Fatalf("first StartBenchmark: %v", err)
	}
	err := ops.StartBenchmark(context.Background())
	opErr, ok := asError(err)
	if !ok || opErr.Code != "benchmark_running" {
		t.Fatalf("second error = %T %v, want benchmark_running", err, err)
	}
	if benchmark.calls != 2 {
		t.Fatalf("benchmark calls = %d, want 2", benchmark.calls)
	}
}

type settingsSourceStub struct {
	view       SettingsView
	rotated    RotateAPIKeyResult
	rotateReq  RotateAPIKeyRequest
	port       int
	clearReq   ClearLockoutsRequest
	cleared    int
	changeReq  ChangeAdminRequest
	resetReq   ResetAdminRequest
	portCalls  int
	clearCalls int
}

func (s *settingsSourceStub) ControlSettings() SettingsView { return s.view }
func (s *settingsSourceStub) ControlRotateAPIKey(req RotateAPIKeyRequest) (RotateAPIKeyResult, error) {
	s.rotateReq = req
	return s.rotated, nil
}
func (s *settingsSourceStub) ControlPersistPanelPort(port int) error {
	s.portCalls++
	s.port = port
	return nil
}
func (s *settingsSourceStub) ControlClearLockouts(req ClearLockoutsRequest) (int, error) {
	s.clearCalls++
	s.clearReq = req
	return s.cleared, nil
}
func (s *settingsSourceStub) ControlChangeAdmin(req ChangeAdminRequest) error {
	s.changeReq = req
	return nil
}
func (s *settingsSourceStub) ControlResetAdmin(req ResetAdminRequest) error {
	s.resetReq = req
	return nil
}

func TestDaemonOperationsSettingsBoundary(t *testing.T) {
	source := &settingsSourceStub{
		view:    SettingsView{PublicIP: "203.0.113.8", AdminUsername: "admin", TOTPEnabled: true},
		rotated: RotateAPIKeyResult{APIKey: "hdns_live_new"},
		cleared: 3,
	}
	ops := NewDaemonOperations(DaemonDependencies{Settings: source})

	if got, err := ops.Settings(context.Background()); err != nil || got != source.view {
		t.Fatalf("Settings = %+v, %v", got, err)
	}
	rotateReq := RotateAPIKeyRequest{CurrentPassword: "current-secret", TOTPCode: "123456"}
	if got, err := ops.RotateAPIKey(context.Background(), rotateReq); err != nil || got != source.rotated {
		t.Fatalf("RotateAPIKey = %+v, %v", got, err)
	}
	if err := ops.PersistPanelPort(context.Background(), 9443); err != nil || source.port != 9443 {
		t.Fatalf("PersistPanelPort: %v, port=%d", err, source.port)
	}
	if got, err := ops.ClearLockouts(context.Background(), ClearLockoutsRequest{IP: "203.0.113.9"}); err != nil || got != 3 {
		t.Fatalf("ClearLockouts = %d, %v", got, err)
	}
	changeReq := ChangeAdminRequest{CurrentPassword: "old", Username: "new-admin", Password: "new-password"}
	if err := ops.ChangeAdmin(context.Background(), changeReq); err != nil || source.changeReq != changeReq {
		t.Fatalf("ChangeAdmin: %v", err)
	}
	resetReq := ResetAdminRequest{Username: "recovered", Password: "replacement-password"}
	if err := ops.ResetAdmin(context.Background(), resetReq); err != nil || source.resetReq != resetReq {
		t.Fatalf("ResetAdmin: %v", err)
	}
}

func TestDaemonOperationsRejectsInvalidPanelPortAndLockoutIP(t *testing.T) {
	source := &settingsSourceStub{}
	ops := NewDaemonOperations(DaemonDependencies{Settings: source})
	for _, port := range []int{-1, 0, 65536} {
		err := ops.PersistPanelPort(context.Background(), port)
		opErr, ok := asError(err)
		if !ok || opErr.Code != "invalid_port" {
			t.Fatalf("port %d error = %T %v", port, err, err)
		}
	}
	if source.portCalls != 0 {
		t.Fatalf("invalid port reached persistence %d times", source.portCalls)
	}
	_, err := ops.ClearLockouts(context.Background(), ClearLockoutsRequest{IP: "not-an-ip"})
	opErr, ok := asError(err)
	if !ok || opErr.Code != "invalid_ip" {
		t.Fatalf("lockout error = %T %v", err, err)
	}
	if source.clearCalls != 0 {
		t.Fatal("invalid IP reached lockout mutation")
	}
}
