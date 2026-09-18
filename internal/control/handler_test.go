package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type operationsStub struct {
	status Status
	calls  []string
	id     string
	err    error
}

func (s *operationsStub) Status(context.Context) (Status, error) {
	s.calls = append(s.calls, "status")
	return s.status, s.err
}
func (s *operationsStub) ListClients(context.Context) ([]ClientView, error) {
	s.calls = append(s.calls, "list-clients")
	return nil, nil
}
func (s *operationsStub) CreateClient(context.Context, CreateClientRequest) (ClientView, error) {
	s.calls = append(s.calls, "create-client")
	return ClientView{}, nil
}
func (s *operationsStub) DeleteClient(_ context.Context, id string) error {
	s.calls = append(s.calls, "delete-client")
	s.id = id
	return nil
}
func (s *operationsStub) FlushCache(context.Context) error {
	s.calls = append(s.calls, "flush-cache")
	return nil
}
func (s *operationsStub) StartBenchmark(context.Context) error {
	s.calls = append(s.calls, "benchmark")
	return nil
}
func (s *operationsStub) Settings(context.Context) (SettingsView, error) {
	s.calls = append(s.calls, "settings")
	return SettingsView{}, nil
}
func (s *operationsStub) RotateAPIKey(context.Context, RotateAPIKeyRequest) (RotateAPIKeyResult, error) {
	s.calls = append(s.calls, "rotate-api-key")
	return RotateAPIKeyResult{}, nil
}
func (s *operationsStub) PersistPanelPort(context.Context, int) error {
	s.calls = append(s.calls, "panel-port")
	return nil
}
func (s *operationsStub) ClearLockouts(context.Context, ClearLockoutsRequest) (int, error) {
	s.calls = append(s.calls, "clear-lockouts")
	return 0, nil
}
func (s *operationsStub) ChangeAdmin(context.Context, ChangeAdminRequest) error {
	s.calls = append(s.calls, "change-admin")
	return nil
}
func (s *operationsStub) ResetAdmin(context.Context, ResetAdminRequest) error {
	s.calls = append(s.calls, "reset-admin")
	return nil
}

func TestHandlerRouteContract(t *testing.T) {
	tests := []struct {
		name, method, path, body, call string
		wantStatus                     int
		wantID                         string
	}{
		{"status", http.MethodGet, "/v1/status", "", "status", http.StatusOK, ""},
		{"list clients", http.MethodGet, "/v1/clients", "", "list-clients", http.StatusOK, ""},
		{"create client", http.MethodPost, "/v1/clients", `{"name":"Alice","days":30}`, "create-client", http.StatusCreated, ""},
		{"delete client", http.MethodDelete, "/v1/clients/client-1", "", "delete-client", http.StatusNoContent, "client-1"},
		{"flush cache", http.MethodPost, "/v1/cache/flush", `{}`, "flush-cache", http.StatusNoContent, ""},
		{"benchmark", http.MethodPost, "/v1/benchmark", `{}`, "benchmark", http.StatusAccepted, ""},
		{"settings", http.MethodGet, "/v1/settings", "", "settings", http.StatusOK, ""},
		{"rotate key", http.MethodPost, "/v1/api-key/rotate", `{"current_password":"pw"}`, "rotate-api-key", http.StatusOK, ""},
		{"panel port", http.MethodPut, "/v1/settings/panel-port", `{"port":9443}`, "panel-port", http.StatusNoContent, ""},
		{"clear lockouts", http.MethodPost, "/v1/lockouts/clear", `{}`, "clear-lockouts", http.StatusOK, ""},
		{"change admin", http.MethodPut, "/v1/admin/change", `{"current_password":"pw","username":"root"}`, "change-admin", http.StatusNoContent, ""},
		{"reset admin", http.MethodPost, "/v1/admin/reset", `{"username":"root","password":"Long-passphrase-7"}`, "reset-admin", http.StatusNoContent, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &operationsStub{}
			h := NewHandler(ops)
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set(ProtocolVersionHeader, ProtocolVersion)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Fatalf("%s %s = %d, want %d; body=%s", tt.method, tt.path, w.Code, tt.wantStatus, w.Body.String())
			}
			if !reflect.DeepEqual(ops.calls, []string{tt.call}) {
				t.Fatalf("calls = %v, want [%s]", ops.calls, tt.call)
			}
			if ops.id != tt.wantID {
				t.Fatalf("id = %q, want %q", ops.id, tt.wantID)
			}
		})
	}
}

func TestHandlerStatusRoute(t *testing.T) {
	h := NewHandler(&operationsStub{status: Status{TotalQueries: 41, CacheItems: 7}})
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set(ProtocolVersionHeader, ProtocolVersion)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /v1/status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got Status
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.TotalQueries != 41 || got.CacheItems != 7 {
		t.Fatalf("status = %+v, want total_queries=41 cache_items=7", got)
	}
}

func TestHandlerProtocolAndRouteErrors(t *testing.T) {
	tests := []struct {
		name, method, path, version, code string
		wantStatus                        int
		wantAllow                         bool
	}{
		{"missing version", http.MethodGet, "/v1/status", "", "version_mismatch", http.StatusBadRequest, false},
		{"wrong version", http.MethodGet, "/v1/status", "v2", "version_mismatch", http.StatusBadRequest, false},
		{"unknown route", http.MethodGet, "/v1/no-such-route", ProtocolVersion, "not_found", http.StatusNotFound, false},
		{"wrong method", http.MethodPatch, "/v1/status", ProtocolVersion, "method_not_allowed", http.StatusMethodNotAllowed, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &operationsStub{}
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.version != "" {
				req.Header.Set(ProtocolVersionHeader, tt.version)
			}
			w := httptest.NewRecorder()
			NewHandler(ops).ServeHTTP(w, req)
			assertProtocolError(t, w, tt.wantStatus, tt.code)
			if tt.wantAllow && !strings.Contains(w.Header().Get("Allow"), http.MethodGet) {
				t.Fatalf("Allow = %q, want GET", w.Header().Get("Allow"))
			}
			if len(ops.calls) != 0 {
				t.Fatalf("calls = %v, want none", ops.calls)
			}
		})
	}
}

func TestHandlerRejectsInvalidBodiesBeforeOperations(t *testing.T) {
	tests := []struct {
		name, body, code string
		wantStatus       int
	}{
		{"empty", "", "invalid_json", http.StatusBadRequest},
		{"malformed", `{"name":`, "invalid_json", http.StatusBadRequest},
		{"unknown field", `{"name":"Alice","days":30,"password":"do-not-echo"}`, "invalid_json", http.StatusBadRequest},
		{"trailing value", `{"name":"Alice","days":30} {}`, "invalid_json", http.StatusBadRequest},
		{"oversized", `{"name":"` + strings.Repeat("x", maxRequestBody) + `","days":30}`, "body_too_large", http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &operationsStub{}
			req := httptest.NewRequest(http.MethodPost, "/v1/clients", strings.NewReader(tt.body))
			req.Header.Set(ProtocolVersionHeader, ProtocolVersion)
			w := httptest.NewRecorder()
			NewHandler(ops).ServeHTTP(w, req)
			assertProtocolError(t, w, tt.wantStatus, tt.code)
			if len(ops.calls) != 0 {
				t.Fatalf("calls = %v, want none", ops.calls)
			}
			if strings.Contains(w.Body.String(), "do-not-echo") {
				t.Fatalf("response echoed request secret: %q", w.Body.String())
			}
		})
	}
}

func TestHandlerDoesNotMountPublicSurfaces(t *testing.T) {
	paths := []string{"/", "/index.html", "/login", "/dns-query", "/sub/client", "/api/status", "/static/app.js"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			ops := &operationsStub{}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(ProtocolVersionHeader, ProtocolVersion)
			w := httptest.NewRecorder()
			NewHandler(ops).ServeHTTP(w, req)
			assertProtocolError(t, w, http.StatusNotFound, "not_found")
			if len(ops.calls) != 0 {
				t.Fatalf("calls = %v, want none", ops.calls)
			}
		})
	}
}

func TestHandlerOperationErrorMappingDoesNotLeakSecrets(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"coded validation", NewError(http.StatusUnprocessableEntity, "invalid_request", "request is invalid", errors.New("password=do-not-echo")), http.StatusUnprocessableEntity, "invalid_request"},
		{"uncoded internal", errors.New("api_key=do-not-echo"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &operationsStub{err: tt.err}
			req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
			req.Header.Set(ProtocolVersionHeader, ProtocolVersion)
			w := httptest.NewRecorder()
			NewHandler(ops).ServeHTTP(w, req)
			assertProtocolError(t, w, tt.wantStatus, tt.wantCode)
			if strings.Contains(w.Body.String(), "do-not-echo") {
				t.Fatalf("response leaked operation error: %q", w.Body.String())
			}
		})
	}
}

func assertProtocolError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, status, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var payload ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v; body=%q", err, w.Body.String())
	}
	if payload.Error.Code != code {
		t.Fatalf("error code = %q, want %q", payload.Error.Code, code)
	}
}
