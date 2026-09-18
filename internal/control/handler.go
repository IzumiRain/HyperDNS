package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxRequestBody = 64 << 10

// NewHandler builds the private control mux. Routes must be added explicitly;
// no dashboard, static, DNS, DoH, subscriber, or public API handler is mounted.
func NewHandler(ops Operations) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", versioned(func(w http.ResponseWriter, r *http.Request) {
		value, err := ops.Status(r.Context())
		respond(w, http.StatusOK, value, err)
	}))
	mux.HandleFunc("GET /v1/clients", versioned(func(w http.ResponseWriter, r *http.Request) {
		value, err := ops.ListClients(r.Context())
		respond(w, http.StatusOK, value, err)
	}))
	mux.HandleFunc("POST /v1/clients", versioned(func(w http.ResponseWriter, r *http.Request) {
		var req CreateClientRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		value, err := ops.CreateClient(r.Context(), req)
		respond(w, http.StatusCreated, value, err)
	}))
	mux.HandleFunc("DELETE /v1/clients/{id}", versioned(func(w http.ResponseWriter, r *http.Request) {
		err := ops.DeleteClient(r.Context(), r.PathValue("id"))
		respond(w, http.StatusNoContent, nil, err)
	}))
	mux.HandleFunc("POST /v1/cache/flush", versioned(func(w http.ResponseWriter, r *http.Request) {
		if !decodeEmptyRequest(w, r) {
			return
		}
		respond(w, http.StatusNoContent, nil, ops.FlushCache(r.Context()))
	}))
	mux.HandleFunc("POST /v1/benchmark", versioned(func(w http.ResponseWriter, r *http.Request) {
		if !decodeEmptyRequest(w, r) {
			return
		}
		respond(w, http.StatusAccepted, nil, ops.StartBenchmark(r.Context()))
	}))
	mux.HandleFunc("GET /v1/settings", versioned(func(w http.ResponseWriter, r *http.Request) {
		value, err := ops.Settings(r.Context())
		respond(w, http.StatusOK, value, err)
	}))
	mux.HandleFunc("POST /v1/api-key/rotate", versioned(func(w http.ResponseWriter, r *http.Request) {
		var req RotateAPIKeyRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		value, err := ops.RotateAPIKey(r.Context(), req)
		respond(w, http.StatusOK, value, err)
	}))
	mux.HandleFunc("PUT /v1/settings/panel-port", versioned(func(w http.ResponseWriter, r *http.Request) {
		var req PanelPortRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		respond(w, http.StatusNoContent, nil, ops.PersistPanelPort(r.Context(), req.Port))
	}))
	mux.HandleFunc("POST /v1/lockouts/clear", versioned(func(w http.ResponseWriter, r *http.Request) {
		var req ClearLockoutsRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		count, err := ops.ClearLockouts(r.Context(), req)
		respond(w, http.StatusOK, struct {
			Cleared int `json:"cleared"`
		}{count}, err)
	}))
	mux.HandleFunc("PUT /v1/admin/change", versioned(func(w http.ResponseWriter, r *http.Request) {
		var req ChangeAdminRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		respond(w, http.StatusNoContent, nil, ops.ChangeAdmin(r.Context(), req))
	}))
	mux.HandleFunc("POST /v1/admin/reset", versioned(func(w http.ResponseWriter, r *http.Request) {
		var req ResetAdminRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		respond(w, http.StatusNoContent, nil, ops.ResetAdmin(r.Context(), req))
	}))
	return typedNotFoundAndMethod(mux)
}

func versioned(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireVersion(w, r) {
			next(w, r)
		}
	}
}

func requireVersion(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get(ProtocolVersionHeader) != ProtocolVersion {
		writeError(w, http.StatusBadRequest, "version_mismatch", "unsupported control protocol version")
		return false
	}
	return true
}

func decodeEmptyRequest(w http.ResponseWriter, r *http.Request) bool {
	var body struct{}
	return decodeRequest(w, r, &body)
}

func decodeRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds limit")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is not valid JSON")
		}
		return false
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain one JSON value")
		return false
	} else if !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body is not valid JSON")
		return false
	}
	return true
}

func respond(w http.ResponseWriter, status int, value any, err error) {
	if err != nil {
		writeOperationError(w, err)
		return
	}
	if status == http.StatusNoContent {
		w.Header().Set(ProtocolVersionHeader, ProtocolVersion)
		w.WriteHeader(status)
		return
	}
	if value == nil {
		value = struct{}{}
	}
	writeJSON(w, status, value)
}

func typedNotFoundAndMethod(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pattern := r.Method + " " + r.URL.Path
		_, matched := mux.Handler(r)
		if matched == "" {
			// Ask ServeMux whether the path exists under another method. It sets Allow
			// and returns 405 without invoking an operation.
			rec := httptestResponse{header: make(http.Header)}
			mux.ServeHTTP(&rec, r)
			if rec.status == http.StatusMethodNotAllowed {
				w.Header().Set("Allow", rec.header.Get("Allow"))
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
				return
			}
			_ = pattern
			writeError(w, http.StatusNotFound, "not_found", "control route not found")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type httptestResponse struct {
	header http.Header
	status int
}

func (w *httptestResponse) Header() http.Header { return w.header }
func (w *httptestResponse) WriteHeader(status int) {
	w.status = status
}
func (w *httptestResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(p), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ProtocolVersionHeader, ProtocolVersion)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeOperationError(w http.ResponseWriter, err error) {
	if opErr, ok := asError(err); ok {
		writeError(w, opErr.Status, opErr.Code, opErr.Message)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal_error", "control operation failed")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{Error: ProtocolError{Code: code, Message: message}})
}

type ErrorResponse struct {
	Error ProtocolError `json:"error"`
}

type ProtocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
