package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"hyperdns/internal/httpx"
	"hyperdns/internal/service"
)

// The named custom policy group endpoints (v2.3). A group is an operator-defined
// bundle of domains with one action, toggled as a unit — the structured form of
// the flat Custom Proxied/Blocked/Direct lists.

type customGroupRequest struct {
	Name    string   `json:"name"`
	Action  string   `json:"action"`
	Domains []string `json:"domains"`
	Enabled bool     `json:"enabled"`
}

// handleCustomGroups is the collection endpoint: GET lists, POST creates.
func (ws *WebServer) handleCustomGroups(w http.ResponseWriter, r *http.Request) {
	if ws.customGroups == nil {
		httpx.WriteJSONError(w, http.StatusServiceUnavailable, "custom policy groups are unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		groups, err := ws.customGroups.List()
		if err != nil {
			httpx.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if groups == nil {
			groups = nil // marshals to [] via the wrapper below
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"groups": groups})
	case http.MethodPost:
		var req customGroupRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, "the request body could not be read as JSON")
			return
		}
		g, err := ws.customGroups.Create(req.Name, req.Action, req.Domains, req.Enabled)
		if err != nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(g)
	default:
		httpx.WriteMethodNotAllowed(w, "GET, POST")
	}
}

// handleCustomGroupByID is the item endpoint: PUT updates, DELETE removes.
func (ws *WebServer) handleCustomGroupByID(w http.ResponseWriter, r *http.Request) {
	if ws.customGroups == nil {
		httpx.WriteJSONError(w, http.StatusServiceUnavailable, "custom policy groups are unavailable")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/custom-groups/")
	id = strings.Trim(strings.TrimSpace(id), "/")
	if id == "" {
		httpx.WriteJSONError(w, http.StatusBadRequest, "missing group id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req customGroupRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, "the request body could not be read as JSON")
			return
		}
		g, err := ws.customGroups.Update(id, req.Name, req.Action, req.Domains, req.Enabled)
		if err != nil {
			ws.writeCustomGroupError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g)
	case http.MethodDelete:
		if err := ws.customGroups.Delete(id); err != nil {
			ws.writeCustomGroupError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	default:
		httpx.WriteMethodNotAllowed(w, "PUT, DELETE")
	}
}

// writeCustomGroupError maps a not-found sentinel to 404 and everything else to
// 400, so a bad id and a bad body are distinguishable to the dashboard.
func (ws *WebServer) writeCustomGroupError(w http.ResponseWriter, err error) {
	if errors.Is(err, service.ErrCustomGroupNotFound) {
		httpx.WriteJSONError(w, http.StatusNotFound, "no custom group with that id")
		return
	}
	httpx.WriteJSONError(w, http.StatusBadRequest, err.Error())
}
