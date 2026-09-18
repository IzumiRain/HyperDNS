// API v2 (RFC-oriented contract), plus the v1 deprecation markers.
//
// v2 exists because v1's contract grew by accretion and no redesign could be
// done in place without breaking every deployed bot: create says `ip` and
// update says `allowed_ip`; the list is a bare array but the single is a bare
// object; errors are `{"error": "..."}`. The user chose the versioned
// transition, so v1 keeps its shape (with security fixes and a Deprecation
// header) while v2 is the contract new integrations are documented against.
//
// v2 rules, applied uniformly:
//   - errors are RFC 9457 application/problem+json;
//   - lists answer {items, next_cursor} with a bounded limit;
//   - one client DTO with symmetric field names (allowed_ips both ways);
//   - actions are POST /clients/{id}/actions/{action};
//   - unknown JSON fields are refused (a typo'd key must not be silently
//     dropped — v1 created lifetime accounts that way).
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"hyperdns/internal/core/matcher"
	"hyperdns/internal/httpx"
	"hyperdns/internal/service"
	"hyperdns/internal/version"
)

// v2LimitMax bounds list sizes; v2LimitDefault applies when the caller asks
// for nothing.
const (
	v2LimitMax     = 200
	v2LimitDefault = 50
)

// writeProblem answers with RFC 9457 application/problem+json. type is a
// short stable identifier (e.g. "invalid_request"); detail is the human
// sentence. Status is also in the body per the RFC, so a log reader never has
// to correlate two sources.
func writeProblem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":     "https://hyperdns.dev/problems/" + typ,
		"title":    http.StatusText(status),
		"status":   status,
		"detail":   detail,
		"instance": "/api/v2",
	})
}

// decodeStrict decodes a JSON body into dst, refusing unknown fields and any
// trailing data after the first JSON value. v1's decoder ignored unknown
// fields, which is how `{"expires_days": 30}` produced a lifetime account —
// the typo fell on the floor and nothing said so; the trailing-data check
// closes the frame boundary, where `{"a":1}{"b":2}` would otherwise be
// accepted on the first object and the second silently dropped.
func decodeStrict(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return false
	}
	if dec.More() {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "unexpected trailing data after the JSON object")
		return false
	}
	return true
}

// v2ClientDTO is the single client shape: create, read and update all speak
// it, and the field names match in both directions (v1's ip/allowed_ip split
// is the asymmetry this exists to end).
type v2ClientDTO struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"display_name"`
	Token           string   `json:"token"`
	AllowedIPs      []string `json:"allowed_ips"`
	ExpiresAt       string   `json:"expires_at,omitempty"` // RFC 3339 UTC; absent = lifetime
	QuotaLimitBytes float64  `json:"quota_limit_gb"`       // 0 = unlimited (unit kept for v1 parity)
	QuotaResetCycle string   `json:"quota_reset_cycle"`    // "", daily, weekly, monthly
	PolicyIDs       []string `json:"policy_ids"`
	Note            string   `json:"note,omitempty"`
	Enabled         bool     `json:"enabled"`
	// Admin-only credential surfaces, exactly as /api/clients v1 exposes them
	// (never on any public route; the portal's public view is a different,
	// smaller struct).
	RegisterSecret string `json:"register_secret,omitempty"`
}

// RegisterRoutesV2 attaches the /api/v2 endpoints.
func (a *API) RegisterRoutesV2(mux *http.ServeMux) {
	mux.HandleFunc("/api/v2/version", a.BindGate(a.handleV2Version))
	mux.HandleFunc("/api/v2/status", a.SecurityMiddleware(a.handleV2Status))
	mux.HandleFunc("/api/v2/clients", a.SecurityMiddleware(a.handleV2Clients))
	mux.HandleFunc("/api/v2/clients/", a.SecurityMiddleware(a.handleV2ClientItem))
	mux.HandleFunc("/api/v2/policies", a.SecurityMiddleware(a.handleV2Policies))
	mux.HandleFunc("/api/v2/cache/flush", a.SecurityMiddleware(a.handleV2FlushCache))
}

// DeprecateV1 wraps a v1 route handler with the deprecation markers. The
// Sunset date is the earliest v1 could be removed — one minor version of
// overlap, per the transition the user chose. Both the RFC 8594 Sunset header
// and the classic Deprecation header are set (the latter predates the I-D
// and is what most clients actually look at).
func (a *API) DeprecateV1(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Deprecation", "true")
		w.Header().Set("Sunset", "Wed, 01 Jul 2026 00:00:00 GMT")
		w.Header().Set("Link", `</api/v2/version>; rel="successor-version"`)
		next(w, r)
	}
}

func (a *API) handleV2Version(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": version.Get(),
		"api":     "v2",
	})
}

func (a *API) handleV2Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET or HEAD only")
		return
	}
	stats := a.stats.GetLiveStats()
	publicIP, apiBind := a.settings.Endpoint()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"version":   version.Get(),
		"telemetry": stats,
		"public_ip": publicIP,
		"api_bind":  apiBind,
	})
}

// handleV2Clients: GET lists with cursor pagination, POST creates.
func (a *API) handleV2Clients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		clients, err := a.clients.ListClientViews()
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		limit := v2LimitDefault
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 {
				writeProblem(w, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
				return
			}
			if n > v2LimitMax {
				writeProblem(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("limit must be at most %d", v2LimitMax))
				return
			}
			limit = n
		}
		cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
		start := 0
		if cursor != "" {
			n, err := strconv.Atoi(cursor)
			if err != nil || n < 0 {
				writeProblem(w, http.StatusBadRequest, "invalid_request", "cursor is not valid")
				return
			}
			start = n
		}
		if start > len(clients) {
			start = len(clients)
		}
		end := start + limit
		if end > len(clients) {
			end = len(clients)
		}
		page := clients[start:end]
		items := make([]v2ClientDTO, 0, len(page))
		for _, c := range page {
			items = append(items, v2ViewToDTO(c))
		}
		var next string
		if end < len(clients) {
			next = strconv.Itoa(end)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":       items,
			"next_cursor": next, // absent (empty) on the last page
		})

	case http.MethodPost:
		var req struct {
			DisplayName     string   `json:"display_name"`
			ValidityDays    int      `json:"validity_days"`
			AllowedIPs      []string `json:"allowed_ips"`
			QuotaLimitGB    float64  `json:"quota_limit_gb"`
			QuotaResetCycle string   `json:"quota_reset_cycle"`
			PolicyIDs       []string `json:"policy_ids"`
			Note            string   `json:"note"`
		}
		if !decodeStrict(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.DisplayName) == "" {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "display_name is required")
			return
		}
		client, err := a.clients.ProvisionClient(service.CreateClientRequest{
			Name: req.DisplayName,
			Days: req.ValidityDays,
			// v1 accepted one `ip`; v2 takes the plural list and uses the first,
			// because the storage model is still 1-IP-bound per account and a
			// silent multi-IP create would be a lie.
			IP:                firstNonEmpty(req.AllowedIPs),
			TrafficLimitGB:    req.QuotaLimitGB,
			TrafficResetCycle: req.QuotaResetCycle,
			Note:              req.Note,
			CustomPolicies:    req.PolicyIDs,
		})
		if err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		w.Header().Set("Location", "/api/v2/clients/"+client.ID)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(v2ViewToDTO(a.clients.ViewClient(client)))

	default:
		writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET, HEAD or POST")
	}
}

// handleV2ClientItem: one client, actions under /actions/{name}.
func (a *API) handleV2ClientItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/clients/")
	rest = strings.TrimSpace(strings.TrimSuffix(rest, "/"))

	if clientID, action, ok := strings.Cut(rest, "/actions/"); ok {
		if r.Method != http.MethodPost {
			writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
			return
		}
		a.v2ClientAction(w, clientID, action)
		return
	}

	id := rest
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		client, err := a.clients.GetClient(id)
		if err != nil {
			writeProblem(w, http.StatusNotFound, "not_found", "no client with that id")
			return
		}
		_ = json.NewEncoder(w).Encode(v2ViewToDTO(a.clients.ViewClient(client)))

	case http.MethodPatch:
		var req v2PatchRequest
		if !decodeStrict(w, r, &req) {
			return
		}
		updated, err := a.clients.UpdateClient(id, req.toService())
		if err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(v2ViewToDTO(a.clients.ViewClient(updated)))

	case http.MethodDelete:
		if err := a.clients.DeleteClient(id); err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET, HEAD, PATCH or DELETE")
	}
}

// v2PatchRequest carries only the fields a PATCH may change; every pointer is
// nil-when-absent so "not sent" and "sent empty" stay distinguishable — the
// difference between leaving a note alone and clearing it.
type v2PatchRequest struct {
	DisplayName     *string   `json:"display_name"`
	AllowedIPs      *[]string `json:"allowed_ips"`
	QuotaLimitGB    *float64  `json:"quota_limit_gb"`
	QuotaResetCycle *string   `json:"quota_reset_cycle"`
	Note            *string   `json:"note"`
	Enabled         *bool     `json:"enabled"`
	ValidityDaysAdd *int      `json:"validity_days_add"`
}

func (p v2PatchRequest) toService() service.UpdateClientRequest {
	req := service.UpdateClientRequest{}
	if p.DisplayName != nil {
		req.Name = p.DisplayName
	}
	if p.AllowedIPs != nil && len(*p.AllowedIPs) > 0 {
		req.AllowedIP = &(*p.AllowedIPs)[0:1][0]
	}
	if p.QuotaLimitGB != nil {
		req.TrafficLimitGB = p.QuotaLimitGB
	}
	if p.QuotaResetCycle != nil {
		req.TrafficResetCycle = p.QuotaResetCycle
	}
	if p.Note != nil {
		req.Note = p.Note
	}
	if p.Enabled != nil {
		req.Enabled = p.Enabled
	}
	if p.ValidityDaysAdd != nil {
		req.DaysToAdd = p.ValidityDaysAdd
	}
	return req
}

func (a *API) v2ClientAction(w http.ResponseWriter, clientID, action string) {
	switch action {
	case "reset-traffic":
		if err := a.clients.ResetClientTraffic(clientID); err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"reset": true})
	case "regenerate-uuid":
		newUUID, err := a.clients.RegenerateUUID(clientID)
		if err != nil {
			httpx.WriteClientError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"uuid": newUUID})
	default:
		writeProblem(w, http.StatusNotFound, "unknown_action", "actions are reset-traffic and regenerate-uuid")
	}
}

func (a *API) handleV2Policies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		policies, err := a.db.ListPolicies()
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":   policies,
			"catalog": matcher.PolicyCatalog(),
		})
	default:
		writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET or HEAD")
	}
}

func (a *API) handleV2FlushCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	a.cache.Flush()
	_ = json.NewEncoder(w).Encode(map[string]bool{"flushed": true})
}

// v2ViewToDTO converts the service view into the v2 wire shape.
func v2ViewToDTO(c service.ClientView) v2ClientDTO {
	dto := v2ClientDTO{
		ID:              c.ID,
		DisplayName:     c.Name,
		Token:           c.Token,
		AllowedIPs:      c.AllowedIPs,
		QuotaLimitBytes: c.TrafficLimitGB,
		QuotaResetCycle: c.TrafficResetCycle,
		PolicyIDs:       c.CustomPolicies,
		Note:            c.Note,
		Enabled:         c.Enabled,
		RegisterSecret:  c.RegisterSecret,
	}
	if !c.ExpiresAt.IsZero() {
		dto.ExpiresAt = c.ExpiresAt.UTC().Format(timeFormatRFC3339)
	}
	return dto
}

const timeFormatRFC3339 = "2006-01-02T15:04:05Z07:00"

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
