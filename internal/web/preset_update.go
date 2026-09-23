package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"hyperdns/internal/httpx"
	"hyperdns/internal/presetupd"
)

// The preset-update channel endpoints (v2.3.0). All are operator-facing: the
// dashboard's Policy Presets card drives Check/Apply/Rollback, and the status
// view shows what the channel has done.

// handlePresetUpdateStatus answers GET /api/presets/update with the channel
// state: base URL, current versions, whether an override is active, and the
// auto-apply toggle.
func (ws *WebServer) handlePresetUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if ws.presetUpdater == nil {
		httpx.WriteJSONError(w, http.StatusServiceUnavailable, "the preset-update channel is unavailable")
		return
	}
	if r.Method != http.MethodGet {
		httpx.WriteMethodNotAllowed(w, "GET")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ws.presetUpdater.Status())
}

// handlePresetUpdateCheck answers POST /api/presets/update/check with the diff
// the channel would apply: one row per policy whose channel version is ahead.
func (ws *WebServer) handlePresetUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if ws.presetUpdater == nil {
		httpx.WriteJSONError(w, http.StatusServiceUnavailable, "the preset-update channel is unavailable")
		return
	}
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	// The channel is another origin; never let a dashboard click hang the
	// resolver thread longer than the updater's own client timeout does.
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	diff, err := ws.presetUpdater.Check(ctx)
	if err != nil {
		httpx.WriteJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if diff == nil {
		diff = []presetupd.DiffEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"up_to_date": len(diff) == 0, "updates": diff})
}

// handlePresetUpdateApply answers POST /api/presets/update/apply. It downloads,
// verifies, swaps, health-checks and persists in one call; any failure rolls
// the matcher straight back and reports why.
func (ws *WebServer) handlePresetUpdateApply(w http.ResponseWriter, r *http.Request) {
	if ws.presetUpdater == nil {
		httpx.WriteJSONError(w, http.StatusServiceUnavailable, "the preset-update channel is unavailable")
		return
	}
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	res, err := ws.presetUpdater.Apply(ctx)
	if err != nil {
		httpx.WriteJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// handlePresetUpdateRollback answers POST /api/presets/update/rollback with the
// previous applied set (or the embedded baseline if the current override was the
// first).
func (ws *WebServer) handlePresetUpdateRollback(w http.ResponseWriter, r *http.Request) {
	if ws.presetUpdater == nil {
		httpx.WriteJSONError(w, http.StatusServiceUnavailable, "the preset-update channel is unavailable")
		return
	}
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	if err := ws.presetUpdater.Rollback(); err != nil {
		httpx.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}
