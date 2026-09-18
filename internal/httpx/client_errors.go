package httpx

import (
	"errors"
	"net/http"

	"hyperdns/internal/database"
	"hyperdns/internal/service"
)

// This file is the one place in httpx that knows anything about the domain, and it
// is separate from respond.go so the coupling is visible and cheap to undo. The
// alternative was a copy of the same switch in internal/web and another in
// internal/api, which is exactly the drift this package exists to prevent: the two
// front-ends serve the same subscriber records to the same dashboard, and a create
// that answers 400 through one route and 500 through the other is a bug report
// waiting to happen. The import direction is safe — service imports database and
// crypto, and neither imports httpx.

// ClientErrorStatus maps a client-service failure onto the status a caller should
// actually see.
//
// Both front-ends used to answer 500 for anything the service returned, which is
// wrong in both directions. A mistyped address is not a server fault, and the
// dashboard renders a 500 as "the server failed" — so an operator who pasted
// "203.0.113.999" was told the daemon was broken instead of being told to look at
// what they typed. In the other direction a 500 is what an operator escalates: it
// buys a VPS login and a log trawl for a typo.
//
// The sentinels below are the only failures the service layer distinguishes, so
// anything else stays a 500 rather than being guessed at.
func ClientErrorStatus(err error) int {
	switch {
	case errors.Is(err, service.ErrInvalidIP):
		return http.StatusBadRequest
	// A cycle name this daemon does not implement is the same class of mistake as a
	// mistyped address: the operator's, and fixable by them. Answering 500 would send
	// a reseller to the VPS logs over "yearly".
	case errors.Is(err, service.ErrInvalidTrafficCycle):
		return http.StatusBadRequest
	case errors.Is(err, database.ErrClientNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// WriteClientError is ClientErrorStatus plus the write, since no caller wants one
// without the other.
func WriteClientError(w http.ResponseWriter, err error) {
	WriteJSONErrorFor(w, ClientErrorStatus(err), err)
}
