package service

import (
	"time"

	"hyperdns/internal/database"
)

// A subscriber record as a front-end has to show it, rather than as it is stored.
//
// Three of the figures an operator and a subscriber actually look at are not fields:
// the live usage total (stored bytes plus whatever has been metered since the last
// flush), whether the allowance is spent, and when it comes back. Every one of them
// was being recomputed in JavaScript from the stored record, which means the
// dashboard held its own copy of the quota rule and of the clamped-month arithmetic
// — and a copy that disagrees with the daemon is worse than no copy at all, because
// the panel then says a subscriber has quota left while the resolver is refusing
// them.
//
// Serialising this instead of database.Client changes nothing about the payload's
// existing fields: the embedded struct is flattened by encoding/json, so every
// key an older dashboard reads is still there and in the same place.

// ClientView is a stored client plus the quota figures that are computed.
type ClientView struct {
	database.Client

	// NextTrafficReset is when the allowance comes back. It is absent rather than
	// zero for an account with no cycle, so a front-end that forgets to check renders
	// nothing instead of January of year 1.
	NextTrafficReset *time.Time `json:"next_traffic_reset,omitempty"`

	// QuotaExceeded is the daemon's own enforcement decision, not the panel's guess
	// at it. A limit of zero is unlimited, so this is false for every account created
	// before quotas existed.
	QuotaExceeded bool `json:"quota_exceeded"`
}

// ViewClient decorates one record, folding in the bytes the ledger has counted since
// the last flush. That fold is the reason this takes a record straight from
// GetClient: usage that is up to a flush interval stale is what let a subscriber
// whose traffic had already been cut off read a page promising them quota.
func (s *ClientService) ViewClient(c *database.Client) ClientView {
	if c == nil {
		return ClientView{}
	}
	view := ClientView{Client: *c}
	view.TrafficUsedBytes = s.TrafficUsed(c)
	view.QuotaExceeded = quotaExceededFor(view.TrafficUsedBytes, view.TrafficLimitGB)
	if next, ok := NextTrafficReset(c); ok {
		view.NextTrafficReset = &next
	}
	return view
}

// ListClientViews is the whole subscriber list, decorated.
//
// It exists so no handler has to remember that ListClients has already folded the
// pending bytes in: decorating that list with ViewClient would fold them a second
// time and report usage that never happened, which for an account near its limit is
// the difference between "active" and "cut off" in the panel.
func (s *ClientService) ListClientViews() ([]ClientView, error) {
	clients, err := s.ListClients()
	if err != nil {
		return nil, err
	}
	views := make([]ClientView, 0, len(clients))
	for i := range clients {
		view := ClientView{Client: clients[i]}
		view.QuotaExceeded = quotaExceededFor(view.TrafficUsedBytes, view.TrafficLimitGB)
		if next, ok := NextTrafficReset(&clients[i]); ok {
			view.NextTrafficReset = &next
		}
		views = append(views, view)
	}
	return views, nil
}
