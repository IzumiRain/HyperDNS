package main

import (
	"strings"

	"hyperdns/internal/database"
)

// repairSubscriptionPortDrift re-points the subscription record's seeded copy
// of the panel port when it has gone stale (v2.2.0).
//
// The seed (EnsureSubscriptionDefaults) copies the panel port into the record
// once. A panel-port change made through older builds updated only the server
// record, so after a restart the copy differed from WebPort — and the listener
// logic read that difference as a DELIBERATE separate portal port, binding a
// subscriber listener on the port the operator had just moved away from and
// serving it with the subscription record's certificate. That is the
// ERR_CERT_COMMON_NAME_INVALID field report.
//
// The untouched-seed signature is what makes the repair safe, and the
// record's PortExplicit flag is what distinguishes a seed from a choice: the
// dashboard sets PortExplicit whenever a save names a port that is neither 0
// nor the panel's, so a deliberate "panel's name, own port, panel
// certificate" record is marked and never re-pointed here. A record written
// before the marker existed decodes as unmarked — seeded behaviour — and a
// single re-save of the card marks it permanently.
//
// The domain condition accepts the empty domain too: since v2.2.0's
// sanitiser, an unset subscription domain MEANS "the panel's", so a cleared
// domain with a stale seeded port is the same drift shape as a mirrored one.
// A record with its own distinct domain carries its own certificate
// relationship and never matches.
// Returns whether a repair was applied.
func repairSubscriptionPortDrift(subs *database.SubscriptionSettings, panelDomain string, panelPort int, persist func(*database.SubscriptionSettings) error) bool {
	if subs == nil {
		return false
	}
	snap := subs.Snapshot()
	if !snap.Enabled || snap.Port == 0 || snap.Port == panelPort {
		return false
	}
	if snap.PortExplicit {
		return false
	}
	if !snap.UsePanelCertificate {
		return false
	}
	if snap.Domain != "" && !strings.EqualFold(snap.Domain, panelDomain) {
		return false
	}
	snap.Port = panelPort
	snap.PortExplicit = false
	if err := subs.Apply(snap, persist); err != nil {
		return false
	}
	return true
}
