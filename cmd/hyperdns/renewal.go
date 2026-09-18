package main

import (
	"time"

	"hyperdns/internal/database"
	"hyperdns/internal/service/acme"
)

// startACMERenewalLoop runs one renewal pass per day. Each pass persists the
// ACME account key and then runs every surface's renewal check: the panel
// domain, the subscription portal's own certificate, and the DoH/DoT
// transports' certificate. The checks themselves live on the web server,
// which owns the records and the single-flighted issuance path — the loop is
// only the clock.
//
// The account key the manager generates on first use is persisted here, not
// inside the manager: the daemon owns the database, and "an encrypted
// setting" is the established shape for state that must survive a restart.
//
// Returns a stop channel (closed by the caller's defer) rather than a
// function, matching StartExpirationWatcher's convention.
func startACMERenewalLoop(m *acme.Manager, db *database.DB, renewChecks ...func()) (stop chan struct{}) {
	stop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		persistAccountKey := func() {
			key := m.AccountKey()
			if len(key) == 0 {
				return
			}
			state := struct {
				AccountKeyPEM []byte `json:"account_key"`
			}{AccountKeyPEM: key}
			_ = db.SetSetting("acme", state)
		}
		persistAccountKey() // the boot-time issuance may already have made one
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				persistAccountKey()
				for _, check := range renewChecks {
					if check != nil {
						check()
					}
				}
			}
		}
	}()
	return stop
}
