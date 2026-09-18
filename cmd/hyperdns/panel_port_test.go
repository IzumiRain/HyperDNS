package main

import (
	"path/filepath"
	"testing"

	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

// openCmdTestDB builds a real encrypted store, the same shape the daemon opens.
func openCmdTestDB(t *testing.T) *database.DB {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	cipher, err := crypto.LoadOrGenerateMasterKey(keyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	db, err := database.Create(filepath.Join(dir, "data.db"), cipher)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestPanelPortChangeCarriesTheSubscriptionCopy: the subscription record is
// seeded with a COPY of the panel port, and a panel-port change through the
// control plane used to leave the copy behind. After the restart the copy no
// longer equalled WebPort, so the daemon read it as a deliberate separate
// portal port and bound a subscriber listener on the port the operator had
// just moved away from — the ERR_CERT_COMMON_NAME_INVALID field report.
func TestPanelPortChangeCarriesTheSubscriptionCopy(t *testing.T) {
	db := openCmdTestDB(t)

	settings := &database.ServerSettings{WebPort: 32604, AdminPath: "0123456789abcdef"}
	if err := db.SetSetting("server", settings); err != nil {
		t.Fatalf("seed server: %v", err)
	}
	subs := &database.SubscriptionSettings{}
	if err := db.SetSetting("subscription", subs); err != nil {
		t.Fatalf("seed subs: %v", err)
	}
	// The seeded copy: same port as the panel, panel certificate, same domain.
	if err := subs.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", Title: "HyperDNS",
		Domain: "dns.example", Port: 32604, UsePanelCertificate: true,
	}, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	d := &daemonControl{db: db, settings: settings, subs: subs}
	if err := d.ControlPersistPanelPort(48224); err != nil {
		t.Fatalf("ControlPersistPanelPort: %v", err)
	}

	// PersistWebPort deliberately leaves the LIVE struct on the old port (the
	// listener is bound and cannot move; the restart applies the record), so
	// the assertion is on the stored record — which is what the next boot reads.
	var storedServer database.ServerSettings
	if err := db.GetSetting("server", &storedServer); err != nil {
		t.Fatalf("read server back: %v", err)
	}
	if storedServer.WebPort != 48224 {
		t.Fatalf("stored panel port = %d, want 48224", storedServer.WebPort)
	}
	// The subscription copy followed — in memory and in the store.
	if got := subs.GetPort(); got != 48224 {
		t.Fatalf("the subscription record's port copy stayed at %d — the next boot would bind a subscriber listener on the abandoned port", got)
	}
	var stored database.SubscriptionSettings
	if err := db.GetSetting("subscription", &stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.GetPort() != 48224 {
		t.Fatalf("stored subscription port = %d, want 48224", stored.GetPort())
	}
}

// ...and the operator's DELIBERATE separate portal port must survive a panel
// port change: the copy only follows when it was still tracking the panel.
func TestPanelPortChangePreservesADeliberatePortalPort(t *testing.T) {
	db := openCmdTestDB(t)

	settings := &database.ServerSettings{WebPort: 32604, AdminPath: "0123456789abcdef"}
	subs := &database.SubscriptionSettings{}
	if err := subs.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", Title: "HyperDNS",
		Domain: "sub.example", Port: 18443, UsePanelCertificate: false,
		CertPath: "certs/acme/sub.example.crt", KeyPath: "certs/acme/sub.example.key",
	}, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	d := &daemonControl{db: db, settings: settings, subs: subs}
	if err := d.ControlPersistPanelPort(48224); err != nil {
		t.Fatalf("ControlPersistPanelPort: %v", err)
	}
	if got := subs.GetPort(); got != 18443 {
		t.Fatalf("a deliberate portal port was overwritten: %d, want 18443", got)
	}
}

// TestRepairSubscriptionPortDriftHealsTheStaleCopy: the boot-half. A record
// written by an older build after a TUI port change holds the pre-change
// panel port while still looking like the untouched seed; boot must re-point
// it or the daemon binds a subscriber listener on the abandoned port.
func TestRepairSubscriptionPortDriftHealsTheStaleCopy(t *testing.T) {
	db := openCmdTestDB(t)
	subs := &database.SubscriptionSettings{}
	// The stale state: seeded at 32604, panel moved to 48224 by an old build.
	if err := subs.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", Title: "HyperDNS",
		Domain: "dns.example", Port: 32604, UsePanelCertificate: true,
	}, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if !repairSubscriptionPortDrift(subs, "dns.example", 48224, func(s *database.SubscriptionSettings) error {
		return db.SetSetting("subscription", s)
	}) {
		t.Fatal("a stale port copy with the untouched-seed signature was not repaired")
	}
	if got := subs.GetPort(); got != 48224 {
		t.Fatalf("port after repair = %d, want 48224", got)
	}
	// And the repair persisted.
	var stored database.SubscriptionSettings
	if err := db.GetSetting("subscription", &stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.GetPort() != 48224 {
		t.Fatalf("stored port after repair = %d, want 48224", stored.GetPort())
	}
}

// The repair must NOT touch a record that chose a separate origin: distinct
// domain, or a matching port already, or disabled.
func TestRepairSubscriptionPortDriftLeavesDeliberateRecordsAlone(t *testing.T) {
	cases := []struct {
		name string
		snap database.SubscriptionSnapshot
	}{
		{"distinct domain with its own pair", database.SubscriptionSnapshot{
			Enabled: true, URIPath: "/sub", Domain: "sub.example", Port: 18443,
			UsePanelCertificate: false, CertPath: "c.crt", KeyPath: "c.key"}},
		{"port already current", database.SubscriptionSnapshot{
			Enabled: true, URIPath: "/sub", Domain: "dns.example", Port: 48224,
			UsePanelCertificate: true}},
		{"disabled record", database.SubscriptionSnapshot{
			Enabled: false, URIPath: "/sub", Domain: "dns.example", Port: 32604,
			UsePanelCertificate: true}},
		{"zero port (rides the panel)", database.SubscriptionSnapshot{
			Enabled: true, URIPath: "/sub", Domain: "dns.example", Port: 0,
			UsePanelCertificate: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subs := &database.SubscriptionSettings{}
			if err := subs.Apply(tc.snap, nil); err != nil {
				t.Fatalf("apply: %v", err)
			}
			before := subs.GetPort()
			if repairSubscriptionPortDrift(subs, "dns.example", 48224, nil) {
				t.Fatal("the repair fired on a record it must leave alone")
			}
			if got := subs.GetPort(); got != before {
				t.Fatalf("port changed %d -> %d on a deliberate record", before, got)
			}
		})
	}
}

// TestRepairSubscriptionPortDriftRespectsTheExplicitPort: the v2.2.0
// remediation marker. A record the operator deliberately pointed at its own
// port (PortExplicit, set by the dashboard's sanitiser on every save that
// names a non-panel port) must survive the boot repair — the stale-seed
// signature and a deliberate choice look identical without it.
func TestRepairSubscriptionPortDriftRespectsTheExplicitPort(t *testing.T) {
	db := openCmdTestDB(t)
	defer func() { _ = db.Close() }()
	subs := &database.SubscriptionSettings{}
	if err := subs.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", Title: "HyperDNS",
		Domain: "panel.example", Port: 18443, UsePanelCertificate: true,
		PortExplicit: true,
	}, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if repairSubscriptionPortDrift(subs, "panel.example", 48224, nil) {
		t.Fatal("a marked deliberate port was re-pointed by the boot repair")
	}
	if got := subs.GetPort(); got != 18443 {
		t.Fatalf("deliberate portal port = %d, want 18443", got)
	}
}

// TestRepairSubscriptionPortDriftHealsTheClearedDomain: an unset subscription
// domain MEANS "the panel's" since the v2.2.0 sanitiser, so a cleared domain
// carrying a stale seeded port is the same drift shape as a mirrored one.
func TestRepairSubscriptionPortDriftHealsTheClearedDomain(t *testing.T) {
	db := openCmdTestDB(t)
	defer func() { _ = db.Close() }()
	subs := &database.SubscriptionSettings{}
	if err := subs.Apply(database.SubscriptionSnapshot{
		Enabled: true, URIPath: "/sub", Title: "HyperDNS",
		Domain: "", Port: 32604, UsePanelCertificate: true,
	}, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if !repairSubscriptionPortDrift(subs, "panel.example", 48224, nil) {
		t.Fatal("the cleared-domain stale copy was not repaired")
	}
	if got := subs.GetPort(); got != 48224 {
		t.Fatalf("repaired port = %d, want 48224 (the panel's new port)", got)
	}
}
