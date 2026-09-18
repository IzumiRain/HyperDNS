package main

import (
	"fmt"
	"os"
	"time"

	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

// Disposable-local-instance helper: reset the admin password to a known
// value and disable TOTP so the browser verification can log in. NEVER run
// against the live VPS database.
func main() {
	dbPath, keyPath := os.Args[1], os.Args[2]
	newPassword := os.Args[3]
	c, err := crypto.LoadOrGenerateMasterKey(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "key:", err)
		os.Exit(1)
	}
	db, err := database.OpenExisting(dbPath, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer db.Close()
	var rec database.AuthSettings
	if err := db.GetSetting("auth", &rec); err != nil {
		fmt.Fprintln(os.Stderr, "auth read:", err)
		os.Exit(1)
	}
	fmt.Printf("before: 2fa=%v pending=%v\n", rec.TOTPEnabled, rec.TOTPPending != "")

	var server database.ServerSettings
	if err := db.GetSetting("server", &server); err != nil {
		fmt.Fprintln(os.Stderr, "server read:", err)
		os.Exit(1)
	}
	hashed, err := crypto.HashPassword(newPassword)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}
	_ = hashed
	// Persist through the accessors so the locking contract holds.
	if err := server.UpdateAndPersist(func(m *database.MutableSettings) {
		m.AdminPassword = hashed
		m.AdminPasswordWeak = false
	}, func(s *database.ServerSettings) error { return db.SetSetting("server", s) }); err != nil {
		fmt.Fprintln(os.Stderr, "persist server:", err)
		os.Exit(1)
	}
	if err := rec.DisableTOTP(func(a *database.AuthSettings) error { return db.SetSetting("auth", a) }); err != nil {
		fmt.Fprintln(os.Stderr, "disable totp:", err)
		os.Exit(1)
	}
	fmt.Println("reset OK; 2FA disabled; password set; lockouts cleared by restart")
	_ = time.Now()
}
