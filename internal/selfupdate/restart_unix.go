//go:build unix

package selfupdate

import (
	"os"
	"syscall"
)

// signalRestart sends SIGTERM to this process. main's signal handler performs a
// graceful shutdown and returns through main so every defer runs; under systemd
// (Restart=always) the unit is then brought back up on the freshly swapped
// binary. This is unit-name-independent — no `systemctl` call required.
func signalRestart() error {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGTERM)
}
