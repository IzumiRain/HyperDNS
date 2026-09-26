//go:build !unix

package selfupdate

import "errors"

// signalRestart is a no-op on platforms without POSIX signals; automatic apply
// is gated to Linux in StartApply, so this is only here to keep the package
// building on Windows/dev.
func signalRestart() error {
	return errors.New("restart not supported on this platform")
}
