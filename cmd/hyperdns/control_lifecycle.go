package main

import (
	"context"
	"errors"
	"time"

	"hyperdns/internal/control"
)

const controlShutdownTimeout = 3 * time.Second

type localControlServer interface {
	Start() error
	Shutdown(context.Context) error
}

// controlStartupFatal decides whether a control-plane startup failure should
// stop the daemon.
//
// A platform with no root-local transport (anything but Linux) is a capability
// limit, not a misconfiguration: the resolver, the relay and the dashboard are
// unaffected, so the daemon runs and only the `hdns` console is unavailable.
// A Linux host where the runtime directory cannot be created — an unprivileged
// run hitting /run/hyperdns, a read-only /run — is the same class of limit for
// the same reason: everything the subscribers touch still works, only the
// console is gone. Every other failure — a refused bind on an existing
// directory, a directory that is not root-owned mode 0700, a lifecycle lock
// already held, a socket still live — says the management surface cannot be
// secured on a host that is supposed to have one, and starting anyway would
// leave an operator with a console that silently does not exist. Those stay
// fatal. Neither branch ever opens a weaker transport.
func controlStartupFatal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, control.ErrUnsupported) {
		return false
	}
	if errors.Is(err, control.ErrRuntimeDir) {
		return false
	}
	return true
}

func startDaemonControl(daemon, server bool, build func() localControlServer) (localControlServer, error) {
	if !daemon && !server {
		return nil, nil
	}
	controlServer := build()
	if err := controlServer.Start(); err != nil {
		return nil, err
	}
	return controlServer, nil
}

func shutdownDaemonControl(server localControlServer) error {
	if server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlShutdownTimeout)
	defer cancel()
	return server.Shutdown(ctx)
}

func cleanupControlAfterStartupFailure(server localControlServer) {
	_ = shutdownDaemonControl(server)
}

func shutdownDaemonRuntime(server localControlServer, stopDNS, stopSNI, stopWeb func()) {
	_ = shutdownDaemonControl(server)
	if stopDNS != nil {
		stopDNS()
	}
	if stopSNI != nil {
		stopSNI()
	}
	if stopWeb != nil {
		stopWeb()
	}
}
