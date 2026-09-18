package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"hyperdns/internal/bootstrap"
	"hyperdns/internal/control"
	"hyperdns/internal/tui"
	"hyperdns/internal/version"
)

var errExplicitBootstrapRequired = errors.New("storage is uninitialized; start with -daemon or -server to initialize it")

func storageInitializationAllowed(state bootstrap.PathsState, stateErr error, daemon, server bool) (bool, error) {
	if stateErr != nil {
		return false, stateErr
	}
	switch state {
	case bootstrap.PathsComplete:
		return false, nil
	case bootstrap.PathsFresh:
		if daemon || server {
			return true, nil
		}
		return false, errExplicitBootstrapRequired
	default:
		return false, fmt.Errorf("database/master-key pair is incomplete")
	}
}

// preDBControlClient is the command-side seam for daemon-owned operations. Task
// 2 supplies the real root-local transport; keeping this command on the seam now
// prevents it from constructing a second, process-local cache.
type preDBControlClient interface {
	FlushCache() error
}

type contextualFlushClient interface {
	FlushCache(context.Context) error
}

type preDBControlAdapter struct {
	client contextualFlushClient
}

func (c preDBControlAdapter) FlushCache() error {
	if c.client == nil {
		return errors.New("daemon control client is unavailable")
	}
	return c.client.FlushCache(context.Background())
}

type unavailablePreDBControlClient struct{}

func (unavailablePreDBControlClient) FlushCache() error {
	return fmt.Errorf("daemon cache control is unavailable until the local control transport is configured")
}

var (
	preDBStatusCommand    = runStatusCommand
	newPreDBControlClient = func() preDBControlClient {
		return preDBControlAdapter{client: control.NewClient(control.DefaultSocketPath)}
	}
	preDBTUICommand = func(in io.Reader, out, errOut io.Writer) error {
		return tui.Run(
			context.Background(),
			in,
			out,
			errOut,
			control.NewClient(control.DefaultSocketPath),
			tui.ExecSystemController{},
		)
	}
	preDBInput = func() io.Reader { return os.Stdin }
)

func runPreDBCommand(args []string, cfgPath string, out, errOut io.Writer) (handled bool, exitCode int) {
	if errOut == nil {
		errOut = io.Discard
	}
	handled, err := dispatchPreDBCommand(args, cfgPath, out, errOut)
	if !handled || err == nil {
		return handled, 0
	}
	fmt.Fprintln(errOut, err)
	return true, 1
}

func preDBArgs(parsedArgs []string, daemon, server bool) []string {
	if len(parsedArgs) != 0 || (!daemon && !server) {
		return parsedArgs
	}
	if daemon {
		return []string{"-daemon"}
	}
	return []string{"-server"}
}

// dispatchPreDBCommand handles commands that must never require master.key or a
// bbolt handle. Unknown commands return handled=false for daemon startup.
func dispatchPreDBCommand(args []string, cfgPath string, out, errOut io.Writer) (handled bool, err error) {
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	_ = errOut
	if len(args) == 0 {
		if err := preDBTUICommand(preDBInput(), out, errOut); err != nil {
			return true, fmt.Errorf("run control console: %w", err)
		}
		return true, nil
	}

	switch strings.ToLower(args[0]) {
	case "help", "-h", "--help":
		fmt.Fprintln(out, "HyperDNS - Standalone Next-Gen SmartDNS Controller")
		fmt.Fprintln(out, "Usage: hyperdns [flags] [subcommand]")
		fmt.Fprintln(out, "Subcommands:")
		fmt.Fprintln(out, "  status      live service report (no database needed; works beside the daemon)")
		fmt.Fprintln(out, "  flush       ask the running daemon to flush its DNS cache")
		fmt.Fprintln(out, "  uninstall   interactive uninstaller")
		return true, nil
	case "version", "-version", "-v", "--version":
		fmt.Fprintln(out, "HyperDNS "+version.Short())
		return true, nil
	case "status":
		return true, preDBStatusCommand(cfgPath, out)
	case "flush":
		if err := newPreDBControlClient().FlushCache(); err != nil {
			return true, fmt.Errorf("flush daemon cache: %w", err)
		}
		fmt.Fprintln(out, "DNS cache flushed successfully.")
		return true, nil
	default:
		return false, nil
	}
}
