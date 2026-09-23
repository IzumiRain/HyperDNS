package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"hyperdns/internal/bootstrap"
	"hyperdns/internal/control"
)

type flushClientStub struct {
	calls int
	err   error
}

func (c *flushClientStub) FlushCache() error {
	c.calls++
	return c.err
}

func (c *flushClientStub) UpdatePresets() (control.UpdatePresetsResult, error) {
	return control.UpdatePresetsResult{}, nil
}

type contextFlushClientStub struct {
	calls int
	err   error
}

func (c *contextFlushClientStub) FlushCache(context.Context) error {
	c.calls++
	return c.err
}

func (c *contextFlushClientStub) UpdatePresets(context.Context) (control.UpdatePresetsResult, error) {
	return control.UpdatePresetsResult{}, nil
}

func TestDefaultPreDBControlClientUsesRootLocalSocket(t *testing.T) {
	client := newPreDBControlClient()
	if client == nil {
		t.Fatal("default pre-DB control client is nil")
	}
	adapter, ok := client.(preDBControlAdapter)
	if !ok {
		t.Fatalf("default pre-DB control client type = %T, want preDBControlAdapter", client)
	}
	if _, ok := adapter.client.(*control.Client); !ok {
		t.Fatalf("adapted client type = %T, want *control.Client", adapter.client)
	}
}

func TestContextControlClientAdaptsFlushCommand(t *testing.T) {
	inner := &contextFlushClientStub{}
	client := preDBControlAdapter{client: inner}
	if err := client.FlushCache(); err != nil {
		t.Fatalf("FlushCache: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("flush calls = %d, want 1", inner.calls)
	}
}

func TestBareInvocationDispatchesClientTUIBeforeStorage(t *testing.T) {
	old := preDBTUICommand
	oldInput := preDBInput
	calls := 0
	wantInput := strings.NewReader("0\n")
	preDBInput = func() io.Reader { return wantInput }
	preDBTUICommand = func(in io.Reader, _ io.Writer, _ io.Writer) error {
		calls++
		if in != wantInput {
			t.Fatalf("TUI input = %T, want injected reader", in)
		}
		return nil
	}
	t.Cleanup(func() {
		preDBTUICommand = old
		preDBInput = oldInput
	})

	var out, errOut bytes.Buffer
	handled, err := dispatchPreDBCommand(nil, "", &out, &errOut)
	if err != nil {
		t.Fatalf("dispatchPreDBCommand: %v", err)
	}
	if !handled || calls != 1 {
		t.Fatalf("handled=%v calls=%d, want true/1", handled, calls)
	}
}

func TestBareInvocationSubprocessDoesNotTouchStorage(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	keyPath := filepath.Join(dir, "master.key")

	cmd := exec.Command(os.Args[0], "-test.run=^TestBareInvocationSubprocessHelper$")
	cmd.Env = append(os.Environ(),
		"HYPERDNS_BARE_CLIENT_HELPER=1",
		"HYPERDNS_TEST_DB_PATH="+dbPath,
		"HYPERDNS_TEST_KEY_PATH="+keyPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("bare client helper: %v, stderr=%q", err, stderr.String())
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("bare client created or accessed database path: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("bare client created or accessed master key path: %v", err)
	}
}

func TestBareInvocationSubprocessHelper(t *testing.T) {
	if os.Getenv("HYPERDNS_BARE_CLIENT_HELPER") != "1" {
		return
	}
	os.Args = []string{
		os.Args[0],
		"-db", os.Getenv("HYPERDNS_TEST_DB_PATH"),
		"-key", os.Getenv("HYPERDNS_TEST_KEY_PATH"),
	}
	preDBInput = func() io.Reader { return strings.NewReader("0\n") }
	main()
	os.Exit(0)
}

func TestBareInvocationPropagatesClientTUIFailure(t *testing.T) {
	old := preDBTUICommand
	oldInput := preDBInput
	want := errors.New("control socket unavailable")
	preDBInput = func() io.Reader { return strings.NewReader("") }
	preDBTUICommand = func(io.Reader, io.Writer, io.Writer) error { return want }
	t.Cleanup(func() {
		preDBTUICommand = old
		preDBInput = oldInput
	})

	handled, err := dispatchPreDBCommand(nil, "", io.Discard, io.Discard)
	if !handled || !errors.Is(err, want) {
		t.Fatalf("handled=%v err=%v, want handled and %v", handled, err, want)
	}
}

func TestDaemonFlagsDoNotDispatchClientTUI(t *testing.T) {
	old := preDBTUICommand
	calls := 0
	preDBTUICommand = func(io.Reader, io.Writer, io.Writer) error {
		calls++
		return nil
	}
	t.Cleanup(func() { preDBTUICommand = old })

	for _, args := range [][]string{
		preDBArgs(nil, true, false),
		preDBArgs(nil, false, true),
		preDBArgs(nil, true, true),
	} {
		handled, err := dispatchPreDBCommand(args, "", io.Discard, io.Discard)
		if err != nil || handled {
			t.Fatalf("dispatchPreDBCommand(%q) = handled %v, err %v; want false, nil", args, handled, err)
		}
	}
	if calls != 0 {
		t.Fatalf("TUI calls = %d, want 0", calls)
	}
}

func TestPreDBArgsPreservesSubcommands(t *testing.T) {
	want := []string{"status"}
	got := preDBArgs(want, true, false)
	if len(got) != 1 || got[0] != "status" {
		t.Fatalf("preDBArgs = %q, want %q", got, want)
	}
}

func TestStorageInitializationPolicy(t *testing.T) {
	tests := []struct {
		name     string
		state    bootstrap.PathsState
		dbErr    error
		daemon   bool
		server   bool
		wantInit bool
		wantErr  error
	}{
		{name: "complete daemon", state: bootstrap.PathsComplete, daemon: true},
		{name: "complete interactive", state: bootstrap.PathsComplete},
		{name: "fresh daemon", state: bootstrap.PathsFresh, daemon: true, wantInit: true},
		{name: "fresh server", state: bootstrap.PathsFresh, server: true, wantInit: true},
		{name: "fresh bare command", state: bootstrap.PathsFresh, wantErr: errExplicitBootstrapRequired},
		{name: "database without key", state: bootstrap.PathsIncomplete, dbErr: bootstrap.ErrMissingMasterKey, daemon: true, wantErr: bootstrap.ErrMissingMasterKey},
		{name: "key without database", state: bootstrap.PathsIncomplete, dbErr: bootstrap.ErrMissingDatabase, daemon: true, wantErr: bootstrap.ErrMissingDatabase},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := storageInitializationAllowed(tt.state, tt.dbErr, tt.daemon, tt.server)
			if got != tt.wantInit || !errors.Is(err, tt.wantErr) {
				t.Fatalf("allowed=%v err=%v, want %v/%v", got, err, tt.wantInit, tt.wantErr)
			}
		})
	}
}

func TestPreDBCommandsRunWhileDatabaseIsLockedAndKeyIsAbsent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	keyPath := filepath.Join(dir, "master.key")
	locked, err := bolt.Open(dbPath, 0o600, nil)
	if err != nil {
		t.Fatalf("hold database lock: %v", err)
	}
	defer locked.Close()

	oldStatus := preDBStatusCommand
	preDBStatusCommand = func(_ string, out io.Writer) error {
		_, err := io.WriteString(out, "status-without-database\n")
		return err
	}
	t.Cleanup(func() { preDBStatusCommand = oldStatus })

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "help", args: []string{"help"}, want: "Usage:"},
		{name: "version", args: []string{"version"}, want: "HyperDNS "},
		{name: "version flag alias", args: []string{"-version"}, want: "HyperDNS "},
		{name: "status", args: []string{"status"}, want: "status-without-database"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			handled, err := dispatchPreDBCommand(tt.args, "missing-config.json", &out, &errOut)
			if err != nil {
				t.Fatalf("dispatchPreDBCommand: %v", err)
			}
			if !handled {
				t.Fatal("command was not handled before database startup")
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Fatalf("output %q does not contain %q", out.String(), tt.want)
			}
			if errOut.Len() != 0 {
				t.Fatalf("stderr = %q", errOut.String())
			}
			if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
				t.Fatalf("pre-DB command created master key: %v", err)
			}
		})
	}
}

func TestStatusGuidanceUsesLiveClientWithoutStoppingDaemon(t *testing.T) {
	var out bytes.Buffer
	if err := runStatusCommand(filepath.Join(t.TempDir(), "missing-config.json"), &out); err != nil {
		t.Fatalf("runStatusCommand: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "Run `hdns` to open the live control console") {
		t.Fatalf("status guidance = %q, want live control-console guidance", got)
	}
	if strings.Contains(got, "systemctl stop hyperdns") || strings.Contains(got, "needs the service stopped") {
		t.Fatalf("status guidance still tells the operator to stop the daemon: %q", got)
	}
}

func TestFlushUsesDaemonControlClient(t *testing.T) {
	oldFactory := newPreDBControlClient
	client := &flushClientStub{}
	newPreDBControlClient = func() preDBControlClient { return client }
	t.Cleanup(func() { newPreDBControlClient = oldFactory })

	var out, errOut bytes.Buffer
	handled, err := dispatchPreDBCommand([]string{"flush"}, "", &out, &errOut)
	if err != nil {
		t.Fatalf("dispatchPreDBCommand: %v", err)
	}
	if !handled || client.calls != 1 {
		t.Fatalf("handled=%v control flush calls=%d, want true/1", handled, client.calls)
	}
	if !strings.Contains(out.String(), "flushed") {
		t.Fatalf("success output = %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestFlushPropagatesControlClientFailure(t *testing.T) {
	oldFactory := newPreDBControlClient
	wantErr := errors.New("daemon control unavailable")
	client := &flushClientStub{err: wantErr}
	newPreDBControlClient = func() preDBControlClient { return client }
	t.Cleanup(func() { newPreDBControlClient = oldFactory })

	handled, err := dispatchPreDBCommand([]string{"flush"}, "", io.Discard, io.Discard)
	if !handled || !errors.Is(err, wantErr) {
		t.Fatalf("handled=%v err=%v, want handled and wrapped %v", handled, err, wantErr)
	}
}

func TestRunPreDBCommandReturnsTruthfulExitCodes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var out, errOut bytes.Buffer
		handled, exitCode := runPreDBCommand([]string{"version"}, "", &out, &errOut)
		if !handled || exitCode != 0 {
			t.Fatalf("handled=%v exitCode=%d, want true/0", handled, exitCode)
		}
		if !strings.Contains(out.String(), "HyperDNS ") {
			t.Fatalf("stdout = %q", out.String())
		}
		if errOut.Len() != 0 {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("failure", func(t *testing.T) {
		oldFactory := newPreDBControlClient
		wantErr := errors.New("daemon control unavailable")
		newPreDBControlClient = func() preDBControlClient {
			return &flushClientStub{err: wantErr}
		}
		t.Cleanup(func() { newPreDBControlClient = oldFactory })

		var out, errOut bytes.Buffer
		handled, exitCode := runPreDBCommand([]string{"flush"}, "", &out, &errOut)
		if !handled || exitCode == 0 {
			t.Fatalf("handled=%v exitCode=%d, want true/nonzero", handled, exitCode)
		}
		if out.Len() != 0 {
			t.Fatalf("stdout = %q", out.String())
		}
		if !strings.Contains(errOut.String(), "flush daemon cache: daemon control unavailable") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})
}

func TestPreDBCommandSubprocessExitStatus(t *testing.T) {
	for _, tt := range []struct {
		name        string
		command     string
		wantFailure bool
		wantStderr  string
	}{
		{name: "successful version", command: "version"},
		{name: "failed flush", command: "flush", wantFailure: true, wantStderr: "flush daemon cache"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestPreDBCommandSubprocessHelper$")
			cmd.Env = append(os.Environ(), "HYPERDNS_PREDB_TEST_COMMAND="+tt.command)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			if tt.wantFailure {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
					t.Fatalf("subprocess error = %v, want nonzero exit", err)
				}
			} else if err != nil {
				t.Fatalf("subprocess error = %v, stderr=%q", err, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestPreDBCommandSubprocessHelper(t *testing.T) {
	command, ok := os.LookupEnv("HYPERDNS_PREDB_TEST_COMMAND")
	if !ok {
		return
	}
	handled, exitCode := runPreDBCommand([]string{command}, "", io.Discard, os.Stderr)
	if !handled {
		os.Exit(125)
	}
	os.Exit(exitCode)
}
