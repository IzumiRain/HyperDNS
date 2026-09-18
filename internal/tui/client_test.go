package tui

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"hyperdns/internal/control"
)

type controlClientStub struct {
	statusCalls int
	flushCalls  int
}

func (c *controlClientStub) Status(context.Context) (control.Status, error) {
	c.statusCalls++
	return control.Status{TotalQueries: 7, CacheItems: 2}, nil
}
func (*controlClientStub) ListClients(context.Context) ([]control.ClientView, error) {
	return nil, nil
}
func (*controlClientStub) CreateClient(context.Context, control.CreateClientRequest) (control.ClientView, error) {
	return control.ClientView{}, nil
}
func (*controlClientStub) DeleteClient(context.Context, string) error { return nil }
func (c *controlClientStub) FlushCache(context.Context) error {
	c.flushCalls++
	return nil
}
func (*controlClientStub) StartBenchmark(context.Context) error { return nil }
func (*controlClientStub) Settings(context.Context) (control.SettingsView, error) {
	return control.SettingsView{}, nil
}
func (*controlClientStub) RotateAPIKey(context.Context, control.RotateAPIKeyRequest) (control.RotateAPIKeyResult, error) {
	return control.RotateAPIKeyResult{}, nil
}
func (*controlClientStub) PersistPanelPort(context.Context, int) error { return nil }
func (*controlClientStub) ClearLockouts(context.Context, control.ClearLockoutsRequest) (int, error) {
	return 0, nil
}
func (*controlClientStub) ChangeAdmin(context.Context, control.ChangeAdminRequest) error {
	return nil
}
func (*controlClientStub) ResetAdmin(context.Context, control.ResetAdminRequest) error {
	return nil
}

type systemControllerStub struct {
	restarts   int
	uninstalls int
	starts     int
	stops      int
}

func (s *systemControllerStub) Restart(context.Context) error {
	s.restarts++
	return nil
}
func (s *systemControllerStub) Uninstall(context.Context) error {
	s.uninstalls++
	return nil
}
func (s *systemControllerStub) Start(context.Context) error {
	s.starts++
	return nil
}
func (s *systemControllerStub) Stop(context.Context) error {
	s.stops++
	return nil
}

func TestMenuUsesControlClientForCacheFlush(t *testing.T) {
	client := &controlClientStub{}
	system := &systemControllerStub{}
	var out, errOut bytes.Buffer

	// v2.2.0: flush moved to option 10, and every action ends in a pause the
	// operator dismisses with Enter — so the input is choice, pause, exit.
	if err := Run(context.Background(), strings.NewReader("10\n\n0\n"), &out, &errOut, client, system); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.flushCalls != 1 {
		t.Fatalf("flush calls = %d, want 1", client.flushCalls)
	}
	if system.restarts != 0 || system.uninstalls != 0 {
		t.Fatalf("system actions = restart %d, uninstall %d; want none", system.restarts, system.uninstalls)
	}
	if !strings.Contains(out.String(), "DNS cache flushed.") || errOut.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestExitAndEOFRemainClientOnly(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want error
	}{
		{name: "explicit exit", in: "0\n"},
		{name: "eof", want: io.EOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &controlClientStub{}
			system := &systemControllerStub{}
			err := Run(context.Background(), strings.NewReader(tt.in), io.Discard, io.Discard, client, system)
			if err != tt.want {
				t.Fatalf("Run error = %v, want %v", err, tt.want)
			}
			if system.restarts != 0 || system.uninstalls != 0 {
				t.Fatalf("exit invoked system action: %+v", system)
			}
		})
	}
}
