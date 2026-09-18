package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type controlServerStub struct {
	events      *[]string
	startErr    error
	shutdownErr error
	deadline    time.Time
}

func (s *controlServerStub) Start() error {
	if s.events != nil {
		*s.events = append(*s.events, "control-start")
	}
	return s.startErr
}

func (s *controlServerStub) Shutdown(ctx context.Context) error {
	if s.events != nil {
		*s.events = append(*s.events, "control-stop")
	}
	s.deadline, _ = ctx.Deadline()
	return s.shutdownErr
}

func TestControlStartsOnlyForExplicitServiceModes(t *testing.T) {
	for _, tt := range []struct {
		name           string
		daemon, server bool
		wantStart      bool
	}{
		{name: "daemon", daemon: true, wantStart: true},
		{name: "server", server: true, wantStart: true},
		{name: "both", daemon: true, server: true, wantStart: true},
		{name: "bare interactive or detached", wantStart: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var events []string
			created := 0
			got, err := startDaemonControl(tt.daemon, tt.server, func() localControlServer {
				created++
				return &controlServerStub{events: &events}
			})
			if err != nil {
				t.Fatalf("startDaemonControl: %v", err)
			}
			if tt.wantStart {
				if got == nil || created != 1 || len(events) != 1 || events[0] != "control-start" {
					t.Fatalf("server=%v created=%d events=%v, want one started server", got, created, events)
				}
				return
			}
			if got != nil || created != 0 || len(events) != 0 {
				t.Fatalf("server=%v created=%d events=%v, want no control binding", got, created, events)
			}
		})
	}
}

func TestControlStartFailureIsReturned(t *testing.T) {
	want := errors.New("bind denied")
	got, err := startDaemonControl(true, false, func() localControlServer {
		return &controlServerStub{startErr: want}
	})
	if got != nil || !errors.Is(err, want) {
		t.Fatalf("server=%v err=%v, want nil and %v", got, err, want)
	}
}

func TestControlShutdownIsBounded(t *testing.T) {
	stub := &controlServerStub{}
	before := time.Now()
	if err := shutdownDaemonControl(stub); err != nil {
		t.Fatalf("shutdownDaemonControl: %v", err)
	}
	if stub.deadline.IsZero() {
		t.Fatal("control shutdown context has no deadline")
	}
	remaining := time.Until(stub.deadline)
	if remaining <= 0 || remaining > controlShutdownTimeout || stub.deadline.Before(before) {
		t.Fatalf("shutdown deadline leaves %s, want (0, %s]", remaining, controlShutdownTimeout)
	}
}

func TestFatalPublicStartupCleansControlFirst(t *testing.T) {
	var events []string
	stub := &controlServerStub{events: &events}
	cleanupControlAfterStartupFailure(stub)
	if len(events) != 1 || events[0] != "control-stop" {
		t.Fatalf("events=%v, want control-stop", events)
	}
}

func TestGracefulShutdownStopsControlBeforePublicListeners(t *testing.T) {
	var events []string
	stub := &controlServerStub{events: &events}
	shutdownDaemonRuntime(stub,
		func() { events = append(events, "dns-stop") },
		func() { events = append(events, "sni-stop") },
		func() { events = append(events, "web-stop") },
	)
	want := []string{"control-stop", "dns-stop", "sni-stop", "web-stop"}
	if len(events) != len(want) {
		t.Fatalf("events=%v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events=%v, want %v", events, want)
		}
	}
}
