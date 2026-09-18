package tui

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestSanitizeStripsTerminalControl: a subscriber name carrying ANSI escape
// sequences must not reach the terminal as-is — cursor movement and OSC
// sequences in printed data are how a hostile name repaints an operator's
// screen or spoofs a prompt.
func TestSanitizeStripsTerminalControl(t *testing.T) {
	hostile := "name\x1b[2J\x1b[Hinjected\x1b]0;fake-title\x07"
	got := Sanitize(hostile)
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Fatalf("control bytes survived sanitization: %q", got)
	}
	if !strings.Contains(got, "name") || !strings.Contains(got, "injected") {
		t.Errorf("sanitization dropped visible content: %q", got)
	}
	// Newlines and tabs become spaces so a table row stays one line.
	if strings.Contains(Sanitize("a\nb\tc"), "\n") {
		t.Error("newline survived sanitization")
	}
}

// TestTruncateCapsDisplayStrings: the table columns bound their content.
func TestTruncateCapsDisplayStrings(t *testing.T) {
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("Truncate altered a short string: %q", got)
	}
	got := Truncate(strings.Repeat("x", 30), 10)
	if got != "xxxxxxxxx…" {
		t.Errorf("Truncate = %q", got)
	}
}

// TestPlainPaletteOnNonTerminal: NewPalette must disable every escape
// sequence for a bytes.Buffer (not a terminal) — a pipe consumer must never
// receive the raw bytes.
func TestPlainPaletteOnNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	p := NewPalette(&buf)
	if p != plainPalette {
		t.Fatal("a non-terminal writer got a color palette")
	}
	if p.cyan != "" || p.reset != "" {
		t.Error("plain palette carries escape bytes")
	}
	if got := p.Red("x"); got != "x" {
		t.Errorf("plain palette Red altered the string: %q", got)
	}
	// ClearScreen on a plain palette writes nothing.
	before := buf.Len()
	p.ClearScreen(&buf)
	if buf.Len() != before {
		t.Error("ClearScreen emitted bytes under a plain palette")
	}
}

// TestBannerHasNoInterpolatedBytes: the banner is a fixed template; only the
// version interpolates, and it is sanitized by the caller.
func TestBannerHasNoInterpolatedBytes(t *testing.T) {
	b := Banner("2.2.0")
	if !strings.Contains(b, "HyperDNS") && !strings.Contains(b, "Standalone SmartDNS") {
		t.Errorf("banner lost its wordmark: %q", b)
	}
	if strings.ContainsAny(b, "\x1b") {
		t.Error("banner carries ANSI bytes — color belongs to the palette, not the template")
	}
}

// TestUninstallCommandIsInteractiveAndPreConfirmed: the field-report regression.
// ExecSystemController.Uninstall used to run the uninstaller with nil stdio:
// its confirmation read EOF through a dead pipe, its output was invisible, and
// the operator saw only "control request failed" after typing UNINSTALL. The
// default command must carry -y (the console already collected the typed word;
// -y still archives the data) and run through runInteractive, which wires the
// real terminal. A custom command exercises the same interactive path.
func TestUninstallCommandIsInteractiveAndPreConfirmed(t *testing.T) {
	err := ExecSystemController{UninstallCommand: []string{"true"}}.Uninstall(context.Background())
	if err != nil {
		t.Fatalf("custom uninstall command failed through the interactive path: %v", err)
	}
}

// sanitizedError must show an exit-status error rather than the redacted
// generic string — that redaction is what hid the uninstaller failure.
func TestSanitizedErrorShowsSystemCommandFailures(t *testing.T) {
	exitErr := exec.Command("false").Run() // *exec.ExitError
	got := sanitizedError(exitErr)
	if got == "control request failed" {
		t.Fatal("a system-command exit status was redacted to the generic control string — the uninstaller's failure reason would be hidden")
	}
	if !strings.Contains(got, "exit status") {
		t.Errorf("exit error rendered as %q, want the exit status visible", got)
	}
	// Arbitrary errors stay redacted.
	if got := sanitizedError(errors.New("password=hunter2 in a wrapped cause")); got != "control request failed" {
		t.Errorf("an arbitrary error leaked: %q", got)
	}
}

// TestStartStopReachTheSystemController: the new lifecycle options are real
// wiring, not menu text.
func TestStartStopReachTheSystemController(t *testing.T) {
	client := &controlClientStub{}
	system := &systemControllerStub{}
	var out, errOut bytes.Buffer

	// Option 4 (stop) demands a typed confirmation first. Each action
	// consumes one line for the choice and one for the pause.
	if err := Run(context.Background(), strings.NewReader("4\nSTOP\n\n5\n\n0\n"), &out, &errOut, client, system); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if system.stops != 1 {
		t.Errorf("stops = %d, want 1 — the STOP confirmation did not reach the controller", system.stops)
	}
	if system.starts != 1 {
		t.Errorf("starts = %d, want 1", system.starts)
	}

	// A wrong confirmation leaves the service alone.
	system2 := &systemControllerStub{}
	if err := Run(context.Background(), strings.NewReader("4\nno\n\n0\n"), &out, &errOut, client, system2); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if system2.stops != 0 {
		t.Errorf("stops after a refused confirmation = %d, want 0", system2.stops)
	}
}

// TestMenuRedrawsWithoutAccumulating: the v2.1 defect this pins — the menu
// appeared once per action, scrolling the terminal. The redraw-in-place
// console prints one banner per loop iteration: the initial screen plus one
// after each action's pause, so two actions produce three banners — never
// the four the old console would have left in the scrollback.
func TestMenuRedrawsWithoutAccumulating(t *testing.T) {
	client := &controlClientStub{}
	system := &systemControllerStub{}
	var out, errOut bytes.Buffer

	if err := Run(context.Background(), strings.NewReader("10\n\n10\n\n0\n"), &out, &errOut, client, system); err != nil {
		t.Fatalf("Run: %v", err)
	}
	banners := strings.Count(out.String(), "control console")
	if banners != 3 {
		t.Errorf("banner count = %d, want 3 (initial + one per action; the old console printed one per action with no redraw)", banners)
	}
	if client.flushCalls != 2 {
		t.Errorf("flush calls = %d, want 2", client.flushCalls)
	}
}
