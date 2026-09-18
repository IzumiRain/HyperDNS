package tui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

// ANSI presentation for the console. The constants are inert data; whether
// they are emitted at all is decided by NewPalette, because a non-terminal
// consumer (a test harness, `hdns | tee`, a CI pipe) must never receive the
// escape sequences — they would corrupt whatever is reading it.
type palette struct {
	cyan   string
	green  string
	yellow string
	red    string
	bold   string
	faint  string
	reset  string
}

// NewPalette decides whether color is appropriate for out: enabled when the
// stream is a terminal, TERM is set to something other than "dumb", and
// NO_COLOR is unset (the https://no-color.org convention).
func NewPalette(out io.Writer) palette {
	if v, ok := os.LookupEnv("NO_COLOR"); ok && v != "" {
		return plainPalette
	}
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return plainPalette
	}
	f, ok := out.(*os.File)
	if !ok {
		return plainPalette
	}
	fi, err := f.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		return plainPalette
	}
	return palette{
		cyan:   "\x1b[36m",
		green:  "\x1b[32m",
		yellow: "\x1b[33m",
		red:    "\x1b[31m",
		bold:   "\x1b[1m",
		faint:  "\x1b[2m",
		reset:  "\x1b[0m",
	}
}

var plainPalette = palette{}

func (p palette) Cyan(s string) string   { return p.cyan + s + p.reset }
func (p palette) Green(s string) string  { return p.green + s + p.reset }
func (p palette) Yellow(s string) string { return p.yellow + s + p.reset }
func (p palette) Red(s string) string    { return p.red + s + p.reset }
func (p palette) Bold(s string) string   { return p.bold + s + p.reset }
func (p palette) Faint(s string) string  { return p.faint + s + p.reset }

// ClearScreen moves the cursor home and wipes the display, so the console
// redraws in place instead of scrolling its whole history down the terminal.
// Only emitted when color is enabled — a pipe consumer must not get the
// bytes, and a TERM-less terminal cannot do anything with them anyway.
func (p palette) ClearScreen(w io.Writer) {
	if p.reset == "" {
		return
	}
	fmt.Fprint(w, "\x1b[2J\x1b[H")
}

// Banner is the console's opening art. Version is interpolated by the caller
// so the string stays a pure template here.
func Banner(version string) string {
	return strings.Join([]string{
		"  _    _                           _____  _   _  _____ ",
		" | |  | |                         |  __ \\| \\ | |/ ____|",
		" | |__| |_   _ _ __   ___ _ __    | |  | |  \\| | (___  ",
		" |  __| | | | | '_ \\ / _ \\ '__|   | |  | | . ` |\\___ \\ ",
		" | |  | | |_| | |_) |  __/ |      | |__| | |\\  |____) |",
		" |_|  |_|\\__, | .__/ \\___|_|      |_____/|_| \\_|_____/ ",
		"          __/ | |                                      ",
		"         |___/|_|      Standalone SmartDNS Controller",
	}, "\n")
}

// Sanitize strips control characters — including ANSI escape sequences, which
// a subscriber's name could otherwise smuggle in to repaint the operator's
// terminal (a classic injection: a name containing cursor-movement or color
// codes that the terminal executes on print). Everything below 0x20 except
// the harmless whitespace set goes, and DEL too; the ESC byte is what makes
// CSI/OSC sequences work, so removing it defuses the whole family.
func Sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			// dropped
		case unicode.IsControl(r):
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Truncate caps a display string at max characters with an ellipsis, for the
// table columns whose source (a subscriber note, a domain) has no bound.
func Truncate(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max-1]) + "…"
}
