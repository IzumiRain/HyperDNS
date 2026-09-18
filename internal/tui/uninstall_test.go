package tui

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The two markers parsed here are read on exactly one occasion: an uninstall, on a live
// host, as the last thing that happens before /opt/hyperdns is deleted. Nothing about that
// path can be exercised for real — it replaces /etc/resolv.conf and runs firewall commands
// as root — so the parsing is split out into pure functions and pinned here instead. A
// mis-read marker does not produce a wrong log line; it leaves a machine with no resolver,
// or closes a port that belonged to something else.
//
// backupIrreplaceableFiles is deliberately not tested: installDir is a constant, so calling
// it on a host that really has HyperDNS installed would copy the live data.db into /root as
// a side effect of `go test`. copyPrivateFile, the part that can actually lose the database,
// is tested below on its own.

// The Ubuntu default, and the case that matters most: /etc/resolv.conf is a symlink into
// resolved's generated file. If this comes back wrong the installer's static replacement
// stays behind, and no DHCP- or netplan-supplied nameserver ever takes effect again.
func TestParseResolvMarkerReadsASymlinkTarget(t *testing.T) {
	kind, body := parseResolvMarker([]byte("symlink\n../run/systemd/resolve/stub-resolv.conf\n"))

	if kind != "symlink" {
		t.Errorf("kind = %q, want \"symlink\"", kind)
	}
	// The caller trims the body for this kind — TrimSpace here mirrors it — so a trailing
	// newline is expected in the raw body and must not end up inside the target.
	if got := strings.TrimSpace(body); got != "../run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("target = %q", got)
	}
}

// A hand-written /etc/resolv.conf is restored byte for byte. Blank lines, comments and the
// trailing newline are the operator's file, not formatting this code may improve on — and
// the body is written straight back with os.WriteFile.
func TestParseResolvMarkerReturnsAFileBodyVerbatim(t *testing.T) {
	const payload = "# corporate resolver, do not edit\nnameserver 10.0.0.53\n\noptions edns0 trust-ad\nsearch corp.example\n"

	kind, body := parseResolvMarker([]byte("file\n" + payload))

	if kind != "file" {
		t.Errorf("kind = %q, want \"file\"", kind)
	}
	if body != payload {
		t.Errorf("body was altered:\n got %q\nwant %q", body, payload)
	}
}

// A marker that has been through a Windows editor, or any transfer that rewrote its line
// endings. The kind still has to match the switch in restoreSystemResolver, and no \r may
// survive into the symlink target: os.Symlink("../run/…conf\r") succeeds and produces a
// link to a path that does not exist, which is a host with no resolver and no error message.
func TestParseResolvMarkerToleratesCRLF(t *testing.T) {
	kind, body := parseResolvMarker([]byte("symlink\r\n../run/systemd/resolve/stub-resolv.conf\r\n"))

	if kind != "symlink" {
		t.Errorf("kind = %q, want \"symlink\"", kind)
	}
	if got := strings.TrimSpace(body); got != "../run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("target = %q; a surviving \\r would break the symlink", got)
	}
}

// "absent" carries no payload, and it is written by whichever shell wrote it last — with or
// without a trailing newline, occasionally with padding. Every spelling has to read as the
// same kind, because the branch it selects deletes /etc/resolv.conf.
func TestParseResolvMarkerReadsAKindWithNoBody(t *testing.T) {
	for _, raw := range []string{"absent", "absent\n", "absent\r\n", "  absent  \n"} {
		kind, body := parseResolvMarker([]byte(raw))

		if kind != "absent" {
			t.Errorf("parseResolvMarker(%q): kind = %q, want \"absent\"", raw, kind)
		}
		if strings.TrimSpace(body) != "" {
			t.Errorf("parseResolvMarker(%q): body = %q, want nothing", raw, body)
		}
	}
}

// Anything the installer did not write has to land in the default branch, which leaves
// /etc/resolv.conf alone. A truncated file, an empty one, a marker from a version that
// recorded something else — none of them may be rounded to "file" or "absent", because both
// of those branches open by deleting the resolver the machine is using at that moment.
func TestParseResolvMarkerLeavesUnknownKindsToTheDefaultBranch(t *testing.T) {
	for _, raw := range []string{"", "\n", "\r\n", "hardlink\n/etc/resolv.conf.orig\n", "file-v2\nnameserver 1.1.1.1\n"} {
		kind, _ := parseResolvMarker([]byte(raw))

		switch kind {
		case "symlink", "file", "absent":
			t.Errorf("parseResolvMarker(%q): kind = %q — that acts on a marker it does not understand", raw, kind)
		}
	}
}

// The kind is one this code acts on, but the payload is missing: a marker truncated after
// its first line, or one whose target was never appended. restoreSystemResolver checks for
// exactly this and keeps the current file. What it must not do is remove /etc/resolv.conf
// and then hand an empty string to os.Symlink, which leaves nothing behind at all.
func TestParseResolvMarkerReportsAnEmptySymlinkTarget(t *testing.T) {
	for _, raw := range []string{"symlink", "symlink\n", "symlink\n\n", "symlink\n   \n"} {
		kind, body := parseResolvMarker([]byte(raw))

		if kind != "symlink" {
			t.Fatalf("parseResolvMarker(%q): kind = %q", raw, kind)
		}
		if strings.TrimSpace(body) != "" {
			t.Errorf("parseResolvMarker(%q): target = %q, want empty so the caller's guard fires", raw, body)
		}
	}
}

// The marker a normal install leaves behind on a ufw host: one line per port install.sh
// opened itself, in the order it opened them. Every one of them has to come back — a port
// left open after an uninstall is a port HyperDNS asked for and nothing is listening on.
func TestParseFirewallMarkerReadsEveryRecordedPort(t *testing.T) {
	raw := []byte("ufw 53/udp\nufw 53/tcp\nufw 853/tcp\nufw 8080/tcp\nufw 443/tcp\n")

	rules := parseFirewallMarker(raw)

	want := []string{"53/udp", "53/tcp", "853/tcp", "8080/tcp", "443/tcp"}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(rules), len(want), rules)
	}
	for i, port := range want {
		if rules[i].Backend != "ufw" || rules[i].Port != port {
			t.Errorf("rule %d = %+v, want {ufw %s}", i, rules[i], port)
		}
	}
}

// A host that has run both backends over its life, with the padding, tabs, blank lines and
// CRLF a marker collects from being appended to by different scripts and copied around. The
// backend field decides which of two different commands is executed, so each port has to
// stay paired with the one that opened it.
func TestParseFirewallMarkerKeepsEachPortWithItsOwnBackend(t *testing.T) {
	raw := []byte("ufw 53/udp\r\n  firewalld 53/tcp  \nufw\t853/tcp\n\nfirewalld 8443/tcp\n")

	rules := parseFirewallMarker(raw)

	want := []firewallRule{
		{Backend: "ufw", Port: "53/udp"},
		{Backend: "firewalld", Port: "53/tcp"},
		{Backend: "ufw", Port: "853/tcp"},
		{Backend: "firewalld", Port: "8443/tcp"},
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(rules), len(want), rules)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, rules[i], want[i])
		}
	}
}

// Everything this parser lets through is handed to exec against a live firewall, so a line
// it does not recognise completely is dropped rather than repaired. The cases below are the
// ones a real file produces: a backend this uninstaller has no command for, a line whose
// port went missing, a line carrying an extra word, and the blank lines an appender leaves
// behind. "UFW" is in the list on purpose — the switch is case-sensitive, and accepting it
// would mean building a command out of a word nobody checked.
func TestParseFirewallMarkerDropsAnythingItDoesNotFullyRecognise(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"iptables 53/udp",
		"nft 53/tcp",
		"UFW 443/tcp",
		"ufw",
		"853/tcp",
		"ufw 8080/tcp extra",
		"ufw allow 80/tcp",
		"",
		"   ",
		"ufw 53/udp",
	}, "\n"))

	rules := parseFirewallMarker(raw)

	if len(rules) != 1 {
		t.Fatalf("got %d rules, want only the single well-formed line: %+v", len(rules), rules)
	}
	if rules[0] != (firewallRule{Backend: "ufw", Port: "53/udp"}) {
		t.Errorf("rule = %+v, want {ufw 53/udp}", rules[0])
	}
}

// No content at all: install.sh found every port already allowed and opened none, or the
// file was created and never appended to. removeRecordedFirewallRules then reports "0
// firewall rule(s) removed", which is the honest answer and leaves the firewall alone.
func TestParseFirewallMarkerReturnsNothingForAnEmptyFile(t *testing.T) {
	for _, raw := range []string{"", "\n", "\n\n\r\n   \n"} {
		if rules := parseFirewallMarker([]byte(raw)); len(rules) != 0 {
			t.Errorf("parseFirewallMarker(%q) = %+v, want no rules", raw, rules)
		}
	}
}

// The number this classifier feeds is printed to the operator as a fact about their own
// firewall, and neither tool reports "there was no such rule" as a failure — both print a
// notice and exit 0. The outputs below are verbatim from ufw 0.36.2 and firewalld on Ubuntu
// 24.04; counting exit statuses instead would report a rule the operator had already deleted
// by hand as one the uninstaller closed.
func TestClassifyFirewallDeleteReadsTheOutputNotTheExitStatus(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
		want firewallDeleteOutcome
	}{
		{
			name: "ufw closed the rule",
			out:  "Rule deleted\nRule deleted (v6)\n",
			want: firewallDeleteRemoved,
		},
		{
			name: "ufw had nothing to close",
			out:  "Could not delete non-existent rule\nCould not delete non-existent rule (v6)\n",
			want: firewallDeleteAlreadyGone,
		},
		{
			name: "firewalld closed the port",
			out:  "success\n",
			want: firewallDeleteRemoved,
		},
		{
			name: "firewalld had nothing to close",
			out:  "Warning: NOT_ENABLED: 8393:tcp\nsuccess\n",
			want: firewallDeleteAlreadyGone,
		},
		{
			// The tool is not installed at all. Nothing was closed, and nothing can be said
			// about whether a rule was there, so this must count as neither.
			name: "command could not run",
			out:  "",
			err:  exec.ErrNotFound,
			want: firewallDeleteFailed,
		},
		{
			// A refusal still carries no information about the rule's existence.
			name: "command ran and failed",
			out:  "ERROR: You need to be root to run this script\n",
			err:  errors.New("exit status 1"),
			want: firewallDeleteFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyFirewallDelete([]byte(tt.out), tt.err); got != tt.want {
				t.Errorf("classifyFirewallDelete(%q, %v) = %d, want %d", tt.out, tt.err, got, tt.want)
			}
		})
	}
}

// master.key is 32 bytes of key material, and this function copies it on the way to the
// directory it lives in being deleted. Byte-for-byte is the entire contract: a truncated or
// re-encoded copy is indistinguishable from a good one until the day someone tries to open
// the database with it, by which time the original is long gone.
func TestCopyPrivateFileCopiesBytesExactly(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "master.key")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7) // spans 0x00 and bytes above 0x7f, which no text-mode path survives
	}
	if err := os.WriteFile(src, key, 0o600); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(dir, "backup", "master.key")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyPrivateFile(src, dst); err != nil {
		t.Fatalf("copyPrivateFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Errorf("copy differs:\n got %d bytes %x\nwant %d bytes %x", len(got), got, len(key), key)
	}
}

// The backup lands in /root, which is only as private as the files inside it. data.db and
// master.key leave the install at mode 600 and have to arrive that way, so that a backup is
// not a world-readable snapshot of every subscriber, quota and API key. The source here is
// deliberately 0644: the mode comes from how the copy is created, not from what it copied.
func TestCopyPrivateFileWritesMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not carry Unix permission bits; the installers this backs up are Linux-only")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "data.db")
	if err := os.WriteFile(src, []byte("bbolt"), 0o644); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(dir, "data.db.copy")
	if err := copyPrivateFile(src, dst); err != nil {
		t.Fatalf("copyPrivateFile: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %#o, want 0600", perm)
	}
}

// A destination can already exist and be longer than what is about to replace it — two
// uninstalls inside the same second share one timestamped directory. O_TRUNC is what keeps
// the tail of the older file from being left behind: 32 bytes of key followed by the last
// 200 bytes of a previous one is not a key, and nothing about the file would look wrong.
func TestCopyPrivateFileTruncatesAnExistingDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(dst, []byte("a much longer file from a previous run"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := copyPrivateFile(src, dst); err != nil {
		t.Fatalf("copyPrivateFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("destination = %q, want %q with no tail from the old file", got, "new")
	}
}

// An error here stops the whole uninstall before anything is deleted, which is the only
// reason the return value is checked at all. Both failures are reachable on a real host: a
// file that disappeared between the Stat that listed it and the copy, and a backup directory
// that could not be created.
func TestCopyPrivateFileReportsFailures(t *testing.T) {
	dir := t.TempDir()

	if err := copyPrivateFile(filepath.Join(dir, "not-there"), filepath.Join(dir, "dst")); err == nil {
		t.Error("copying a missing source returned no error")
	}

	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyPrivateFile(src, filepath.Join(dir, "no-such-dir", "dst")); err == nil {
		t.Error("copying into a directory that does not exist returned no error")
	}
}
