package tui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// installDir is where every installer under scripts/ puts HyperDNS.
const installDir = "/opt/hyperdns"

// irreplaceableFiles are the files under installDir that a reinstall cannot bring back.
// data.db holds every subscriber, policy and quota counter; master.key is the AES-256-GCM
// key it is encrypted with, so a database without its key is permanently unreadable;
// config.json holds the API key and the server settings.
//
// certs/ is not in the list because a certificate can be reissued, and scripts/uninstall.sh
// (which handles the normal path) archives it anyway.
var irreplaceableFiles = []string{"config.json", "data.db", "master.key"}

// UninstallHyperDNS runs the uninstaller shipped alongside the binary, and falls back to
// removing the installation itself when that script is missing.
//
// The fallback used to be six unconditional exec calls ending in RemoveAll("/opt/hyperdns"):
// no backup, no mention of the database, and — the part that broke the host rather than
// merely the install — it left /etc/systemd/resolved.conf.d/hyperdns.conf in place. With
// that drop-in still setting DNSStubListener=no and HyperDNS no longer listening on 53,
// the machine had no resolver at all after "uninstalling".
func UninstallHyperDNS() {
	fmt.Println("\n=======================================================")
	fmt.Println(" 🗑️  COMPLETE HYPERDNS UNINSTALLATION")
	fmt.Println("=======================================================")
	fmt.Println("This will permanently remove:")
	fmt.Println("  1. HyperDNS service and systemd configuration")
	fmt.Println("  2. The system resolver override and the firewall rules it added")
	fmt.Println("  3. /usr/local/bin/hdns and everything in " + installDir)
	fmt.Println("")
	fmt.Printf("%sIncluding your data:%s\n", Yellow, Reset)
	fmt.Printf("%s  • data.db    — every subscriber, policy, and quota counter%s\n", Yellow, Reset)
	fmt.Printf("%s  • master.key — the key data.db is encrypted with; without it no%s\n", Yellow, Reset)
	fmt.Printf("%s                 backup of the database can ever be read again%s\n", Yellow, Reset)
	fmt.Printf("%s  • config.json — settings and API key%s\n", Yellow, Reset)
	fmt.Println("")
	fmt.Printf("%sA copy of those three is kept outside %s before anything is deleted.%s\n",
		Cyan, installDir, Reset)
	fmt.Print("\nAre you sure you want to completely uninstall HyperDNS? (y/N): ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Println("Uninstallation aborted.")
		return
	}
	choice := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if choice != "y" && choice != "yes" {
		fmt.Println("Uninstallation aborted.")
		return
	}

	uninstallerPath := filepath.Join(installDir, "scripts", "uninstall.sh")
	if _, err := os.Stat(uninstallerPath); err != nil {
		fallbackUninstall()
		return
	}

	// The script asks for confirmation again, and that second prompt is the authoritative
	// one: it knows the size of the database and the exact path of the archive it is about
	// to write, neither of which this menu can state.
	cmd := exec.Command("bash", uninstallerPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Printf("\n%s✗ The uninstaller exited with an error: %v%s\n", Red, err, Reset)
		fmt.Printf("%s  Run it directly to see why: sudo bash %s%s\n", Yellow, uninstallerPath, Reset)
		os.Exit(1)
	}
	os.Exit(0)
}

// fallbackUninstall removes the installation without scripts/uninstall.sh.
//
// It exists for installs whose bundle never carried the script, and it does the same work
// in the same order: keep the data first, then undo the changes made outside installDir,
// and only then delete the directory. If the backup cannot be written it stops instead of
// deleting — an uninstall that fails is recoverable, a database that is gone is not.
func fallbackUninstall() {
	fmt.Printf("\n%sscripts/uninstall.sh is not present; running the built-in cleanup.%s\n",
		Yellow, Reset)

	backupDir, err := backupIrreplaceableFiles()
	switch {
	case err != nil:
		fmt.Printf("%s✗ Could not back up your data: %v%s\n", Red, err, Reset)
		fmt.Printf("%s  Nothing has been deleted. Copy %s somewhere safe by hand, or%s\n",
			Red, installDir, Reset)
		fmt.Printf("%s  re-run the installer to restore scripts/uninstall.sh.%s\n", Red, Reset)
		return
	case backupDir != "":
		fmt.Printf("%s✓ Data copied to %s (mode 0700)%s\n", Green, backupDir, Reset)
	}

	fmt.Println("Stopping the service...")
	_ = exec.Command("systemctl", "stop", "hyperdns").Run()
	_ = exec.Command("systemctl", "disable", "hyperdns").Run()
	_ = os.Remove("/etc/systemd/system/hyperdns.service")
	_ = exec.Command("systemctl", "daemon-reload").Run()

	restoreSystemResolver()
	removeRecordedFirewallRules()

	// Only this installation's symlink. A regular file of the same name belongs to
	// something else, which is why install.sh creates the link with `ln -sf`.
	if info, statErr := os.Lstat("/usr/local/bin/hdns"); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove("/usr/local/bin/hdns")
		} else {
			fmt.Printf("%s! /usr/local/bin/hdns is not a symlink; left in place.%s\n", Yellow, Reset)
		}
	}

	if err := os.RemoveAll(installDir); err != nil {
		fmt.Printf("%s✗ Could not remove %s: %v%s\n", Red, installDir, err, Reset)
		os.Exit(1)
	}

	fmt.Printf("\n%s✓ HyperDNS has been completely removed.%s\n", Green, Reset)
	if backupDir != "" {
		fmt.Printf("%sYour data is in %s — keep master.key with the database.%s\n",
			Cyan, backupDir, Reset)
	}
	os.Exit(0)
}

// backupIrreplaceableFiles copies config.json, data.db and master.key out of installDir
// and returns the directory it wrote them to, or "" when there was nothing to copy.
func backupIrreplaceableFiles() (string, error) {
	present := make([]string, 0, len(irreplaceableFiles))
	for _, name := range irreplaceableFiles {
		if _, err := os.Stat(filepath.Join(installDir, name)); err == nil {
			present = append(present, name)
		}
	}
	if len(present) == 0 {
		return "", nil
	}

	// /root, matching scripts/uninstall.sh, so an operator who has used one knows where to
	// look after the other. TempDir is only a fallback for an image without /root.
	parent := "/root"
	if info, err := os.Stat(parent); err != nil || !info.IsDir() {
		parent = os.TempDir()
	}
	dest := filepath.Join(parent, "hyperdns-backup-"+time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	for _, name := range present {
		src := filepath.Join(installDir, name)
		if err := copyPrivateFile(src, filepath.Join(dest, name)); err != nil {
			return "", fmt.Errorf("copying %s: %w", name, err)
		}
	}
	return dest, nil
}

// copyPrivateFile copies one file at mode 0600 and flushes it to disk before returning.
//
// The sync is not ceremony: the caller deletes the original moments later, and a copy that
// is still only in the page cache when the machine loses power is a file that exists with
// nothing in it. Close is checked for the same reason — it is where a deferred write error
// surfaces, and for master.key the difference between a backup and an empty file named
// like one is total.
func copyPrivateFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// parseResolvMarker splits .resolv-backup into the kind of /etc/resolv.conf the installer
// found and the payload it saved.
//
// The format is the one scripts/install.sh writes: line one is "symlink", "file" or
// "absent", and everything after the first newline is the payload — a symlink target, or
// the entire previous resolv.conf. Two details are load-bearing. The split is on the
// *first* newline, so a multi-line body stays whole; and the body is returned verbatim,
// because it is written straight back to /etc/resolv.conf and a resolv.conf legitimately
// contains blank lines, comments and a trailing newline. Trimming it would silently
// reformat a file the operator never asked anyone to touch.
//
// It is a separate function so it can be tested at all: its caller replaces
// /etc/resolv.conf on a live host, and a parser that mis-reads its own marker is exactly
// how a machine ends up with no resolver after a successful "uninstall".
func parseResolvMarker(raw []byte) (kind, body string) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	// Cut splits on the first newline and reports whether it found one; when it does
	// not, `before` is the whole string and `after` is empty, which is precisely the
	// single-line "absent" marker case.
	kind, body, _ = strings.Cut(text, "\n")
	return strings.TrimSpace(kind), body
}

// restoreSystemResolver undoes step [2/6] of the installer: the resolved drop-in that turned
// the stub listener off to free port 53, and the /etc/resolv.conf that had to be replaced
// along with it.
//
// Removing the drop-in without restarting resolved leaves the host exactly as broken as
// before, and restoring resolv.conf matters even more: the installer replaced a symlink to
// resolved's generated file with a static "nameserver 1.1.1.1". Left in place, that file
// keeps answering after HyperDNS is gone, and no DHCP- or netplan-supplied nameserver ever
// takes effect again on that machine.
func restoreSystemResolver() {
	fmt.Println("Restoring the system DNS resolver...")
	_ = os.Remove("/etc/systemd/resolved.conf.d/hyperdns.conf")

	marker := filepath.Join(installDir, ".resolv-backup")
	if raw, err := os.ReadFile(marker); err != nil {
		fmt.Printf("%s! No resolver backup found; /etc/resolv.conf left as it is.%s\n", Yellow, Reset)
		fmt.Printf("%s  If DNS stops working: systemctl restart systemd-resolved%s\n", Yellow, Reset)
	} else {
		kind, body := parseResolvMarker(raw)

		switch kind {
		case "symlink":
			target := strings.TrimSpace(body)
			if target == "" {
				fmt.Printf("%s! Resolver marker names no symlink target; left as it is.%s\n", Yellow, Reset)
				break
			}
			_ = os.Remove("/etc/resolv.conf")
			if err := os.Symlink(target, "/etc/resolv.conf"); err != nil {
				fmt.Printf("%s! Could not recreate /etc/resolv.conf -> %s: %v%s\n", Yellow, target, err, Reset)
			} else {
				fmt.Printf("%s✓ /etc/resolv.conf restored as a symlink to %s%s\n", Green, target, Reset)
			}
		case "file":
			_ = os.Remove("/etc/resolv.conf")
			if err := os.WriteFile("/etc/resolv.conf", []byte(body), 0o644); err != nil {
				fmt.Printf("%s! Could not restore /etc/resolv.conf: %v%s\n", Yellow, err, Reset)
			} else {
				fmt.Printf("%s✓ /etc/resolv.conf restored from backup.%s\n", Green, Reset)
			}
		case "absent":
			_ = os.Remove("/etc/resolv.conf")
			fmt.Printf("%s✓ /etc/resolv.conf removed (there was none before install).%s\n", Green, Reset)
		default:
			fmt.Printf("%s! Resolver marker unreadable; /etc/resolv.conf left as it is.%s\n", Yellow, Reset)
		}
	}

	// Unconditional: this is what brings the 127.0.0.53 stub listener back now that nothing
	// is holding port 53. A host with resolved masked simply gets a failed command.
	if err := exec.Command("systemctl", "restart", "systemd-resolved").Run(); err == nil {
		fmt.Printf("%s✓ systemd-resolved restarted; the port 53 stub listener is back.%s\n", Green, Reset)
	}
}

// firewallRule is one line of .firewall-backup: the backend that opened a port, and the
// port spec exactly as install.sh recorded it.
type firewallRule struct {
	Backend string // "ufw" or "firewalld", never anything else
	Port    string // "53/udp", "443/tcp" — passed through verbatim
}

// parseFirewallMarker returns the rules recorded in .firewall-backup — and only the ones
// this uninstaller is willing to execute.
//
// Every line install.sh appends has the shape "<backend> <port>", and it only appends a
// line for a port it actually opened: a port that was already allowed is never recorded,
// which is what stops an uninstall from closing 443 on a host that was already serving on
// it. The parser is deliberately strict about that shape. A line with three fields, or one
// naming a backend nobody here knows, is dropped rather than guessed at, because the
// alternative is handing words out of a file to exec against a live firewall.
func parseFirewallMarker(raw []byte) []firewallRule {
	var rules []firewallRule
	// SplitSeq rather than Split: the lines are consumed once and never indexed, so
	// there is no reason to allocate a slice of every line in the file first.
	for line := range strings.SplitSeq(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "ufw", "firewalld":
			rules = append(rules, firewallRule{Backend: fields[0], Port: fields[1]})
		}
	}
	return rules
}

// firewallDeleteOutcome is what a delete command actually did, as opposed to what its exit
// status claims.
type firewallDeleteOutcome int

const (
	// firewallDeleteFailed: the tool is not installed, or refused the command outright.
	firewallDeleteFailed firewallDeleteOutcome = iota
	// firewallDeleteRemoved: a rule was really closed.
	firewallDeleteRemoved
	// firewallDeleteAlreadyGone: the rule was recorded at install time but is not there now,
	// so somebody removed it by hand in between.
	firewallDeleteAlreadyGone
)

// classifyFirewallDelete reads the outcome out of the command's output instead of its exit
// status, because neither tool reports "there was no such rule" as a failure:
//
//	ufw delete allow 9999                    → "Could not delete non-existent rule", exit 0
//	firewall-cmd --permanent --remove-port=… → "Warning: NOT_ENABLED: 9999:tcp",     exit 0
//
// Counting exit statuses therefore over-reports: a HyperDNS rule the operator had already
// deleted by hand would be counted again here, and the total is printed to them as a fact
// about their own firewall.
func classifyFirewallDelete(out []byte, err error) firewallDeleteOutcome {
	if err != nil {
		return firewallDeleteFailed
	}
	if bytes.Contains(out, []byte("non-existent")) || bytes.Contains(out, []byte("NOT_ENABLED")) {
		return firewallDeleteAlreadyGone
	}
	return firewallDeleteRemoved
}

// removeRecordedFirewallRules deletes the rules the installer recorded in .firewall-backup,
// and only those.
//
// The list is what install.sh actually opened, skipping ports that were already allowed, so
// nothing here can close 80, 443 or 8080 on a server that was serving something else on them
// before HyperDNS was installed.
func removeRecordedFirewallRules() {
	raw, err := os.ReadFile(filepath.Join(installDir, ".firewall-backup"))
	if err != nil {
		fmt.Printf("%s! No firewall marker found; rules left untouched. Review with%s\n", Yellow, Reset)
		fmt.Printf("%s    ufw status   (or)   firewall-cmd --list-ports%s\n", Yellow, Reset)
		return
	}

	removed, absent, firewalld := 0, 0, false
	for _, rule := range parseFirewallMarker(raw) {
		var out []byte
		var runErr error
		switch rule.Backend {
		case "ufw":
			out, runErr = exec.Command("ufw", "delete", "allow", rule.Port).CombinedOutput()
		case "firewalld":
			firewalld = true
			out, runErr = exec.Command("firewall-cmd", "--permanent", "--remove-port="+rule.Port).CombinedOutput()
		default:
			continue
		}
		switch classifyFirewallDelete(out, runErr) {
		case firewallDeleteRemoved:
			removed++
		case firewallDeleteAlreadyGone:
			absent++
		case firewallDeleteFailed:
			// Nothing was closed and nothing was there to close as far as this can tell;
			// counting it either way would be a guess.
		}
	}
	if firewalld {
		_ = exec.Command("firewall-cmd", "--reload").Run()
	}
	fmt.Printf("%s✓ %d firewall rule(s) removed; anything you added yourself was left alone.%s\n",
		Green, removed, Reset)
	if absent > 0 {
		fmt.Printf("%s  %d recorded rule(s) had already been removed by hand.%s\n", Yellow, absent, Reset)
	}
}
