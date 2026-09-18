package tui

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"hyperdns/internal/database"
)

// Changing the dashboard port from the console.
//
// This is the one settings change in this menu whose failure mode is losing the
// panel, so the checks in front of it are not decoration. Three facts about how the
// value travels decide what this file has to do:
//
//  1. The stored record beats config.json. main.go layers the settings in a fixed
//     order — built-in defaults, then applyConfigFile, then db.GetSetting("server")
//     — so writing the port to the database is effective and survives a restart
//     even though config.json still says 8080. That is why persisting is worth
//     doing at all.
//
//  2. The command line beats the stored record. `-web-port` is applied after the
//     database read, and scripts/hyperdns.service passes no such flag — so the
//     stored port does take effect in production, and the flag remains available as
//     the way back in if a change goes wrong. Both halves have to be said out loud,
//     because the second one is the lockout recovery path.
//
//  3. A failed web bind kills the service. In daemon mode main.go's startupFailure
//     is log.Fatalf, so a port that cannot be bound on the next start does not
//     degrade to "no panel" — it degrades to "no resolver either". Every collision
//     this file can see in advance is therefore an error, not a warning.
//
// And one fact about how the port is reached, which no amount of reading the Go
// code would reveal: scripts/install.sh opens a *fixed* firewall set —
// 53/udp 53/tcp 80/tcp 443/tcp 853/tcp 8080/tcp 8443/tcp — so a successful change
// to any other port produces a panel that binds perfectly and is unreachable from
// outside. The operator has to be told to open it.

var (
	// errPortEmpty is defensive: manageWebPort treats an empty line as "go back"
	// before it calls the validator, so reaching this means a different caller.
	errPortEmpty     = errors.New("no port entered")
	errPortSyntax    = errors.New("not a number")
	errPortRange     = errors.New("outside the 1-65535 range")
	errPortUnchanged = errors.New("already the current port")
	errPortInUse     = errors.New("port already claimed by another HyperDNS listener")
)

// portUse is one port this daemon already binds, or would bind if its service were
// switched on.
type portUse struct {
	port int
	live bool   // the owning service is enabled, so the collision is real today
	name string // what the operator would lose, in their words
}

// orDefault mirrors dns.NewServer's coercion of a zero port.
//
// This matters more than it looks. A 0 in DNSSettings does not mean "this listener
// is off" — NewServer replaces 0 with 53, 853 or 8443 and binds it anyway. Reading
// a stored 0 as "free" would let an operator move the panel onto the port that DoH
// is about to take, and the resulting bind failure is fatal in daemon mode.
func orDefault(port, fallback int) int {
	if port == 0 {
		return fallback
	}
	return port
}

// listenerPorts enumerates every port this process binds besides the panel.
//
// Both arguments may be nil, which is what a caller with no settings loaded looks
// like; the result is then simply shorter. The DNS trio is gated as a group because
// DNSSettings has a single Enabled flag covering all three listeners.
//
// The four extra game listeners were literals in sni.Start() until v2.2.0 and are
// settings fields now — an operator who points one of them at the panel port gets
// the same collision check every other listener already had.
func listenerPorts(dns *database.DNSSettings, sni *database.SNIProxySettings) []portUse {
	var out []portUse
	if dns != nil {
		out = append(out,
			portUse{orDefault(dns.Port, 53), dns.Enabled, "plain DNS (UDP and TCP)"},
			portUse{orDefault(dns.DoTPort, 853), dns.Enabled, "DNS-over-TLS"},
			portUse{orDefault(dns.DoHPort, 8443), dns.Enabled, "DNS-over-HTTPS"},
		)
	}
	if sni != nil {
		for _, p := range []portUse{
			{sni.HTTPSPort, sni.Enabled, "the HTTPS SNI relay"},
			{sni.HTTPPort, sni.Enabled, "the HTTP relay"},
			{sni.GameChatTLSPort, sni.Enabled, "the game chat TLS relay"},
			{sni.GameChatXMPPPort, sni.Enabled, "the game chat XMPP relay"},
			{sni.RiotRTMPort, sni.Enabled, "the Riot PVP.net relay"},
			{sni.RiotPatcherPort, sni.Enabled, "the Riot patcher relay"},
		} {
			// sni.Start() skips a non-positive port, so it is genuinely free.
			if p.port > 0 {
				out = append(out, p)
			}
		}
	}
	return out
}

// validateWebPort turns a typed line into a port to store, plus the warnings the
// operator has to read before it is stored.
//
// The split between an error and a warning is the whole design. An error is a
// change that would stop the daemon from starting, and there is no informed-consent
// path to that: in daemon mode a failed web bind is log.Fatalf, so it takes the
// resolver down with the panel, on the next restart, remotely. A warning is a change
// that will work and might still surprise — a port a disabled service will want back
// the day it is switched on, or a privileged port that depends on how the unit runs.
//
// The returned slice is ordered most-consequential first, because that is the order
// an operator reads in.
func validateWebPort(raw string, current int, dns *database.DNSSettings, sni *database.SNIProxySettings) (int, []string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil, errPortEmpty
	}

	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %q", errPortSyntax, raw)
	}
	if port < 1 || port > 65535 {
		return 0, nil, fmt.Errorf("%w: %d", errPortRange, port)
	}
	if port == current {
		return 0, nil, fmt.Errorf("%w: %d", errPortUnchanged, port)
	}

	var warnings []string
	for _, u := range listenerPorts(dns, sni) {
		if u.port != port {
			continue
		}
		if u.live {
			return 0, nil, fmt.Errorf("%w: %d is bound by %s", errPortInUse, port, u.name)
		}
		// The service is off today, so the bind succeeds. It is still a trap: the
		// operator who turns that service back on months from now gets a fatal
		// startup and no memory of this menu.
		warnings = append(warnings, fmt.Sprintf(
			"Port %d is the configured port for %s. That service is disabled, so the panel "+
				"can take it — but enabling it later will fail to start the daemon.", port, u.name))
	}

	// Below 1024 needs CAP_NET_BIND_SERVICE or root. The packaged unit runs as root,
	// so this usually works; a hardened unit or a manual run as an unprivileged user
	// is where it does not, and that failure is fatal in daemon mode.
	if port < 1024 {
		warnings = append(warnings, fmt.Sprintf(
			"Port %d is privileged (below 1024). The packaged systemd unit runs as root and "+
				"will bind it, but a run as an unprivileged user will not — and a failed panel "+
				"bind stops the whole daemon, resolver included.", port))
	}

	// The firewall note is unconditional except for the ports install.sh already
	// opened, because a change nobody can reach is the likeliest way this goes wrong.
	if !installerOpensPort(port) {
		warnings = append(warnings, fmt.Sprintf(
			"The installer opens a fixed firewall set (53, 80, 443, 853, 8080, 8443) and %d is "+
				"not in it. The panel will bind and still be unreachable until you open it.", port))
	}

	return port, warnings, nil
}

// installerOpensPort reports whether scripts/install.sh already opened this port.
//
// Kept as a list rather than a range check because it mirrors a concrete line in
// another file (install.sh:179) and drifts with it; a reader comparing the two
// should see the same numbers.
func installerOpensPort(port int) bool {
	switch port {
	case 53, 80, 443, 853, 8080, 8443:
		return true
	}
	return false
}

// probeBind answers the question the settings cannot: is this port free on this
// host, right now, including to processes HyperDNS knows nothing about?
//
// A validator built only on the settings structs sees collisions with our own
// listeners and nothing else. The common real case is different — an nginx, a
// Docker publish, another panel — and the consequence is identical, so the check
// has to be a real bind rather than a lookup. It is closed immediately; a listener
// that never accepted a connection frees its port at once.
func probeBind(bindHost string, port int) error {
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bindHost, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return ln.Close()
}

// manageWebPort stores a new dashboard port and tells the operator what is now true.
//
// The confirmation is y/N rather than manageAPIKey's typed word, and the difference
// is proportionate: rotating a key is instant and irreversible, while this takes
// effect on a restart the operator performs themselves, and the old port keeps
// serving until they do. What this needs instead is the four post-conditions printed
// at the end — the restart, the unchanged running port, the -web-port override that
// doubles as the way back in, and the firewall.
func manageWebPort(
	db *database.DB,
	settings *database.ServerSettings,
	dns *database.DNSSettings,
	sni *database.SNIProxySettings,
	s *bufio.Scanner,
) {
	// One snapshot, so every line below describes the same moment even if the
	// dashboard rewrites the advertised IP while this prompt is open.
	snap := settings.Snapshot()

	fmt.Printf("\n=== Dashboard Panel Port ===\n")
	fmt.Printf(" Current port: %s%d%s\n", Bold, snap.WebPort, Reset)
	fmt.Printf(" Dashboard:    http://%s:%d\n", snap.PublicIP, snap.WebPort)
	fmt.Printf(" Bind host:    %s\n", snap.BindHost)

	fmt.Printf("\n %sThe new port takes effect on the next start, not now.%s The listener is already\n", Yellow, Reset)
	fmt.Printf(" bound and cannot be moved, so this panel keeps answering on %d until you restart.\n", snap.WebPort)
	fmt.Print("\n Enter the new port (1-65535), or press [Enter] to go back: ")

	if !s.Scan() {
		return
	}
	raw := strings.TrimSpace(s.Text())
	if raw == "" {
		fmt.Println(" Left unchanged.")
		waitEnter(s)
		return
	}

	port, warnings, err := validateWebPort(raw, snap.WebPort, dns, sni)
	if err != nil {
		fmt.Printf("\n%s✗ %v%s\n", Red, err, Reset)
		if errors.Is(err, errPortInUse) {
			fmt.Printf(" Moving the panel onto a port this daemon already binds makes the next start\n")
			fmt.Printf(" fail — and in service mode that failure is fatal, so DNS stops too.\n")
		}
		fmt.Printf(" Nothing was changed; the panel is still on %d.\n", snap.WebPort)
		waitEnter(s)
		return
	}

	// Free according to our own settings is not the same as free on this host.
	if err := probeBind(snap.BindHost, port); err != nil {
		fmt.Printf("\n%s✗ Port %d cannot be bound on %s: %v%s\n", Red, port, snap.BindHost, err, Reset)
		fmt.Printf(" Something outside HyperDNS is holding it. Storing it anyway would leave the\n")
		fmt.Printf(" daemon unable to start, so nothing was changed.\n")
		waitEnter(s)
		return
	}

	for _, w := range warnings {
		fmt.Printf("\n %s! %s%s\n", Yellow, w, Reset)
	}

	fmt.Printf("\n Change the stored dashboard port from %s%d%s to %s%d%s? [y/N]: ",
		Bold, snap.WebPort, Reset, Bold, port, Reset)
	if !s.Scan() {
		return
	}
	if answer := strings.ToLower(strings.TrimSpace(s.Text())); answer != "y" && answer != "yes" {
		fmt.Println(" Left unchanged.")
		waitEnter(s)
		return
	}

	// PersistWebPort deliberately does not touch the running settings: the banner,
	// the subscriber portal URLs and the 1-click register links all read WebPort
	// directly, and every one of them would start advertising a port with nothing
	// behind it. Only the stored record moves.
	if err := settings.PersistWebPort(port, func(srv *database.ServerSettings) error {
		return db.SetSetting("server", srv)
	}); err != nil {
		fmt.Printf("\n%s✗ Could not save the new port: %v%s\n", Red, err, Reset)
		fmt.Printf(" The stored port is unchanged, so a restart still brings the panel up on %d.\n", snap.WebPort)
		waitEnter(s)
		return
	}

	fmt.Printf("\n%s✓ Stored. The panel moves to port %d on the next start.%s\n", Green, port, Reset)
	fmt.Printf("   New URL after the restart: http://%s:%d\n", snap.PublicIP, port)
	fmt.Printf("\n Before you restart:\n")
	if !installerOpensPort(port) {
		fmt.Printf("  %s1.%s Open the port in the firewall, or the panel will be unreachable:\n", Bold, Reset)
		fmt.Printf("       ufw allow %d/tcp\n", port)
		fmt.Printf("       firewall-cmd --permanent --add-port=%d/tcp && firewall-cmd --reload\n", port)
	} else {
		fmt.Printf("  %s1.%s Port %d is already open — the installer's firewall rules cover it.\n", Bold, Reset, port)
	}
	fmt.Printf("  %s2.%s Restart to apply: menu option [8], or systemctl restart hyperdns\n", Bold, Reset)
	fmt.Printf("  %s3.%s If the new port turns out to be wrong, start with -web-port %d on the\n", Bold, Reset, snap.WebPort)
	fmt.Printf("       command line. The flag overrides the stored value, and it is how you get\n")
	fmt.Printf("       back into a panel you have locked yourself out of.\n")
	waitEnter(s)
}
