// Package netutil's portplan: shared listener-port collision planning.
//
// The v2.1 port validator lived inside the (then-dead) TUI manager, and the
// live control op that actually persists a port change checked only
// 1..65535. A port the daemon itself binds on the next start therefore
// sailed through as "valid", and the operator discovered the collision as a
// fatal startup — the resolver dying with the panel. v2.2.0 lifts the logic
// here so every writer of a port setting (control socket, dashboard, TUI)
// enforces the same rules.
package netutil

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"hyperdns/internal/database"
)

var (
	ErrPortEmpty     = errors.New("no port entered")
	ErrPortSyntax    = errors.New("not a number")
	ErrPortRange     = errors.New("outside the 1-65535 range")
	ErrPortUnchanged = errors.New("already the current port")
	ErrPortInUse     = errors.New("port already claimed by another HyperDNS listener")
)

// PortUse is one port this daemon already binds, or would bind if its
// service were switched on.
type PortUse struct {
	Port int
	Live bool   // the owning service is enabled, so the collision is real today
	Name string // what the operator would lose, in their words
}

// orDefault mirrors dns.NewServer's coercion of a zero port: a 0 in
// DNSSettings does not mean "off" — NewServer replaces it with 53, 853 or
// 8443 and binds it anyway. Reading a stored 0 as "free" would let an
// operator move the panel onto the port DoH is about to take.
func orDefault(port, fallback int) int {
	if port == 0 {
		return fallback
	}
	return port
}

// ListenerPorts enumerates every port this process binds besides the panel.
// Any argument may be nil (a caller with no settings loaded); the result is
// then simply shorter. The DNS trio is gated as a group because DNSSettings
// has one Enabled flag for all three listeners; each SNI listener is gated
// individually because v2.2.0 made the four game ports settings where 0
// disables one. The redirect listener is the v2.2.0 addition: it binds only
// when the panel serves HTTPS, and without it an operator could move the
// panel onto a port the redirect would take at the next boot — a fatal
// collision in service mode, discovered as a daemon that no longer starts.
func ListenerPorts(dns *database.DNSSettings, sni *database.SNIProxySettings, tls *database.TLSSettings) []PortUse {
	var out []PortUse
	if dns != nil {
		out = append(out,
			PortUse{orDefault(dns.Port, 53), dns.Enabled, "plain DNS (UDP and TCP)"},
			PortUse{orDefault(dns.DoTPort, 853), dns.Enabled, "DNS-over-TLS"},
			PortUse{orDefault(dns.DoHPort, 8443), dns.Enabled, "DNS-over-HTTPS"},
		)
	}
	if sni != nil {
		for _, p := range []PortUse{
			{sni.HTTPSPort, sni.Enabled, "the HTTPS SNI relay"},
			{sni.HTTPPort, sni.Enabled, "the HTTP relay"},
			{sni.GameChatTLSPort, sni.Enabled, "the game chat TLS relay"},
			{sni.GameChatXMPPPort, sni.Enabled, "the game chat XMPP relay"},
			{sni.RiotRTMPort, sni.Enabled, "the Riot PVP.net relay"},
			{sni.RiotPatcherPort, sni.Enabled, "the Riot patcher relay"},
		} {
			// sni.Start() skips a non-positive port, so it is genuinely free.
			if p.Port > 0 {
				out = append(out, p)
			}
		}
	}
	if tls != nil && tls.RedirectPort > 0 {
		out = append(out, PortUse{tls.RedirectPort, tls.PanelHTTPS, "the HTTP→HTTPS redirect listener"})
	}
	return out
}

// ValidatePort turns a typed line into a port to store, plus the warnings the
// operator has to read before it is stored.
//
// The split between an error and a warning is the whole design. An error is a
// change that would stop the daemon from starting (a port another HyperDNS
// listener binds is fatal in service mode — log.Fatalf takes the resolver
// down with the panel). A warning is a change that will work and might still
// surprise. The returned slice is ordered most-consequential first.
func ValidatePort(raw string, current int, dns *database.DNSSettings, sni *database.SNIProxySettings, tls *database.TLSSettings) (int, []string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil, ErrPortEmpty
	}

	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %q", ErrPortSyntax, raw)
	}
	if port < 1 || port > 65535 {
		return 0, nil, fmt.Errorf("%w: %d", ErrPortRange, port)
	}
	if port == current {
		return 0, nil, fmt.Errorf("%w: %d", ErrPortUnchanged, port)
	}

	var warnings []string
	for _, u := range ListenerPorts(dns, sni, tls) {
		if u.Port != port {
			continue
		}
		if u.Live {
			return 0, nil, fmt.Errorf("%w: %d is bound by %s", ErrPortInUse, port, u.Name)
		}
		warnings = append(warnings, fmt.Sprintf(
			"Port %d is the configured port for %s. That service is disabled, so the panel "+
				"can take it — but enabling it later will fail to start the daemon.", port, u.Name))
	}

	if port < 1024 {
		warnings = append(warnings, fmt.Sprintf(
			"Port %d is privileged (below 1024). The packaged systemd unit runs as root and "+
				"will bind it, but a run as an unprivileged user will not — and a failed panel "+
				"bind stops the whole daemon, resolver included.", port))
	}

	if !InstallerOpensPort(port) {
		warnings = append(warnings, fmt.Sprintf(
			"The installer opens a fixed firewall set and %d is not in it. The panel will bind "+
				"and still be unreachable until you open it.", port))
	}

	return port, warnings, nil
}

// InstallerOpensPort reports whether the installers already opened this port.
// Kept as a list because it mirrors a concrete firewall line in the
// installers and drifts with them.
func InstallerOpensPort(port int) bool {
	switch port {
	case 53, 80, 443, 853, 8080, 8443:
		return true
	}
	return false
}

// ProbeBind answers the question the settings cannot: is this port free on
// this host, right now, including to processes HyperDNS knows nothing about?
// A validator built only on the settings structs sees collisions with our own
// listeners and nothing else — the common real case is an nginx, a Docker
// publish, another panel. The listener is closed immediately; one that never
// accepted frees its port at once.
func ProbeBind(bindHost string, port int) error {
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bindHost, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return ln.Close()
}
