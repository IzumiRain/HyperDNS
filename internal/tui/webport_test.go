package tui

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"hyperdns/internal/database"
)

// validateWebPort is the only thing standing between a typed line and a stored
// value that stops the daemon from starting. In daemon mode main.go's
// startupFailure is log.Fatalf, so a panel port that cannot be bound on the next
// start does not degrade to "no dashboard" — it takes the resolver with it, on a
// remote box, at the moment the operator was told to restart. Everything below is
// a case that would have produced exactly that.

// liveDNS and liveSNI are the shipped defaults with their services switched on:
// DNS 53/853/8443, relay 80/443 plus the four hardcoded game ports.
func liveDNS() *database.DNSSettings {
	return &database.DNSSettings{Enabled: true, Port: 53, DoTPort: 853, DoHPort: 8443}
}

func liveSNI() *database.SNIProxySettings {
	return &database.SNIProxySettings{Enabled: true, HTTPPort: 80, HTTPSPort: 443,
		GameChatTLSPort: 5223, GameChatXMPPPort: 5222, RiotRTMPort: 2099, RiotPatcherPort: 8393}
}

func TestValidateWebPortRejectsWhatWouldBreakTheDaemon(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
	}{
		// An empty line reaches the validator only from a caller that forgot to
		// treat it as "go back", so it is an error rather than a silent zero.
		{"empty", "", errPortEmpty},
		{"whitespace only", "   ", errPortEmpty},
		{"not a number", "eight-oh-eight-oh", errPortSyntax},
		// The one that reads like a port and is not. Atoi refuses it, and the
		// alternative — Sscanf, which the client prompts in this package use — would
		// silently return 9090 and store it.
		{"trailing junk", "9090/tcp", errPortSyntax},
		{"decimal", "9090.5", errPortSyntax},
		{"zero", "0", errPortRange},
		{"negative", "-1", errPortRange},
		{"above the 16-bit ceiling", "65536", errPortRange},
		{"far above", "999999", errPortRange},
		// Storing the port already in force would print a restart notice for a
		// change that does not exist.
		{"unchanged", "8080", errPortUnchanged},

		// Collisions with a listener this daemon is currently binding. Each of these
		// saves cleanly and kills the service on the next restart.
		{"plain DNS", "53", errPortInUse},
		{"DNS-over-TLS", "853", errPortInUse},
		{"DNS-over-HTTPS", "8443", errPortInUse},
		{"HTTP relay", "80", errPortInUse},
		{"HTTPS relay", "443", errPortInUse},
		// The four the settings structs never mention. sni.Start() binds them from
		// literals, so nothing an operator can read tells them these are taken —
		// and the relay starts before the web server, so the panel is the bind that
		// fails.
		{"game chat TLS", "5223", errPortInUse},
		{"game chat XMPP", "5222", errPortInUse},
		{"Riot PVP.net", "2099", errPortInUse},
		{"Riot patcher", "8393", errPortInUse},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			port, warnings, err := validateWebPort(c.raw, 8080, liveDNS(), liveSNI())
			if !errors.Is(err, c.want) {
				t.Fatalf("validateWebPort(%q) error = %v, want %v", c.raw, err, c.want)
			}
			if port != 0 {
				t.Errorf("a rejected input returned port %d, want 0 — a caller that ignores "+
					"the error would store it", port)
			}
			if warnings != nil {
				t.Errorf("a rejected input returned warnings %v; the operator should get the "+
					"refusal, not advice about a change that is not happening", warnings)
			}
		})
	}
}

// A zero in DNSSettings does not mean "off". dns.NewServer replaces 0 with 53, 853
// or 8443 and binds it anyway, so a validator that reads a stored 0 as "free" hands
// the panel a port DoH is about to take.
func TestValidateWebPortHonoursTheZeroPortDefaults(t *testing.T) {
	zeroed := &database.DNSSettings{Enabled: true} // Port, DoTPort, DoHPort all 0

	for _, port := range []int{53, 853, 8443} {
		raw := strconv.Itoa(port)
		if _, _, err := validateWebPort(raw, 8080, zeroed, nil); !errors.Is(err, errPortInUse) {
			t.Errorf("validateWebPort(%q) with zeroed DNS ports = %v, want errPortInUse. "+
				"NewServer coerces a stored 0 to this port and binds it.", raw, err)
		}
	}
}

// A disabled service must not block the change — it is not binding anything — but
// it must not pass silently either. The operator who re-enables it months later
// gets a fatal startup and no memory of this menu.
func TestValidateWebPortWarnsOnADisabledService(t *testing.T) {
	off := &database.DNSSettings{Enabled: false, Port: 53, DoTPort: 853, DoHPort: 8443}
	offSNI := &database.SNIProxySettings{Enabled: false, HTTPPort: 80, HTTPSPort: 443,
		GameChatTLSPort: 5223, GameChatXMPPPort: 5222, RiotRTMPort: 2099, RiotPatcherPort: 8393}

	port, warnings, err := validateWebPort("8443", 8080, off, offSNI)
	if err != nil {
		t.Fatalf("validateWebPort on a disabled listener's port = %v, want it allowed", err)
	}
	if port != 8443 {
		t.Errorf("port = %d, want 8443", port)
	}
	if len(warnings) == 0 {
		t.Fatal("no warning for a port a disabled service is configured to bind")
	}
	if !strings.Contains(strings.Join(warnings, " "), "DNS-over-HTTPS") {
		t.Errorf("the warnings %v do not name DNS-over-HTTPS, so they do not tell the operator "+
			"which service will fail to start", warnings)
	}
}

// A non-positive SNI port is skipped by sni.Start(), so it is genuinely free and
// must not be reported as a collision — otherwise turning the relay's HTTP listener
// off would make its old port permanently unusable for the panel.
func TestValidateWebPortIgnoresNonPositiveRelayPorts(t *testing.T) {
	sni := &database.SNIProxySettings{Enabled: true, HTTPPort: 0, HTTPSPort: 443}

	if _, _, err := validateWebPort("0", 8080, nil, sni); !errors.Is(err, errPortRange) {
		t.Errorf("validateWebPort(\"0\") = %v, want errPortRange rather than a collision with "+
			"the disabled HTTP relay", err)
	}
	// And the enabled one on the same struct still collides.
	if _, _, err := validateWebPort("443", 8080, nil, sni); !errors.Is(err, errPortInUse) {
		t.Errorf("validateWebPort(\"443\") = %v, want errPortInUse", err)
	}
}

func TestValidateWebPortWarnsAboutPrivilegedPortsAndTheFirewall(t *testing.T) {
	// 1024 is the first unprivileged port and is in no listener list, so the only
	// warning it earns is the firewall one.
	port, warnings, err := validateWebPort("1024", 8080, liveDNS(), liveSNI())
	if err != nil || port != 1024 {
		t.Fatalf("validateWebPort(\"1024\") = %d, %v; want it accepted", port, err)
	}
	joined := strings.Join(warnings, " ")
	if strings.Contains(joined, "privileged") {
		t.Errorf("1024 was called privileged: %v", warnings)
	}
	if !strings.Contains(joined, "firewall") {
		t.Errorf("no firewall warning for 1024: %v. install.sh opens a fixed set and 1024 is "+
			"not in it, so the panel would bind and be unreachable.", warnings)
	}

	// 1023 is the last privileged one. Both warnings apply.
	_, warnings, err = validateWebPort("1023", 8080, liveDNS(), liveSNI())
	if err != nil {
		t.Fatalf("validateWebPort(\"1023\") = %v, want it allowed with a warning", err)
	}
	joined = strings.Join(warnings, " ")
	if !strings.Contains(joined, "privileged") {
		t.Errorf("no privileged-port warning for 1023: %v", warnings)
	}
	if !strings.Contains(joined, "firewall") {
		t.Errorf("no firewall warning for 1023: %v", warnings)
	}
}

// The ports install.sh already opened are the only ones that need no firewall
// change, and saying so matters: an operator told to open a port that is already
// open learns to ignore the advice.
func TestValidateWebPortSkipsTheFirewallNoteForAlreadyOpenPorts(t *testing.T) {
	// Every port in the installer's set except the panel's own is bound by some
	// listener above, so the only way to reach this branch with services enabled is
	// with them off.
	_, warnings, err := validateWebPort("8443", 8080,
		&database.DNSSettings{Enabled: false, DoHPort: 8443}, nil)
	if err != nil {
		t.Fatalf("validateWebPort(\"8443\") = %v", err)
	}
	if joined := strings.Join(warnings, " "); strings.Contains(joined, "firewall") {
		t.Errorf("8443 earned a firewall warning: %v. install.sh:179 already opens 8443/tcp.", warnings)
	}
}

func TestValidateWebPortAcceptsAPlainHighPort(t *testing.T) {
	port, warnings, err := validateWebPort("9090", 8080, liveDNS(), liveSNI())
	if err != nil {
		t.Fatalf("validateWebPort(\"9090\") = %v, want it accepted", err)
	}
	if port != 9090 {
		t.Errorf("port = %d, want 9090", port)
	}
	// One warning, the firewall. Anything more means a check fired that should not
	// have, and warning fatigue is what makes the firewall line get skipped.
	if len(warnings) != 1 || !strings.Contains(warnings[0], "firewall") {
		t.Errorf("warnings = %v, want exactly the firewall note", warnings)
	}
}

// Surrounding whitespace is what a paste produces, and refusing it would send the
// operator hunting for a syntax problem that is not there.
func TestValidateWebPortTrimsItsInput(t *testing.T) {
	port, _, err := validateWebPort("  9090\t", 8080, nil, nil)
	if err != nil || port != 9090 {
		t.Errorf("validateWebPort(\"  9090\\t\") = %d, %v; want 9090, nil", port, err)
	}
}

// Nil settings are a caller with nothing loaded, not a reason to panic — the port
// check simply sees fewer listeners.
func TestValidateWebPortToleratesNilSettings(t *testing.T) {
	port, _, err := validateWebPort("53", 8080, nil, nil)
	if err != nil {
		t.Fatalf("validateWebPort with nil settings = %v", err)
	}
	if port != 53 {
		t.Errorf("port = %d, want 53", port)
	}
}

// probeBind is the check the settings structs cannot make: a port held by nginx, a
// Docker publish, or another panel looks free to listenerPorts and is not, and the
// consequence is the same fatal start.
func TestProbeBindReportsAHeldPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback listener in this environment: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if err := probeBind("127.0.0.1", port); err == nil {
		t.Errorf("probeBind reported port %d free while this test holds it — storing it would "+
			"leave the daemon unable to start", port)
	}
}

// And the other half: a free port must come back free, or the option refuses every
// change. The probe also has to release what it took, so a second probe of the same
// port has to succeed.
func TestProbeBindReleasesWhatItTakes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback listener in this environment: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // now known-free, and nobody else is racing for it

	if err := probeBind("127.0.0.1", port); err != nil {
		t.Fatalf("probeBind(%d) on a free port = %v", port, err)
	}
	if err := probeBind("127.0.0.1", port); err != nil {
		t.Errorf("the second probeBind(%d) = %v — the first one did not release the port, so "+
			"the option would reject a port it had just tested", port, err)
	}
}

// An empty bind host is what a settings record written before BindHost existed
// looks like, and net.Listen on ":<port>" is not the same address family question
// as "0.0.0.0:<port>". probeBind applies the same coercion the DNS and SNI servers
// apply, so the probe tests the address the daemon will actually bind.
func TestProbeBindCoercesAnEmptyHost(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot bind a wildcard listener in this environment: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if err := probeBind("", port); err == nil {
		t.Errorf("probeBind(\"\", %d) reported free while a wildcard listener holds it", port)
	}
}
