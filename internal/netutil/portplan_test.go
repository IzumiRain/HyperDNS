package netutil

// Regression test for Mantis v2.2.0 B-2: the panel-port validator must know
// about the HTTP→HTTPS redirect listener. Without it an operator could move
// the panel onto the port the redirect binds — the collision only surfaced as
// a fatal startup in service mode, the exact failure the validator exists to
// prevent.

import (
	"errors"
	"testing"

	"hyperdns/internal/database"
)

func TestListenerPortsIncludesRedirectPort(t *testing.T) {
	tls := &database.TLSSettings{RedirectPort: 80, PanelHTTPS: true}
	ports := ListenerPorts(nil, nil, tls)
	if len(ports) != 1 {
		t.Fatalf("ListenerPorts returned %d entries, want 1", len(ports))
	}
	if ports[0].Port != 80 || !ports[0].Live {
		t.Fatalf("redirect entry = %+v, want port 80 live", ports[0])
	}

	// No redirect configured (0) and no TLS settings: nothing extra listed.
	if got := ListenerPorts(nil, nil, nil); len(got) != 0 {
		t.Fatalf("nil TLS settings produced %d entries, want 0", len(got))
	}
	if got := ListenerPorts(nil, nil, &database.TLSSettings{RedirectPort: 0, PanelHTTPS: true}); len(got) != 0 {
		t.Fatalf("RedirectPort 0 produced %d entries, want 0", len(got))
	}
}

func TestValidatePortRefusesTheRedirectListenerPort(t *testing.T) {
	tls := &database.TLSSettings{RedirectPort: 80, PanelHTTPS: true}
	_, _, err := ValidatePort("80", 443, nil, nil, tls)
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("ValidatePort onto a live redirect port = %v, want ErrPortInUse", err)
	}

	// Redirect configured but the panel serves plain HTTP: the listener is
	// not bound today, so a warning is the right answer, not an error.
	tls.PanelHTTPS = false
	port, warnings, err := ValidatePort("80", 443, nil, nil, tls)
	if err != nil {
		t.Fatalf("ValidatePort onto an idle redirect port = %v, want nil", err)
	}
	if port != 80 || len(warnings) == 0 {
		t.Fatalf("port=%d warnings=%d, want port 80 with at least one warning", port, len(warnings))
	}
}
