// `hdns status` — a no-database status report.
//
// This command is dispatched before storage initialization, so it can inspect a
// running daemon without reading master.key or competing for bbolt ownership.
// It assembles the report from the config file, live listener probes, a real DNS
// query, the certificate on disk, and systemd for the unit state.
package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"

	"hyperdns/internal/database"
	"hyperdns/internal/version"
)

// runStatusCommand prints the report and returns an error only when something
// prevented the report from being assembled at all — an unreachable config is
// not an error, it just means the config section says so.
func runStatusCommand(configPath string, out io.Writer) error {
	if out == nil {
		out = io.Discard
	}
	fmt.Fprintf(out, " HyperDNS %s\n", version.Short())
	fmt.Fprintln(out, strings.Repeat("─", 62))

	// 1. Service state (systemd only; the installers always create the unit).
	if runtime.GOOS != "windows" {
		if commandOutput, err := exec.Command("systemctl", "is-active", "hyperdns").Output(); err == nil {
			state := strings.TrimSpace(string(commandOutput))
			if state == "active" {
				fmt.Fprintln(out, " Service        : active (systemd)")
			} else {
				fmt.Fprintf(out, " Service        : %s\n", state)
			}
		} else {
			fmt.Fprintln(out, " Service        : systemd unit not found (manual run?)")
		}
	}

	// 2. Configuration as the daemon would resolve it: defaults, then the
	// file's overrides. The database is deliberately not consulted — it is
	// the thing this command must not need.
	server := &database.ServerSettings{
		PublicIP:      "127.0.0.1",
		BindHost:      "0.0.0.0",
		WebPort:       8080,
		AdminUsername: "admin",
		APIBind:       "127.0.0.1",
	}
	dnsCfg := &database.DNSSettings{
		Enabled: true,
		Port:    53,
		DoTPort: 853,
		DoHPort: 8443,
	}
	sni := &database.SNIProxySettings{Enabled: true, HTTPPort: 80, HTTPSPort: 443}
	tlsCfg := &database.TLSSettings{CertPath: "certs/cert.pem", KeyPath: "certs/key.pem"}
	if _, err := os.Stat(configPath); err == nil {
		applyConfigFile(configPath, server, dnsCfg, sni, tlsCfg)
		fmt.Fprintf(out, " Config         : %s\n", configPath)
	} else {
		fmt.Fprintf(out, " Config         : %s not found — built-in defaults\n", configPath)
	}

	// 3. Live listeners. A TCP connect is the honest probe: it answers "is
	// something accepting here right now" whether the process is this
	// binary, systemd-managed, or something else entirely.
	probe := func(name string, port int) {
		enabled := port != 0
		if !enabled {
			fmt.Fprintf(out, " %-14s : disabled\n", name+":")
			return
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), time.Second)
		if err != nil {
			fmt.Fprintf(out, " %-14s : port %-5d NOT answering\n", name+":", port)
			return
		}
		_ = conn.Close()
		fmt.Fprintf(out, " %-14s : port %-5d listening\n", name+":", port)
	}
	if dnsCfg.Enabled {
		probe("DNS (tcp)", dnsCfg.Port)
	} else {
		fmt.Fprintln(out, " DNS (tcp)      : disabled by config")
	}
	probe("DoT (tls)", dnsCfg.DoTPort)
	probe("Panel/DoH (tls)", dnsCfg.DoHPort)
	probe("Panel (web)", server.WebPort)
	if sni.Enabled {
		probe("SNI relay http", sni.HTTPPort)
		probe("SNI relay https", sni.HTTPSPort)
	}

	// 4. One real DNS query through the resolver itself, so the report shows
	// the service works rather than merely that a port is open.
	if dnsCfg.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		c := new(dns.Client)
		c.Timeout = 3 * time.Second
		start := time.Now()
		reply, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort("127.0.0.1", fmt.Sprint(dnsCfg.Port)))
		if err != nil {
			fmt.Fprintf(out, " DNS query      : FAILED (%v)\n", err)
		} else {
			status := "no answer"
			if reply.Rcode == dns.RcodeSuccess {
				status = "NOERROR"
			} else if reply.Rcode == dns.RcodeNameError {
				status = "NXDOMAIN"
			}
			fmt.Fprintf(out, " DNS query      : OK — example.com A → %s in %dms\n", status, time.Since(start).Milliseconds())
		}
	}

	// 5. The panel certificate, parsed rather than shelled out to openssl.
	domain := tlsCfg.GetDomain()
	fmt.Fprintf(out, " Panel domain   : %s\n", orNone(domain))
	certPath := resolveDataPath(tlsCfg.CertPath)
	if leaf, err := readCertLeaf(certPath); err != nil {
		fmt.Fprintf(out, " Certificate    : %s unreadable (%v)\n", certPath, err)
	} else {
		selfSigned := string(leaf.RawIssuer) == string(leaf.RawSubject)
		kind := "CA-signed"
		if selfSigned {
			kind = "SELF-SIGNED (browsers will refuse it)"
		}
		fmt.Fprintf(out, " Certificate    : %s — %s, expires %s\n", certPath, kind, leaf.NotAfter.UTC().Format("2006-01-02"))
		for _, n := range leaf.DNSNames {
			if n == domain {
				fmt.Fprintf(out, "                  covers configured domain %q\n", domain)
				break
			}
		}
	}

	// 6. Where the operator logs in. The admin path lives in the database,
	// which this command does not open; the startup banner records it in the
	// journal, so on a systemd box that is where it comes from.
	if runtime.GOOS != "windows" {
		if journalOutput, err := exec.Command("journalctl", "-u", "hyperdns", "--no-pager", "-b", "-n", "400").Output(); err == nil {
			for _, line := range strings.Split(string(journalOutput), "\n") {
				if i := strings.Index(line, "/dash/"); i >= 16 {
					ap := line[i-16 : i]
					if _, err := hex.DecodeString(ap); err == nil {
						scheme := "http"
						if domain != "" {
							scheme = "https"
						}
						fmt.Fprintf(out, " Dashboard URL  : %s://%s:%d/%s/dash/\n", scheme, displayHost(server.GetPublicIP()), server.WebPort, ap)
						break
					}
				}
			}
		}
	}

	fmt.Fprintln(out, strings.Repeat("─", 62))
	fmt.Fprintln(out, " Run `hdns` to open the live control console; the daemon keeps running.")
	fmt.Fprintln(out, " Use `hdns flush` to flush its DNS cache directly.")
	return nil
}

// resolveDataPath mirrors the daemon's own resolution order for the relative
// cert paths a config usually carries: /opt/hyperdns when it exists, the
// working directory otherwise.
func resolveDataPath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if _, err := os.Stat("/opt/hyperdns"); err == nil {
		return filepath.Join("/opt/hyperdns", p)
	}
	return p
}

// readCertLeaf parses the first certificate of a PEM file. The daemon's
// cert.pem carries certificates only (the key lives in key.pem), so the pair
// loader is the wrong tool; the first CERTIFICATE block is what the panel
// serves.
func readCertLeaf(path string) (*x509.Certificate, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("no certificate path configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no CERTIFICATE PEM block found")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		data = rest
	}
}

// displayHost brackets nothing — the public IP is written into URLs verbatim
// — but an empty value reads better as "unknown".
func displayHost(h string) string {
	if strings.TrimSpace(h) == "" || h == "127.0.0.1" {
		return "<server-ip>"
	}
	return h
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none configured — panel binds loopback only)"
	}
	return s
}
