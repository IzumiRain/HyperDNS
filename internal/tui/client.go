package tui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"hyperdns/internal/control"
	"hyperdns/internal/version"
)

// ControlClient is the daemon-owned management surface consumed by the TUI.
// It intentionally contains DTOs only; the TUI cannot open a database, load a
// master key, or start a second resolver process.
type ControlClient interface {
	Status(context.Context) (control.Status, error)
	ListClients(context.Context) ([]control.ClientView, error)
	CreateClient(context.Context, control.CreateClientRequest) (control.ClientView, error)
	DeleteClient(context.Context, string) error
	FlushCache(context.Context) error
	StartBenchmark(context.Context) error
	Settings(context.Context) (control.SettingsView, error)
	RotateAPIKey(context.Context, control.RotateAPIKeyRequest) (control.RotateAPIKeyResult, error)
	PersistPanelPort(context.Context, int) error
	ClearLockouts(context.Context, control.ClearLockoutsRequest) (int, error)
	ChangeAdmin(context.Context, control.ChangeAdminRequest) error
	ResetAdmin(context.Context, control.ResetAdminRequest) error
}

// SystemController contains actions that affect the host/service rather than
// daemon state. Keeping it separate makes option 0 incapable of stopping the
// daemon and makes the client path straightforward to test.
//
// v2.2.0 adds Start and Stop: the console is a client process that runs with
// the daemon down (bare `hdns` is dispatched before any DB access), so it is
// exactly the place an operator lands when the service is stopped and needs
// the way back up.
type SystemController interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
	Uninstall(ctx context.Context) error
}

type ExecSystemController struct {
	StartCommand     []string
	StopCommand      []string
	RestartCommand   []string
	UninstallCommand []string
}

func (s ExecSystemController) Start(ctx context.Context) error {
	args := s.StartCommand
	if len(args) == 0 {
		args = []string{"systemctl", "start", "hyperdns"}
	}
	return runCommand(ctx, args)
}

func (s ExecSystemController) Stop(ctx context.Context) error {
	args := s.StopCommand
	if len(args) == 0 {
		args = []string{"systemctl", "stop", "hyperdns"}
	}
	return runCommand(ctx, args)
}

func (s ExecSystemController) Restart(ctx context.Context) error {
	args := s.RestartCommand
	if len(args) == 0 {
		args = []string{"systemctl", "restart", "hyperdns"}
	}
	return runCommand(ctx, args)
}

func (s ExecSystemController) Uninstall(ctx context.Context) error {
	args := s.UninstallCommand
	if len(args) == 0 {
		// The console already collected the typed UNINSTALL confirmation,
		// so the script's own prompt is answered with -y: the run is not
		// interactive dead-weight on a pipe. -y still writes the /root
		// backup archive — only --purge skips that, and nothing in this
		// console passes --purge.
		args = []string{"/opt/hyperdns/scripts/uninstall.sh", "-y"}
	}
	return runInteractive(ctx, args)
}

func runCommand(ctx context.Context, command []string) error {
	if len(command) == 0 {
		return errors.New("empty system command")
	}
	return exec.CommandContext(ctx, command[0], command[1:]...).Run()
}

// runInteractive is runCommand with the terminal handed to the child. The
// uninstaller prints its own progress and (without -y) asks its own
// confirmation; run with nil stdio those prompts read EOF and the whole run
// is invisible, which is exactly how "Uninstall" once answered a typed
// confirmation with a bare "control request failed".
func runInteractive(ctx context.Context, command []string) error {
	if len(command) == 0 {
		return errors.New("empty system command")
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Run is the pure-client interactive console. It returns nil for an explicit
// exit and io.EOF when the input stream closes unexpectedly; neither case stops
// the daemon or invokes a host action.
func Run(ctx context.Context, in io.Reader, out, errOut io.Writer, client ControlClient, system SystemController) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if in == nil {
		return io.EOF
	}
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	if client == nil {
		return errors.New("control client is unavailable")
	}

	p := NewPalette(out)
	scanner := bufio.NewScanner(in)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// v2.2.0: clear and redraw in place. The v2.1 console appended its
		// whole menu after every action, so a ten-action session scrolled ten
		// copies of the menu down the terminal.
		p.ClearScreen(out)
		printBanner(out, p)
		printMenu(ctx, out, p, client)
		if _, err := fmt.Fprint(out, " Select an option [0-16]: "); err != nil {
			return err
		}
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return io.EOF
		}
		choice := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if choice == "0" || choice == "q" || choice == "quit" || choice == "exit" {
			fmt.Fprintln(out, "Goodbye.")
			return nil
		}
		if err := runChoice(ctx, choice, scanner, out, errOut, client, system); err != nil {
			if errors.Is(err, io.EOF) {
				return err
			}
			fmt.Fprintf(errOut, "%s %v\n", p.Red("✗"), sanitizedError(err))
		}
		// The pause keeps the result on screen; the next iteration's clear
		// would otherwise wipe it before anyone read it.
		fmt.Fprint(out, p.Faint("\n Press Enter to continue... "))
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return io.EOF
		}
	}
}

func printBanner(out io.Writer, p palette) {
	fmt.Fprintln(out, p.Cyan(p.Bold(Banner(version.Get().Display))))
	fmt.Fprintln(out, p.Faint("  control console — the daemon keeps running when you exit"))
	fmt.Fprintln(out)
}

func printMenu(ctx context.Context, out io.Writer, p palette, client ControlClient) {
	// The status line is the old console’s [●] header, fed by the live control
	// socket: service state, machine-wide CPU and RAM (internal/sysmetrics —
	// the whole server, not just the daemon), subscriber count. A status the
	// console cannot fetch reads as DOWN, never as a guess.
	status, err := client.Status(ctx)
	if err != nil {
		fmt.Fprintf(out, " %s %s\n", p.Cyan("[●]"), p.Red("Service: ● DOWN — "+sanitizedError(err)))
	} else {
		service := p.Green("● ACTIVE")
		cpu := "—"
		if status.SystemCPUPercent >= 0 {
			cpu = fmt.Sprintf("%.1f%%", status.SystemCPUPercent)
		}
		ram := "—"
		if status.SystemMemUsedMB >= 0 && status.SystemMemTotalMB > 0 {
			ram = fmt.Sprintf("%.0f/%.0f MB (%.0f%%)", status.SystemMemUsedMB, status.SystemMemTotalMB, status.SystemMemPercent)
		}
		fmt.Fprintf(out, " %s %s   %s %s   %s %s\n",
			p.Cyan("[●]"), p.Bold("Service: "+service),
			p.Cyan("[●]"), p.Bold("CPU: "+cpu),
			p.Cyan("[●]"), p.Bold("RAM: "+ram))
		fmt.Fprintf(out, " %s %s   %s %s   %s %s\n",
			p.Cyan("[●]"), p.Bold(fmt.Sprintf("Clients: %d", status.ClientCount)),
			p.Cyan("[●]"), p.Bold(fmt.Sprintf("Queries: %d", status.TotalQueries)),
			p.Cyan("[●]"), p.Bold("Uptime: "+formatUptime(status.UptimeSec)))
	}
	fmt.Fprintln(out, p.Faint(strings.Repeat("─", 64)))
	fmt.Fprintln(out, p.Bold(" 🛠  Service"))
	fmt.Fprintln(out, "  [1] 📊 Status & telemetry        [2] 🩺 Diagnostics")
	fmt.Fprintln(out, "  [3] 🔄 Restart service           [4] 🛑 Stop service")
	fmt.Fprintln(out, "  [5] ▶️  Start service (after a stop)")
	fmt.Fprintln(out, p.Bold(" 👥 Subscribers"))
	fmt.Fprintln(out, "  [6] 📋 List subscriber accounts  [7] ➕ Add subscriber")
	fmt.Fprintln(out, "  [8] 🗑️  Delete subscriber")
	fmt.Fprintln(out, p.Bold(" 🌐 Engine & Network"))
	fmt.Fprintln(out, "  [9] ⚡ Benchmark DNS upstreams   [10] 🧹 Flush DNS cache")
	fmt.Fprintln(out, "  [11] 🔌 Change dashboard panel port")
	fmt.Fprintln(out, p.Bold(" 🔒 Security & System"))
	fmt.Fprintln(out, "  [12] 🔑 View / rotate API key    [13] 🔓 Clear login lockouts")
	fmt.Fprintln(out, "  [14] 🛡️  Change admin credentials [15] 🚨 Emergency admin reset")
	fmt.Fprintln(out, "  [16] 💣 Uninstall HyperDNS")
	fmt.Fprintln(out, p.Faint(strings.Repeat("─", 64)))
	fmt.Fprintln(out, "  [0] 🚪 Exit console (daemon keeps running)")
}

func runChoice(ctx context.Context, choice string, scanner *bufio.Scanner, out, errOut io.Writer, client ControlClient, system SystemController) error {
	switch choice {
	case "1":
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "\nQueries: %d\nQPS: %.1f\nActive relays: %d\nCache: %d (%d hits, %d misses)\nUptime: %s\n",
			status.TotalQueries, status.QPS, status.ActiveRelays, status.CacheItems, status.CacheHits, status.CacheMisses, formatUptime(status.UptimeSec))
		if status.SystemCPUPercent >= 0 {
			fmt.Fprintf(out, "Server CPU: %.1f%%\n", status.SystemCPUPercent)
		}
		if status.SystemMemUsedMB >= 0 && status.SystemMemTotalMB > 0 {
			fmt.Fprintf(out, "Server RAM: %.0f / %.0f MB (%.0f%%)\n",
				status.SystemMemUsedMB, status.SystemMemTotalMB, status.SystemMemPercent)
		}
	case "2":
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Control socket: reachable\nQueries: %d\nCache entries: %d\nUptime: %s\n", status.TotalQueries, status.CacheItems, formatUptime(status.UptimeSec))
	case "3":
		if system == nil {
			return errors.New("system controller is unavailable")
		}
		if err := system.Restart(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, "Service restart requested.")
	case "4":
		if system == nil {
			return errors.New("system controller is unavailable")
		}
		confirm, err := prompt(scanner, out, "Type STOP to stop the daemon (DNS service goes down): ")
		if err != nil {
			return err
		}
		if strings.TrimSpace(strings.ToUpper(confirm)) != "STOP" {
			fmt.Fprintln(out, "Stop cancelled.")
			break
		}
		if err := system.Stop(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, "Service stopped. Use [5] Start service (or systemctl start hyperdns) to bring it back.")
	case "5":
		if system == nil {
			return errors.New("system controller is unavailable")
		}
		if err := system.Start(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, "Service start requested.")
	case "6":
		clients, err := client.ListClients(ctx)
		if err != nil {
			return err
		}
		if len(clients) == 0 {
			fmt.Fprintln(out, "No subscriber accounts.")
			break
		}
		// Aligned table: names and IPs are operator-managed free text, so they
		// are sanitized (ANSI injection) and truncated to keep one row per line.
		fmt.Fprintln(out, "\nNAME              ID      ENABLED  EXPIRES                IPS")
		for _, c := range clients {
			fmt.Fprintf(out, "%-16s  %s  %-8t %s  %s\n",
				Truncate(Sanitize(c.Name), 16), Sanitize(c.ID), c.Enabled, expiry(c.ExpiresAt), Sanitize(strings.Join(c.AllowedIPs, ",")))
		}
	case "7":
		return createClient(ctx, scanner, out, client)
	case "8":
		id, err := prompt(scanner, out, "Client ID: ")
		if err != nil {
			return err
		}
		if err := client.DeleteClient(ctx, strings.TrimSpace(id)); err != nil {
			return err
		}
		fmt.Fprintln(out, "Client deleted.")
	case "9":
		if err := client.StartBenchmark(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, "Benchmark started.")
	case "10":
		if err := client.FlushCache(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, "DNS cache flushed.")
	case "11":
		portText, err := prompt(scanner, out, "New panel port: ")
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(strings.TrimSpace(portText))
		if err != nil {
			return errors.New("panel port must be a number")
		}
		if err := client.PersistPanelPort(ctx, port); err != nil {
			return err
		}
		fmt.Fprintln(out, "Panel port saved; restart the service to apply it.")
	case "12":
		return apiKeyFlow(ctx, scanner, out, client)
	case "13":
		cleared, err := client.ClearLockouts(ctx, control.ClearLockoutsRequest{})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Cleared %d lockout record(s).\n", cleared)
	case "14":
		return changeAdminFlow(ctx, scanner, out, client)
	case "15":
		return resetAdminFlow(ctx, scanner, out, client)
	case "16":
		if system == nil {
			return errors.New("system controller is unavailable")
		}
		confirm, err := prompt(scanner, out, "Type UNINSTALL to continue: ")
		if err != nil {
			return err
		}
		if strings.TrimSpace(confirm) != "UNINSTALL" {
			fmt.Fprintln(out, "Uninstall cancelled.")
			break
		}
		return system.Uninstall(ctx)
	default:
		fmt.Fprintln(errOut, "unknown option")
	}
	return nil
}

func createClient(ctx context.Context, scanner *bufio.Scanner, out io.Writer, client ControlClient) error {
	name, err := prompt(scanner, out, "Client name: ")
	if err != nil {
		return err
	}
	daysText, err := prompt(scanner, out, "Validity days (0 = lifetime): ")
	if err != nil {
		return err
	}
	days, err := strconv.Atoi(strings.TrimSpace(daysText))
	if err != nil || days < 0 {
		return errors.New("validity days must be a non-negative number")
	}
	ip, err := prompt(scanner, out, "Initial IP (optional): ")
	if err != nil {
		return err
	}
	created, err := client.CreateClient(ctx, control.CreateClientRequest{Name: strings.TrimSpace(name), Days: days, IP: strings.TrimSpace(ip)})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Client created: %s (%s)\nSubscription token: %s\nRegistration secret: %s\n", created.Name, created.ID, created.SubscriptionToken, created.RegistrationSecret)
	return nil
}

func apiKeyFlow(ctx context.Context, scanner *bufio.Scanner, out io.Writer, client ControlClient) error {
	settings, err := client.Settings(ctx)
	if err != nil {
		return err
	}
	if settings.APIKey != "" {
		fmt.Fprintf(out, "Current API key: %s\n", settings.APIKey)
	}
	answer, err := prompt(scanner, out, "Type rotate to replace it, or press Enter to leave unchanged: ")
	if err != nil || strings.ToLower(strings.TrimSpace(answer)) != "rotate" {
		return err
	}
	password, err := prompt(scanner, out, "Current admin password: ")
	if err != nil {
		return err
	}
	result, err := client.RotateAPIKey(ctx, control.RotateAPIKeyRequest{CurrentPassword: password})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "New API key: %s\n", result.APIKey)
	return nil
}

func changeAdminFlow(ctx context.Context, scanner *bufio.Scanner, out io.Writer, client ControlClient) error {
	current, err := prompt(scanner, out, "Current admin password: ")
	if err != nil {
		return err
	}
	username, err := prompt(scanner, out, "New username (Enter keeps current): ")
	if err != nil {
		return err
	}
	password, err := prompt(scanner, out, "New password (Enter keeps current): ")
	if err != nil {
		return err
	}
	if err := client.ChangeAdmin(ctx, control.ChangeAdminRequest{CurrentPassword: current, Username: strings.TrimSpace(username), Password: password}); err != nil {
		return err
	}
	fmt.Fprintln(out, "Administrator settings updated.")
	return nil
}

func resetAdminFlow(ctx context.Context, scanner *bufio.Scanner, out io.Writer, client ControlClient) error {
	username, err := prompt(scanner, out, "Replacement username: ")
	if err != nil {
		return err
	}
	password, err := prompt(scanner, out, "Replacement password: ")
	if err != nil {
		return err
	}
	confirm, err := prompt(scanner, out, "Repeat replacement password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return errors.New("replacement passwords do not match")
	}
	if err := client.ResetAdmin(ctx, control.ResetAdminRequest{Username: strings.TrimSpace(username), Password: password}); err != nil {
		return err
	}
	fmt.Fprintln(out, "Administrator credentials reset; existing sessions were revoked.")
	return nil
}

func prompt(scanner *bufio.Scanner, out io.Writer, label string) (string, error) {
	if _, err := fmt.Fprint(out, label); err != nil {
		return "", err
	}
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	return scanner.Text(), nil
}

func expiry(t time.Time) string {
	if t.IsZero() {
		return "lifetime"
	}
	return t.UTC().Format(time.RFC3339)
}

func sanitizedError(err error) string {
	if err == nil {
		return ""
	}
	// Protocol errors are already redacted by control.Client. System-command
	// errors (an *exec.ExitError from the uninstaller, systemctl, …) carry
	// only an exit status and the command's own already-printed output, so
	// they are shown as-is — collapsing them into the generic string is how
	// a failed uninstall once read as an unexplained "control request
	// failed". Everything else (arbitrary wrapped errors that might carry a
	// request body or password) stays redacted.
	if op, ok := err.(*control.Error); ok {
		return op.Message
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return err.Error()
	}
	// A missing host script (the uninstaller an older installer never shipped)
	// used to surface as the generic "control request failed", which reads as
	// a daemon problem and sent operators into pointless reinstalls. Name the
	// actual cause instead.
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) && errors.Is(pathErr.Err, fs.ErrNotExist) {
		return fmt.Sprintf("%s: not found on this server — it ships with the current installer; reinstall once with it and this action will work", pathErr.Path)
	}
	return "control request failed"
}
