//go:build linux

package integration

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
	"hyperdns/internal/control"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

const (
	processControlDir  = "/run/hyperdns"
	processControlSock = processControlDir + "/control.sock"
	processControlLock = processControlSock + ".lock"
)

type runtimePathIdentity struct {
	device uint64
	inode  uint64
	type_  os.FileMode
}

type daemonProcessFixture struct {
	binary        string
	dbPath        string
	keyPath       string
	configPath    string
	webPort       int
	keyBytes      []byte
	command       *exec.Cmd
	output        bytes.Buffer
	dirCreated    bool
	controlDirID  runtimePathIdentity
	controlLockID runtimePathIdentity
}

func TestBareTUIUsesDaemonWithoutTakingRuntimeOwnership(t *testing.T) {
	requireRootLinuxProcessFixture(t)
	fixture := startDaemonProcessFixture(t)

	beforePID := fixture.command.Process.Pid
	beforeKey := mustReadFile(t, fixture.keyPath)
	fixture.assertDatabaseExclusivelyLocked(t)
	beforeListeners := processListenerSet(t, beforePID)
	if len(beforeListeners) == 0 {
		t.Fatal("daemon owns no listeners after startup")
	}

	clientDB := filepath.Join(t.TempDir(), "client.db")
	clientKey := filepath.Join(t.TempDir(), "client.key")
	createdOutput := fixture.runBareTUI(t, clientDB, clientKey, "1\n2\n3\nProcess Subscriber\n1\n203.0.113.42\n0\n", false)
	assertOutputContains(t, createdOutput, "Queries:", "No subscriber accounts.", "Client created: Process Subscriber (")
	createdID := clientIDFromTUI(t, createdOutput)
	clients := fixture.controlClients(t)
	if len(clients) != 1 || clients[0].ID != createdID {
		t.Fatalf("created client not visible through daemon control: %+v", clients)
	}
	if clients[0].SubscriptionToken != "" || clients[0].RegistrationSecret != "" {
		t.Fatal("client list disclosed creation-only credentials")
	}

	deletedOutput := fixture.runBareTUI(t, clientDB, clientKey, "2\n4\n"+createdID+"\n6\n0\n", false)
	assertOutputContains(t, deletedOutput, "Process Subscriber ("+createdID+")", "Client deleted.", "DNS cache flushed.")
	if clients := fixture.controlClients(t); len(clients) != 0 {
		t.Fatalf("deleted client still visible through daemon control: %+v", clients)
	}
	eofOutput := fixture.runBareTUI(t, clientDB, clientKey, "", true)
	assertOutputContains(t, eofOutput, "run control console: EOF")

	if got := fixture.command.Process.Pid; got != beforePID {
		t.Fatalf("daemon PID changed from %d to %d", beforePID, got)
	}
	if err := fixture.command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("daemon stopped after client exit/EOF: %v\n%s", err, fixture.output.String())
	}
	if got := mustReadFile(t, fixture.keyPath); !bytes.Equal(got, beforeKey) || !bytes.Equal(got, fixture.keyBytes) {
		t.Fatal("daemon master-key bytes changed while clients ran")
	}
	assertPathAbsent(t, clientDB)
	assertPathAbsent(t, clientKey)
	fixture.assertDatabaseExclusivelyLocked(t)
	if got := processListenerSet(t, beforePID); !equalStringSets(got, beforeListeners) {
		t.Fatalf("daemon listener set changed after clients: before=%v after=%v", sortedSet(beforeListeners), sortedSet(got))
	}
}

func requireRootLinuxProcessFixture(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux process and /proc semantics")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for the production SO_PEERCRED policy and /run fixture")
	}
	for _, path := range []string{processControlSock, processControlLock} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("refusing to replace pre-existing runtime path %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect %s: %v", path, err)
		}
	}
	if info, err := os.Lstat(processControlDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("refusing unsafe existing runtime path %s", processControlDir)
		}
		entries, readErr := os.ReadDir(processControlDir)
		if readErr != nil {
			t.Fatalf("read runtime directory: %v", readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("refusing non-empty existing runtime directory %s", processControlDir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect runtime directory: %v", err)
	}
}

func startDaemonProcessFixture(t *testing.T) *daemonProcessFixture {
	t.Helper()
	dir := t.TempDir()
	fixture := &daemonProcessFixture{
		binary:     processTestBinary(t),
		dbPath:     filepath.Join(dir, "data.db"),
		keyPath:    filepath.Join(dir, "master.key"),
		configPath: filepath.Join(dir, "config.json"),
		webPort:    reserveLoopbackPort(t),
		keyBytes:   bytes.Repeat([]byte{0x6d}, 32),
	}
	if err := os.WriteFile(fixture.keyPath, fixture.keyBytes, 0o600); err != nil {
		t.Fatalf("write fixture master key: %v", err)
	}
	cipher, err := crypto.NewCipher(fixture.keyBytes)
	if err != nil {
		t.Fatalf("create fixture cipher: %v", err)
	}
	db, err := database.Create(fixture.dbPath, cipher)
	if err != nil {
		t.Fatalf("create fixture database: %v", err)
	}
	if err := db.SetSetting("tls", &database.TLSSettings{
		Domain:        "",
		CertPath:      filepath.Join(dir, "cert.pem"),
		KeyPath:       filepath.Join(dir, "cert.key"),
		AutoRenewACME: false,
		PanelHTTPS:    false,
	}); err != nil {
		t.Fatalf("seed fixture TLS settings: %v", err)
	}
	if err := db.SetSetting("subscription", &database.SubscriptionSettings{
		Enabled:             true,
		Port:                fixture.webPort,
		URIPath:             "/sub",
		Title:               "HyperDNS",
		UsePanelCertificate: true,
	}); err != nil {
		t.Fatalf("seed fixture subscription settings: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}
	if err := os.Chmod(fixture.dbPath, 0o600); err != nil {
		t.Fatalf("set fixture database mode: %v", err)
	}
	config := fmt.Sprintf(`{
  "server": {
    "public_ip": "192.0.2.10",
    "bind_host": "127.0.0.1",
    "web_port": %d,
    "admin_username": "process-admin",
    "admin_password": "ProcessFixture-Password-938!",
    "api_bind": "127.0.0.1"
  },
  "dns": {
    "enabled": false,
    "upstreams": ["127.0.0.1:1"],
    "query_timeout": 50000000,
    "fastest_racing": false
  },
  "sniproxy": {"enabled": false},
  "access": {"allow_all": false},
  "tls": {
    "domain": "",
    "auto_cert": false,
    "cert_file": %q,
    "key_file": %q
  }
}`, fixture.webPort, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "cert.key"))
	if err := os.WriteFile(fixture.configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write fixture config: %v", err)
	}

	if _, err := os.Lstat(processControlDir); errors.Is(err, os.ErrNotExist) {
		fixture.dirCreated = true
	}
	fixture.command = exec.Command(fixture.binary,
		"-server",
		"-db", fixture.dbPath,
		"-key", fixture.keyPath,
		"-config", fixture.configPath,
	)
	fixture.command.Stdout = &fixture.output
	fixture.command.Stderr = &fixture.output
	fixture.command.Stdin = nil
	if err := fixture.command.Start(); err != nil {
		t.Fatalf("start disposable daemon: %v", err)
	}
	t.Cleanup(func() { fixture.stop(t) })

	waitUntil(t, 12*time.Second, func() (bool, error) {
		if err := fixture.command.Process.Signal(syscall.Signal(0)); err != nil {
			return false, fmt.Errorf("daemon exited during startup: %v\n%s", err, fixture.output.String())
		}
		if _, err := os.Lstat(processControlSock); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.webPort)), 100*time.Millisecond)
		if err != nil {
			return false, nil
		}
		_ = conn.Close()
		return true, nil
	})
	fixture.assertRuntimePathSecurity(t)
	fixture.controlDirID = mustRuntimePathIdentity(t, processControlDir)
	fixture.controlLockID = mustRuntimePathIdentity(t, processControlLock)
	return fixture
}

func processTestBinary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("HYPERDNS_PROCESS_TEST_BINARY"); path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("resolve HYPERDNS_PROCESS_TEST_BINARY: %v", err)
		}
		return absolute
	}
	t.Skip("set HYPERDNS_PROCESS_TEST_BINARY to a Linux hyperdns executable")
	return ""
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return port
}

func (f *daemonProcessFixture) controlClients(t *testing.T) []control.ClientView {
	t.Helper()
	clients, err := control.NewClient(processControlSock).ListClients(t.Context())
	if err != nil {
		t.Fatalf("list clients through daemon control: %v", err)
	}
	return clients
}

func (f *daemonProcessFixture) runBareTUI(t *testing.T, dbPath, keyPath, input string, wantFailure bool) string {
	t.Helper()
	cmd := exec.Command(f.binary, "-db", dbPath, "-key", keyPath, "-config", f.configPath)
	cmd.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if wantFailure {
		if err == nil {
			t.Fatal("closed-stdin client unexpectedly returned success instead of EOF")
		}
	} else if err != nil {
		t.Fatalf("scripted bare TUI: %v\n%s", err, output.String())
	}
	assertPathAbsent(t, dbPath)
	assertPathAbsent(t, keyPath)
	return output.String()
}

func assertOutputContains(t *testing.T, output string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(output, fragment) {
			t.Fatalf("TUI output does not contain %q:\n%s", fragment, output)
		}
	}
}

func clientIDFromTUI(t *testing.T, output string) string {
	t.Helper()
	const marker = "Client created: Process Subscriber ("
	start := strings.Index(output, marker)
	if start < 0 {
		t.Fatalf("create confirmation absent from TUI output:\n%s", output)
	}
	start += len(marker)
	end := strings.IndexByte(output[start:], ')')
	if end <= 0 {
		t.Fatalf("created client ID absent from TUI output:\n%s", output)
	}
	return output[start : start+end]
}

func (f *daemonProcessFixture) assertRuntimePathSecurity(t *testing.T) {
	t.Helper()
	assertUnixPath(t, processControlDir, os.ModeDir, 0o700)
	assertUnixPath(t, processControlSock, os.ModeSocket, 0o600)
	assertUnixPath(t, processControlLock, 0, 0o600)
}

func assertUnixPath(t *testing.T, path string, wantType, wantPerm os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	if wantType == os.ModeDir {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s mode = %v, want real directory", path, info.Mode())
		}
	} else if info.Mode()&os.ModeType != wantType {
		t.Fatalf("%s type = %v, want %v", path, info.Mode()&os.ModeType, wantType)
	}
	if got := info.Mode().Perm(); got != wantPerm {
		t.Fatalf("%s permissions = %04o, want %04o", path, got, wantPerm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		t.Fatalf("%s is not root-owned", path)
	}
}

func mustRuntimePathIdentity(t *testing.T, path string) runtimePathIdentity {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat identity unavailable for %s", path)
	}
	return runtimePathIdentity{device: uint64(stat.Dev), inode: stat.Ino, type_: info.Mode() & os.ModeType}
}

func sameRuntimePath(path string, want runtimePathIdentity) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeType != want.type_ {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == want.device && stat.Ino == want.inode
}

func (f *daemonProcessFixture) assertDatabaseExclusivelyLocked(t *testing.T) {
	t.Helper()
	locked, err := bolt.Open(f.dbPath, 0o600, &bolt.Options{Timeout: 100 * time.Millisecond})
	if err == nil {
		_ = locked.Close()
		t.Fatal("second process acquired the daemon-owned bbolt file")
	}
	if !errors.Is(err, bolterrors.ErrTimeout) {
		t.Fatalf("second bbolt open error = %v, want lock timeout", err)
	}
}

func processFDTargets(t *testing.T, pid int) map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatalf("read daemon file descriptors: %v", err)
	}
	result := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fmt.Sprintf("/proc/%d/fd", pid), entry.Name()))
		if err == nil {
			result[target] = struct{}{}
		}
	}
	return result
}

func processListenerSet(t *testing.T, pid int) map[string]struct{} {
	t.Helper()
	listeners := listeningSocketInodes(t)
	result := make(map[string]struct{})
	for target := range processFDTargets(t, pid) {
		inode, ok := socketTargetInode(target)
		if ok {
			if _, listening := listeners[inode]; listening {
				result[target] = struct{}{}
			}
		}
	}
	return result
}

func listeningSocketInodes(t *testing.T) map[string]struct{} {
	t.Helper()
	result := make(map[string]struct{})
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			t.Fatalf("read %s: %v", path, err)
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 10 && fields[3] == "0A" {
				result[fields[9]] = struct{}{}
			}
		}
	}
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		t.Fatalf("read /proc/net/unix: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 7 && fields[5] == "01" {
			result[fields[6]] = struct{}{}
		}
	}
	return result
}

func socketTargetInode(target string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]"), true
}

func (f *daemonProcessFixture) stop(t *testing.T) {
	t.Helper()
	if f.command != nil && f.command.Process != nil {
		if err := f.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("signal disposable daemon: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- f.command.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("disposable daemon exit: %v\n%s", err, f.output.String())
			}
		case <-time.After(8 * time.Second):
			_ = f.command.Process.Kill()
			<-done
			t.Errorf("disposable daemon did not stop within 8s\n%s", f.output.String())
		}
	}
	if _, err := os.Lstat(processControlSock); err == nil {
		t.Errorf("control socket remained after daemon shutdown")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("inspect control socket after shutdown: %v", err)
	}
	removeFixtureRuntimePath(t, processControlLock, f.controlLockID)
	if f.dirCreated {
		removeFixtureRuntimePath(t, processControlDir, f.controlDirID)
	}
}

func removeFixtureRuntimePath(t *testing.T, path string, identity runtimePathIdentity) {
	t.Helper()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Errorf("inspect fixture runtime path %s: %v", path, err)
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !sameRuntimePath(path, identity) {
		t.Errorf("refusing to remove replaced or non-root-owned runtime path %s", path)
		return
	}
	if identity.type_ == os.ModeDir {
		entries, readErr := os.ReadDir(path)
		if readErr != nil || len(entries) != 0 {
			t.Errorf("refusing to remove non-empty fixture directory %s", path)
			return
		}
	}
	if err := os.Remove(path); err != nil {
		t.Errorf("remove fixture runtime path %s: %v", path, err)
	}
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok, err := condition()
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for disposable daemon readiness")
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %s exists or cannot be inspected: %v", path, err)
	}
}

func equalStringSets(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for value := range a {
		if _, ok := b[value]; !ok {
			return false
		}
	}
	return true
}

func sortedSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
