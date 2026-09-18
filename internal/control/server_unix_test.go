//go:build linux

package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func requireRootControlTest(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root ownership and SO_PEERCRED tests require root")
	}
}

func controlSocketPath(t *testing.T) string {
	t.Helper()
	requireRootControlTest(t)
	return filepath.Join(t.TempDir(), "hyperdns", "control.sock")
}

func startTestControlServer(t *testing.T, srv *Server) {
	t.Helper()
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
}

func assertRootMode(t *testing.T, path string, want os.FileMode) syscall.Stat_t {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%s) = %04o, want %04o", path, got, want)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat type = %T", info.Sys())
	}
	if stat.Uid != 0 {
		t.Fatalf("owner(%s) = uid %d, want root", path, stat.Uid)
	}
	return *stat
}

func TestServerCreatesPrivateRootOwnedDirectoryAndSocket(t *testing.T) {
	path := controlSocketPath(t)
	srv := NewServer(path, NewHandler(&operationsStub{}))
	startTestControlServer(t, srv)

	assertRootMode(t, filepath.Dir(path), 0o700)
	stat := assertRootMode(t, path, 0o600)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("control path is not a socket: mode=%v err=%v", info.Mode(), err)
	}
	if stat.Ino == 0 {
		t.Fatal("socket inode is zero")
	}
}

func TestServerAcceptsRootPeerAndIgnoresSpoofedIdentity(t *testing.T) {
	path := controlSocketPath(t)
	srv := NewServer(path, NewHandler(&operationsStub{status: Status{TotalQueries: 41}}))
	startTestControlServer(t, srv)

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = fmt.Fprintf(conn, "GET /v1/status?uid=1000 HTTP/1.1\r\nHost: local\r\n%s: %s\r\nX-UID: 0\r\nX-Forwarded-User: root\r\nContent-Length: 14\r\n\r\n{\"uid\":\"1000\"}", ProtocolVersionHeader, ProtocolVersion)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("status = %q, want 200", status)
	}
}

func TestServerRejectsInjectedNonRootBeforeReadingHTTP(t *testing.T) {
	path := controlSocketPath(t)
	called := make(chan struct{}, 1)
	var handled bool
	srv := newServer(path, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handled = true
	}), func(net.Conn) (uint32, error) {
		called <- struct{}{}
		return 1000, nil
	})
	startTestControlServer(t, srv)

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	spoofed := "GET /v1/status?uid=0 HTTP/1.1\r\nHost: local\r\nX-UID: 0\r\nX-Forwarded-User: root\r\nContent-Length: 11\r\n\r\n{\"uid\":\"0\"}"
	if _, err := io.WriteString(conn, spoofed); err != nil && !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("write spoofed identity: %v", err)
	}
	one := make([]byte, 1)
	if _, err := conn.Read(one); err == nil {
		t.Fatal("unauthorized peer remained connected")
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("peer credential check was not called")
	}
	if handled {
		t.Fatal("HTTP handler received an unauthorized connection")
	}
}

func TestServerRefusesToUnlinkLiveSocket(t *testing.T) {
	path := controlSocketPath(t)
	first := NewServer(path, NewHandler(&operationsStub{}))
	startTestControlServer(t, first)
	before := assertRootMode(t, path, 0o600)

	second := NewServer(path, NewHandler(&operationsStub{}))
	if err := second.Start(); err == nil {
		t.Fatal("second Start succeeded on a live socket")
	}
	after := assertRootMode(t, path, 0o600)
	if before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("live socket was replaced")
	}
}

func TestServerRemovesVerifiedStaleSocket(t *testing.T) {
	path := controlSocketPath(t)
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale fixture missing: %v", err)
	}

	srv := NewServer(path, NewHandler(&operationsStub{}))
	startTestControlServer(t, srv)
	assertRootMode(t, path, 0o600)
}

func TestServerPreservesPathOnAmbiguousProbeFailure(t *testing.T) {
	path := controlSocketPath(t)
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat stale fixture: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale fixture mode = %v, want socket", info.Mode())
	}

	srv := NewServer(path, NewHandler(&operationsStub{}))
	srv.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, os.ErrPermission
	}
	if err := srv.Start(); err == nil {
		t.Fatal("Start succeeded after ambiguous stale probe")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("ambiguous probe removed path: %v", err)
	}
}

func TestServerRejectsUnsafeParentAndNonSocketPaths(t *testing.T) {
	requireRootControlTest(t)
	t.Run("parent mode", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "hyperdns")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		err := NewServer(filepath.Join(dir, "control.sock"), NewHandler(&operationsStub{})).Start()
		if err == nil {
			t.Fatal("Start accepted non-private parent")
		}
	})
	t.Run("parent symlink", func(t *testing.T) {
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		linkDir := filepath.Join(base, "hyperdns")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		if err := NewServer(filepath.Join(linkDir, "control.sock"), NewHandler(&operationsStub{})).Start(); err == nil {
			t.Fatal("Start followed a parent symlink")
		}
	})
	t.Run("existing regular file", func(t *testing.T) {
		path := controlSocketPath(t)
		if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewServer(path, NewHandler(&operationsStub{})).Start(); err == nil {
			t.Fatal("Start replaced a regular file")
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "keep" {
			t.Fatalf("regular file changed: %q, %v", got, err)
		}
	})
}

func TestServerShutdownReleasesOnlyOwnedSocket(t *testing.T) {
	path := controlSocketPath(t)
	srv := NewServer(path, NewHandler(&operationsStub{}))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	owned := path + ".owned"
	if err := os.Rename(path, owned); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	replacement.SetUnlinkOnClose(false)
	defer func() {
		_ = replacement.Close()
		_ = os.Remove(path)
		_ = os.Remove(owned)
	}()
	replacementStat, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	got, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("replacement path removed: %v", err)
	}
	before := replacementStat.Sys().(*syscall.Stat_t)
	after := got.Sys().(*syscall.Stat_t)
	if before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("replacement socket changed during shutdown")
	}
}

func TestServerShutdownIsBoundedAndRemovesOwnedPath(t *testing.T) {
	path := controlSocketPath(t)
	srv := NewServer(path, NewHandler(&operationsStub{}))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("Shutdown took %s, want bounded below deadline", elapsed)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket remains after shutdown: %v", err)
	}
}
