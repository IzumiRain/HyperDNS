//go:build linux

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	controlDirectoryMode = 0o700
	controlSocketMode    = 0o600
)

type peerUIDFunc func(net.Conn) (uint32, error)
type dialContextFuncServer func(context.Context, string, string) (net.Conn, error)

type socketIdentity struct {
	device uint64
	inode  uint64
}

// Server is the root-local HTTP control endpoint. Start must complete before
// public listeners become ready; Shutdown stops acceptance and releases only the
// exact socket inode this instance created.
type Server struct {
	path    string
	handler http.Handler
	peerUID peerUIDFunc
	dial    dialContextFuncServer

	mu       sync.Mutex
	listener *net.UnixListener
	http     *http.Server
	owned    socketIdentity
	lockFile *os.File
}

func NewServer(path string, handler http.Handler) *Server {
	return newServer(path, handler, linuxPeerUID)
}

func newServer(path string, handler http.Handler, peerUID peerUIDFunc) *Server {
	return &Server{
		path:    path,
		handler: handler,
		peerUID: peerUID,
		dial:    (&net.Dialer{}).DialContext,
	}
}

func (s *Server) Start() error {
	if s == nil || s.path == "" || s.handler == nil || s.peerUID == nil {
		return errors.New("control server is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return errors.New("control server is already running")
	}

	if err := ensurePrivateRootDirectory(filepath.Dir(s.path)); err != nil {
		return err
	}
	lock, err := acquireControlLock(s.path + ".lock")
	if err != nil {
		return err
	}
	cleanupLock := true
	defer func() {
		if cleanupLock {
			releaseControlLock(lock)
		}
	}()

	if err := s.prepareSocketPath(); err != nil {
		return err
	}
	listener, err := listenUnixSocket(s.path)
	if err != nil {
		return fmt.Errorf("bind control socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	cleanupSocket := true
	defer func() {
		if cleanupSocket {
			_ = listener.Close()
			_ = os.Remove(s.path)
		}
	}()
	if err := os.Chmod(s.path, controlSocketMode); err != nil {
		return fmt.Errorf("set control socket mode: %w", err)
	}
	owned, err := secureSocketIdentity(s.path)
	if err != nil {
		return err
	}

	authorized := &authorizedListener{Listener: listener, peerUID: s.peerUID}
	httpServer := &http.Server{Handler: s.handler}
	s.listener = listener
	s.http = httpServer
	s.owned = owned
	s.lockFile = lock
	cleanupLock = false
	cleanupSocket = false
	go func() {
		_ = httpServer.Serve(authorized)
	}()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	listener := s.listener
	httpServer := s.http
	owned := s.owned
	lock := s.lockFile
	s.listener = nil
	s.http = nil
	s.owned = socketIdentity{}
	s.lockFile = nil
	s.mu.Unlock()
	if listener == nil {
		return nil
	}

	// Drain the HTTP server first: http.Server.Shutdown closes the listener as
	// part of stopping acceptance, so closing the listener before it races the
	// drain and surfaces a benign "use of closed network connection" as a real
	// shutdown error. In this order listener.Close is the idempotent tail.
	err := httpServer.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		_ = httpServer.Close()
	}
	_ = listener.Close()
	if sameSocket(s.path, owned) {
		if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && err == nil {
			err = fmt.Errorf("remove control socket: %w", removeErr)
		}
	}
	releaseControlLock(lock)
	return err
}

func (s *Server) prepareSocketPath() error {
	before, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect control socket: %w", err)
	}
	if before.Mode()&os.ModeSocket == 0 {
		return errors.New("control path exists and is not a socket")
	}
	identity, err := rootSocketIdentity(before)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), controlProbeTimeout)
	defer cancel()
	conn, dialErr := s.dial(ctx, "unix", s.path)
	if dialErr == nil {
		_ = conn.Close()
		return errors.New("control socket is already active")
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("control socket state is ambiguous: %w", dialErr)
	}
	if !sameSocket(s.path, identity) {
		return errors.New("control socket changed during stale check")
	}
	if err := os.Remove(s.path); err != nil {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	return nil
}

const controlProbeTimeout = 250 * time.Millisecond

func ensurePrivateRootDirectory(dir string) error {
	info, err := lstatPathWithoutSymlinkComponents(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, controlDirectoryMode); err != nil {
			// ErrRuntimeDir marks the "cannot create the directory at all"
			// class (an unprivileged run against /run/hyperdns, a read-only
			// /run). The daemon classifies it as a capability limit — keep
			// serving DNS and the panel, lose only the console — rather than
			// a fatal misconfiguration. The wrap keeps the OS error visible.
			return fmt.Errorf("create control directory: %w: %w", ErrRuntimeDir, err)
		}
		info, err = lstatPathWithoutSymlinkComponents(dir)
	}
	if err != nil {
		return fmt.Errorf("inspect control directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("control directory must be a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("control directory must be owned by root")
	}
	if info.Mode().Perm() != controlDirectoryMode {
		return fmt.Errorf("control directory mode must be %04o", controlDirectoryMode)
	}
	return nil
}

func listenUnixSocket(path string) (*net.UnixListener, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.Fchmod(fd, controlSocketMode); err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return nil, err
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "hyperdns-control")
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	closeFD = false
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, errors.New("bound control listener is not Unix")
	}
	unixListener.SetUnlinkOnClose(false)
	return unixListener, nil
}

func lstatPathWithoutSymlinkComponents(path string) (os.FileInfo, error) {
	clean := filepath.Clean(path)
	current := string(filepath.Separator)
	if !filepath.IsAbs(clean) {
		current = ""
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	var info os.FileInfo
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		var err error
		info, err = os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("control directory path contains a symlink")
		}
	}
	return info, nil
}

func secureSocketIdentity(path string) (socketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return socketIdentity{}, fmt.Errorf("inspect bound control socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != controlSocketMode {
		return socketIdentity{}, errors.New("bound control path is not a private socket")
	}
	return rootSocketIdentity(info)
}

func rootSocketIdentity(info os.FileInfo) (socketIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return socketIdentity{}, errors.New("control socket must be owned by root")
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func sameSocket(path string, want socketIdentity) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == want.device && stat.Ino == want.inode
}

func acquireControlLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, controlSocketMode)
	if err != nil {
		return nil, fmt.Errorf("open control lock: %w", err)
	}
	if err := os.Chmod(path, controlSocketMode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set control lock mode: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock control socket lifecycle: %w", err)
	}
	return file, nil
}

func releaseControlLock(file *os.File) {
	if file == nil {
		return
	}
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	_ = file.Close()
}

type authorizedListener struct {
	net.Listener
	peerUID peerUIDFunc
}

func (l *authorizedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, credErr := l.peerUID(conn)
		if credErr != nil || uid != 0 {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

func linuxPeerUID(conn net.Conn) (uint32, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New("control connection has no raw socket")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cred, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	if cred == nil {
		return 0, errors.New("control peer credentials are unavailable")
	}
	return cred.Uid, nil
}
