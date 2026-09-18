//go:build !linux

package control

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedServerReturnsErrorWithoutBindingFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	srv := NewServer(path, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	if err := srv.Start(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Start error = %v, want ErrUnsupported", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported server created requested path: %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(path)); err != nil {
		t.Fatalf("existing parent directory changed: %v", err)
	}
}
