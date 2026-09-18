//go:build !linux

package control

import (
	"context"
	"net/http"
)

// Server is unavailable off Linux: there is deliberately no TCP or
// unauthenticated Unix fallback. Start reports ErrUnsupported (declared in
// model.go, so callers on every platform can recognise it), and the daemon
// treats that as "no local console here" rather than as a reason not to run.
type Server struct{}

func NewServer(string, http.Handler) *Server { return &Server{} }

func (*Server) Start() error { return ErrUnsupported }

func (*Server) Shutdown(context.Context) error { return nil }
