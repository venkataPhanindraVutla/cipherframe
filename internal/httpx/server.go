package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Server limits. They are deliberately conservative; large bodies and segments do not stream
// through the api listener, and the edge streams segments within WriteTimeout.
const (
	ReadHeaderTimeout = 10 * time.Second
	ReadTimeout       = 30 * time.Second
	WriteTimeout      = 60 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 32 << 10
)

// NewServer returns an http.Server for addr and h with timeouts and a header size limit set.
// net/http's own error log goes through log at warn level.
func NewServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// Serve serves srv on ln until ctx is cancelled, then shuts down gracefully: it stops accepting
// connections and waits up to grace for in-flight requests, after which it closes the rest. It
// returns nil after a clean shutdown, and the serve or shutdown error otherwise.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener, grace time.Duration) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), grace)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
		<-errc
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	<-errc // http.ErrServerClosed
	return nil
}
