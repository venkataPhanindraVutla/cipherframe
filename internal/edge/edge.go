// Package edge is the browser-facing data-plane listener (ADR 0008): playlists, the key endpoint
// and segments arrive with later tasks. For now it serves health and readiness from its own small
// router.
//
// This package must not import internal/api or internal/worker (enforced by depguard).
package edge

import (
	"log/slog"
	"net/http"

	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
)

// Deps are the collaborators of the edge handlers.
type Deps struct {
	Log   *slog.Logger
	Ready *health.Runner
	// ContentKeys reads content keys for the key endpoint (M4). No endpoint uses it yet.
	ContentKeys *contentkey.Manager
}

// Edge is the data-plane HTTP handler.
type Edge struct {
	router  *httpx.Router
	handler http.Handler
}

// New builds the edge handler: generated routes on a problem-aware router, wrapped in the
// standard middleware (request ID, access log, panic recovery).
func New(d Deps) *Edge {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	router := httpx.NewRouter()
	strict := gen.NewStrictHandlerWithOptions(&server{ready: d.Ready}, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  httpx.RequestErrorHandler,
		ResponseErrorHandlerFunc: httpx.ResponseErrorHandler,
	})
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: httpx.RequestErrorHandler,
	})
	return &Edge{router: router, handler: httpx.Chain(router, httpx.Standard(d.Log)...)}
}

// Handler returns the full handler chain, ready for an http.Server.
func (e *Edge) Handler() http.Handler { return e.handler }

// Routes returns the registered route patterns, sorted, for example "GET /healthz".
func (e *Edge) Routes() []string { return e.router.Patterns() }
