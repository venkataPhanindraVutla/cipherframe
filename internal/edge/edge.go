// Package edge is the browser-facing data-plane listener (ADR 0008): health and readiness, the
// upload endpoints, and the session-scoped playlists, segments and content key (play.go,
// play_key.go).
//
// This package must not import internal/api or internal/worker (enforced by depguard).
package edge

import (
	"log/slog"
	"net/http"

	"github.com/venkataPhanindraVutla/cipherframe/internal/accesslog"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
)

// Deps are the collaborators of the edge handlers.
type Deps struct {
	Log   *slog.Logger
	Ready *health.Runner
	// Uploads serves the upload endpoints (M3-2). Without it they answer 503
	// dependency_unavailable.
	Uploads *Uploads
	// Playback serves the session-scoped playlists and segments (M4-3). Without it those routes
	// answer 503 dependency_unavailable.
	Playback *Playback
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
	strict := gen.NewStrictHandlerWithOptions(&server{ready: d.Ready, up: d.Uploads, play: d.Playback}, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  httpx.RequestErrorHandler,
		ResponseErrorHandlerFunc: writeAuthError,
	})
	gen.HandlerWithOptions(guarded{ServerInterface: strict, up: d.Uploads, play: d.Playback}, gen.StdHTTPServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: httpx.RequestErrorHandler,
	})
	router.Mount(TusMount, tusHandler(d.Uploads))
	mw := append(httpx.Standard(d.Log), accesslog.Middleware(), playGate(d.Playback), uploadCORS)
	return &Edge{router: router, handler: httpx.Chain(router, mw...)}
}

// tusHandler returns the mounted tus handler, or one that answers 503 when the process has no
// upload machinery. A tusd configuration error is a programming error and fails at startup.
func tusHandler(up *Uploads) http.Handler {
	if up == nil || up.Authz == nil || up.Tus == nil || up.Locker == nil {
		return tusUnavailable()
	}
	h, err := newTus(up)
	if err != nil {
		panic("edge: tus handler: " + err.Error())
	}
	return h
}

// Handler returns the full handler chain, ready for an http.Server.
func (e *Edge) Handler() http.Handler { return e.handler }

// Routes returns the registered route patterns, sorted, for example "GET /healthz". Mounted
// handlers that the spec documents but does not generate (tus) are in Mounts.
func (e *Edge) Routes() []string { return e.router.Patterns() }

// Mounts returns the path prefixes of handlers mounted from libraries, sorted.
func (e *Edge) Mounts() []string { return e.router.Mounts() }
