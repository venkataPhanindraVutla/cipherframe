// Package api is the control-plane listener (ADR 0008): server-to-server endpoints called by the
// embedding application. The handlers implement the strict server interface generated from
// spec/openapi.yaml into package gen.
//
// This package must not import internal/edge or internal/worker (enforced by depguard).
package api

import (
	"log/slog"
	"net/http"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
)

// Deps are the collaborators of the API handlers. Later tasks add repositories, the storage port
// and authentication here.
type Deps struct {
	Log   *slog.Logger
	Ready *health.Runner
}

// API is the control-plane HTTP handler.
type API struct {
	router  *httpx.Router
	handler http.Handler
}

// New builds the API: generated routes on a problem-aware router, wrapped in the standard
// middleware (request ID, access log, panic recovery).
func New(d Deps) *API {
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
	return &API{router: router, handler: httpx.Chain(router, httpx.Standard(d.Log)...)}
}

// Handler returns the full handler chain, ready for an http.Server.
func (a *API) Handler() http.Handler { return a.handler }

// Routes returns the registered route patterns, sorted, for example "GET /healthz". The contract
// test compares them with the operations in the spec.
func (a *API) Routes() []string { return a.router.Patterns() }
