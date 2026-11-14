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
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// maxBodyBytes caps request bodies on the control plane. Its JSON bodies are a few hundred bytes.
const maxBodyBytes = 64 << 10

// Deps are the collaborators of the API handlers. Later tasks add the storage port here.
//
// Verifier and Manager come together: the verifier authenticates every /v1/ request and the
// manager serves the management endpoints. Without a Verifier, /v1/ requests that carry a
// well-formed Authorization header get 503 dependency_unavailable (health endpoints still work).
type Deps struct {
	Log      *slog.Logger
	Ready    *health.Runner
	Verifier *auth.Verifier
	Manager  *auth.Manager
	// ContentKeys creates, reads and destroys content keys (M2-1). No endpoint uses it yet.
	ContentKeys *contentkey.Manager
	// Assets serves the asset endpoints (M3-1). Without it they answer 503 dependency_unavailable.
	Assets *uploads.Service
	// Playback serves the playback-session and playback-settings endpoints (M4-1). Without it
	// they answer 503 dependency_unavailable.
	Playback *playback.Service
	// Signing manages the integrity signing keys (M5-2). Without it the admin endpoints answer 503
	// dependency_unavailable.
	Signing *signing.Manager
	// KeySet serves the public key set (/.well-known/cipherframe-keys.json). Without it the
	// endpoint answers 503.
	KeySet *signing.KeySet
	// Repos serves the integrity endpoints (manifest, proof, verify; M5-3), together with KeySet.
	// Without either they answer 503 dependency_unavailable.
	Repos *db.Repos
}

// API is the control-plane HTTP handler.
type API struct {
	router  *httpx.Router
	handler http.Handler
}

// New builds the API: generated routes on a problem-aware router, wrapped in the standard
// middleware (request ID, access log, panic recovery, body size cap). Secured operations
// authenticate and check scopes before their handler runs (see guard.go).
func New(d Deps) *API {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	router := httpx.NewRouter()
	strict := gen.NewStrictHandlerWithOptions(&server{ready: d.Ready, mgr: d.Manager, assets: d.Assets, playback: d.Playback, signing: d.Signing, keyset: d.KeySet, repos: d.Repos}, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  httpx.RequestErrorHandler,
		ResponseErrorHandlerFunc: httpx.ResponseErrorHandler,
	})
	guard := guarded{ServerInterface: strict, a: &authn{verifier: d.Verifier, log: d.Log}}
	gen.HandlerWithOptions(guard, gen.StdHTTPServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: httpx.RequestErrorHandler,
	})
	mw := append(httpx.Standard(d.Log), httpx.LimitBody(maxBodyBytes))
	return &API{router: router, handler: httpx.Chain(router, mw...)}
}

// Handler returns the full handler chain, ready for an http.Server.
func (a *API) Handler() http.Handler { return a.handler }

// Routes returns the registered route patterns, sorted, for example "GET /healthz". The contract
// test compares them with the operations in the spec.
func (a *API) Routes() []string { return a.router.Patterns() }
