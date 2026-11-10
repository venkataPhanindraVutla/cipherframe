// Package httpx holds the HTTP plumbing shared by the api and edge listeners: a router that
// answers unknown paths and methods with problem responses, request ID, access log and panic
// recovery middleware, problem-shaped error handlers for generated strict servers, and
// http.Server construction with graceful shutdown.
//
// Nothing here logs a query string, a request header value, a request body or an error cause
// that is not already safe to log (ADR 0012, invariant 9).
package httpx

import (
	"net/http"
	"sort"
	"sync"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// Router is an http.ServeMux that remembers the patterns registered on it and answers requests
// that match no pattern with RFC 9457 problems instead of the standard library's plain text:
// 404 not_found for an unknown path and 405 method_not_allowed (with an Allow header) when the
// path exists for other methods.
//
// Its HandleFunc method makes it usable as the BaseRouter of oapi-codegen's generated handlers.
type Router struct {
	mux *http.ServeMux

	mu       sync.Mutex
	patterns []string
}

// NewRouter returns an empty Router.
func NewRouter() *Router { return &Router{mux: http.NewServeMux()} }

// HandleFunc registers handler for pattern, using http.ServeMux pattern syntax.
func (rt *Router) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	rt.mux.HandleFunc(pattern, handler)
	rt.mu.Lock()
	rt.patterns = append(rt.patterns, pattern)
	rt.mu.Unlock()
}

// Patterns returns the registered patterns, sorted. Tests compare it with the spec.
func (rt *Router) Patterns() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := append([]string(nil), rt.patterns...)
	sort.Strings(out)
	return out
}

// ServeHTTP dispatches r. The matched pattern is available as r.Pattern afterwards.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h, pattern := rt.mux.Handler(r)
	if pattern != "" {
		rt.mux.ServeHTTP(w, r) // also sets r.Pattern and path values
		return
	}
	// No pattern matched. The mux's own handler decides between 404, 405 and a clean-path
	// redirect; run it against a probe so the plain-text body never reaches the client.
	probe := &probeWriter{header: http.Header{}}
	h.ServeHTTP(probe, r)
	switch probe.status {
	case http.StatusNotFound:
		WriteProblem(w, r, errs.New(errs.NotFound, "No such resource."))
	case http.StatusMethodNotAllowed:
		if allow := probe.header.Get("Allow"); allow != "" {
			w.Header().Set("Allow", allow)
		}
		WriteProblem(w, r, errs.New(errs.MethodNotAllowed, "This method is not supported for this resource."))
	default: // redirect to the cleaned path
		for k, v := range probe.header {
			w.Header()[k] = v
		}
		w.WriteHeader(probe.status)
	}
}

// probeWriter records a status and headers and discards the body.
type probeWriter struct {
	header http.Header
	status int
}

func (p *probeWriter) Header() http.Header { return p.header }

func (p *probeWriter) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	return len(b), nil
}

func (p *probeWriter) WriteHeader(code int) {
	if p.status == 0 {
		p.status = code
	}
}
