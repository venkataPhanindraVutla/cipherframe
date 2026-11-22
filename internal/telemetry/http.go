package telemetry

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// KeyRoute is the template of the content key route; requests to it also feed
// cipherframe_key_request_duration_seconds.
const KeyRoute = "/v1/play/{session_id}/key"

type routeKey struct{}

// routeHolder carries the matched pattern from the router back to the middleware. The router
// matches on a copy of the request that outer middleware cannot see, so it reports through the
// context instead.
type routeHolder struct{ pattern string }

// SetRoute is called by the router once it has matched a request. pattern is the ServeMux
// pattern ("GET /v1/assets/{asset_id}"), empty when nothing matched.
func SetRoute(ctx context.Context, pattern string) {
	if h, ok := ctx.Value(routeKey{}).(*routeHolder); ok {
		h.pattern = pattern
	}
}

// template reduces a ServeMux pattern to the route template: the method and host are dropped.
func template(pattern string) string {
	if pattern == "" {
		return RouteOther
	}
	if _, p, ok := strings.Cut(pattern, " "); ok {
		pattern = p
	}
	if i := strings.IndexByte(pattern, '/'); i > 0 {
		pattern = pattern[i:]
	}
	return pattern
}

func knownMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect:
		return m
	}
	return "OTHER"
}

// statusClass is "2xx" for 200..299 and so on.
func statusClass(status int) string { return strconv.Itoa(status/100) + "xx" }

// Middleware records a span and the request duration histogram for every request of service
// ("api" or "edge"). Put it outermost, so it covers the whole chain, and make the router call
// SetRoute.
//
// The span is named "METHOD template" and carries only the method, the route template and the
// status code. It never records the URL, the path, the query, the client address, the user agent
// or any header, because paths and queries carry session IDs, tokens and signed parameters.
// An incoming traceparent header is honoured as the parent.
func Middleware(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t := cur()
			if t == nil {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			method := knownMethod(r.Method)
			holder := &routeHolder{}
			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			ctx = context.WithValue(ctx, routeKey{}, holder)
			ctx, span := t.tracer.Start(ctx, "HTTP "+method, trace.WithSpanKind(trace.SpanKindServer))
			rec := &statusWriter{ResponseWriter: w}
			done := false
			defer func() {
				status := rec.status()
				if !done { // a panic is on its way out; the recovery middleware will answer 500
					status = http.StatusInternalServerError
				}
				route := template(holder.pattern)
				if status >= 500 {
					span.SetStatus(codes.Error, "")
				}
				span.SetName(method + " " + route)
				span.SetAttributes(
					attribute.String("http.request.method", method),
					attribute.String("http.route", route),
					attribute.Int("http.response.status_code", status),
				)
				span.End()
				d := time.Since(start)
				t.m.httpDuration.WithLabelValues(service, route, method, statusClass(status)).Observe(d.Seconds())
				if service == "edge" && route == KeyRoute {
					t.m.keyDuration.WithLabelValues(keyOutcome(status)).Observe(d.Seconds())
				}
			}()
			next.ServeHTTP(rec, r.WithContext(ctx))
			done = true
		})
	}
}

// keyOutcome maps the status of a key response to its fixed outcome.
func keyOutcome(status int) string {
	switch {
	case status/100 == 2:
		return KeyServed
	case status == http.StatusUnauthorized, status == http.StatusForbidden, status == http.StatusTooManyRequests:
		return KeyDenied
	case status == http.StatusNotFound:
		return KeyNotFound
	}
	return KeyError
}

// statusWriter records the response status.
type statusWriter struct {
	http.ResponseWriter
	code    int
	written bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.written {
		s.code, s.written = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.written {
		s.code, s.written = http.StatusOK, true
	}
	return s.ResponseWriter.Write(b)
}

// Flush lets streaming handlers flush through the wrapper.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		if !s.written {
			s.code, s.written = http.StatusOK, true
		}
		f.Flush()
	}
}

// Unwrap supports http.ResponseController.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) status() int {
	if s.code == 0 {
		return http.StatusOK
	}
	return s.code
}
