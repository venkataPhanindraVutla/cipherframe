package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/reqid"
)

// RequestIDHeader carries the request ID on requests and responses.
const RequestIDHeader = "X-Request-Id"

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so that the first one is outermost.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// Standard returns the middleware every listener uses, outermost first: request ID, access log,
// panic recovery. Recovery sits inside the access log so a recovered panic is logged as a 500.
func Standard(log *slog.Logger) []Middleware {
	return []Middleware{RequestID(log), AccessLog(), Recover()}
}

type loggerKey struct{}

// WithLogger returns a context carrying log.
func WithLogger(ctx context.Context, log *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, log)
}

// Logger returns the request-scoped logger stored by RequestID, which already carries the
// request_id attribute. It falls back to slog.Default.
func Logger(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// RequestID gives every request a request ID (ADR 0012). A valid UUID in the incoming
// X-Request-Id header is kept (normalised to lowercase); anything else, including a missing
// header, is replaced by a new UUIDv7. The ID goes into the response header, the request context
// and a request-scoped logger derived from base.
func RequestID(base *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := reqid.Sanitize(r.Header.Get(RequestIDHeader))
			if !ok {
				id = reqid.New()
			}
			w.Header().Set(RequestIDHeader, id)
			ctx := reqid.WithContext(r.Context(), id)
			ctx = WithLogger(ctx, base.With(slog.String("request_id", id)))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AccessLog logs one line per request: method, route pattern, status and duration, plus the
// request ID from the request-scoped logger.
//
// It deliberately never logs the URL: not the query string, which can carry tokens, and not the
// path either, because later routes carry capability-like values in the path. The matched route
// pattern (for example "GET /v1/assets/{asset_id}") identifies the endpoint without them. Header
// values (Authorization and all others) are never logged.
func AccessLog() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(rec, r)

			route := r.Pattern // set by the router on this same *http.Request
			if route == "" {
				route = "unmatched"
			}
			level := slog.LevelInfo
			switch st := rec.Status(); {
			case st == http.StatusServiceUnavailable: // an unready dependency, not a server bug
				level = slog.LevelWarn
			case st >= 500:
				level = slog.LevelError
			}
			Logger(r.Context()).LogAttrs(r.Context(), level, "request",
				slog.String("method", knownMethod(r.Method)),
				slog.String("route", route),
				slog.Int("status", rec.Status()),
				slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
			)
		})
	}
}

// knownMethod returns m if it is a standard HTTP method and "OTHER" otherwise, so a client cannot
// write arbitrary text into the log through the method.
func knownMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect:
		return m
	default:
		return "OTHER"
	}
}

// Recover turns a handler panic into a 500 internal_error problem. The panic value is not logged
// (it may carry request data); its type and the stack are. http.ErrAbortHandler is re-panicked
// as the net/http contract requires.
func Recover() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				Logger(r.Context()).LogAttrs(r.Context(), slog.LevelError, "panic recovered",
					slog.String("panic_type", fmt.Sprintf("%T", v)),
					slog.String("stack", string(debug.Stack())),
				)
				if sw, ok := w.(*statusWriter); ok && sw.Written() {
					return // the response has started; nothing sensible can be added
				}
				WriteProblem(w, r, errs.New(errs.InternalError, "An internal error occurred."))
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// statusWriter records the status code and whether the response has started.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.written {
		s.status, s.written = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.written {
		s.status, s.written = http.StatusOK, true
	}
	return s.ResponseWriter.Write(b)
}

// Flush lets streaming handlers flush through the wrapper.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		if !s.written {
			s.status, s.written = http.StatusOK, true
		}
		f.Flush()
	}
}

// Unwrap supports http.ResponseController.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Status returns the response status, 200 if nothing was written.
func (s *statusWriter) Status() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

// Written reports whether the response has started.
func (s *statusWriter) Written() bool { return s.written }
