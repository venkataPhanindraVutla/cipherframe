package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/reqid"
)

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func problemOf(t *testing.T, rec *httptest.ResponseRecorder) errs.Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != errs.ContentType {
		t.Fatalf("content type = %q, want %q", ct, errs.ContentType)
	}
	var p errs.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not a problem: %v: %s", err, rec.Body.String())
	}
	return p
}

func newOKHandler(buf *bytes.Buffer) (http.Handler, *Router) {
	rt := NewRouter()
	rt.HandleFunc("GET /ok/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return Chain(rt, Standard(testLogger(buf))...), rt
}

func TestRequestIDValidIncomingKept(t *testing.T) {
	var buf bytes.Buffer
	h, _ := newOKHandler(&buf)
	const in = "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ok/1", nil)
	req.Header.Set(RequestIDHeader, strings.ToUpper(in))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get(RequestIDHeader); got != in {
		t.Fatalf("request ID = %q, want %q (kept, lowercased)", got, in)
	}
	if !strings.Contains(buf.String(), `"request_id":"`+in+`"`) {
		t.Fatalf("log line lacks the request ID: %s", buf.String())
	}
}

func TestRequestIDInvalidIncomingReplaced(t *testing.T) {
	var buf bytes.Buffer
	h, _ := newOKHandler(&buf)
	for _, bad := range []string{"", "not-a-uuid", "x\ninjected", strings.Repeat("a", 500), "{0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35}"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ok/1", nil)
		if bad != "" {
			req.Header["X-Request-Id"] = []string{bad}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		got := rec.Header().Get(RequestIDHeader)
		if got == bad {
			t.Fatalf("invalid ID %q was kept", bad)
		}
		if _, ok := reqid.Sanitize(got); !ok {
			t.Fatalf("replacement %q is not a valid UUID", got)
		}
	}
}

func TestRecoverReturnsProblem(t *testing.T) {
	var buf bytes.Buffer
	rt := NewRouter()
	rt.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("secret-token-value") })
	h := Chain(rt, Standard(testLogger(&buf))...)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	p := problemOf(t, rec)
	if p.Code != errs.InternalError || p.RequestID == "" || p.RequestID != rec.Header().Get(RequestIDHeader) {
		t.Fatalf("unexpected problem %+v", p)
	}
	if strings.Contains(rec.Body.String(), "secret-token-value") || strings.Contains(buf.String(), "secret-token-value") {
		t.Fatal("panic value leaked into the response or the log")
	}
	if !strings.Contains(buf.String(), "panic recovered") || !strings.Contains(buf.String(), `"status":500`) {
		t.Fatalf("expected panic and 500 access log lines: %s", buf.String())
	}
}

func TestRecoverAfterResponseStarted(t *testing.T) {
	var buf bytes.Buffer
	rt := NewRouter()
	rt.HandleFunc("GET /half", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		panic("late")
	})
	h := Chain(rt, Standard(testLogger(&buf))...)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/half", nil))
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("response was changed after it started: %d %q", rec.Code, rec.Body.String())
	}
}

func TestRecoverRepanicsAbortHandler(t *testing.T) {
	var buf bytes.Buffer
	rt := NewRouter()
	rt.HandleFunc("GET /abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	h := Chain(rt, Standard(testLogger(&buf))...)
	defer func() {
		if recover() != http.ErrAbortHandler { //nolint:errorlint // the net/http contract panics with this exact value
			t.Fatal("http.ErrAbortHandler was swallowed")
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/abort", nil))
}

func TestAccessLogNeverContainsQueryOrAuthorization(t *testing.T) {
	var buf bytes.Buffer
	h, _ := newOKHandler(&buf)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ok/ses_topsecretvalue?token=querysecret&X-Amz-Signature=sig", nil)
	req.Header.Set("Authorization", "Bearer headersecret")
	req.Header.Set("Cookie", "sid=cookiesecret")
	h.ServeHTTP(httptest.NewRecorder(), req)

	line := buf.String()
	for _, banned := range []string{"querysecret", "token=", "X-Amz-Signature", "headersecret", "Bearer", "Authorization", "cookiesecret", "topsecretvalue", "?"} {
		if strings.Contains(line, banned) {
			t.Fatalf("access log contains %q: %s", banned, line)
		}
	}
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log is not one JSON line: %v: %s", err, line)
	}
	if rec["method"] != "GET" || rec["route"] != "GET /ok/{id}" || rec["status"] != float64(204) || rec["request_id"] == nil || rec["duration_ms"] == nil {
		t.Fatalf("unexpected access log fields: %v", rec)
	}
}

func TestAccessLogUnmatchedRouteAndOddMethod(t *testing.T) {
	var buf bytes.Buffer
	h, _ := newOKHandler(&buf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "BREW", "/nope/secret-path?x=1", nil))
	line := buf.String()
	if !strings.Contains(line, `"route":"unmatched"`) || !strings.Contains(line, `"method":"OTHER"`) || strings.Contains(line, "secret-path") {
		t.Fatalf("unexpected log line: %s", line)
	}
}

func TestRouterProblems(t *testing.T) {
	var buf bytes.Buffer
	h, rt := newOKHandler(&buf)
	if got := rt.Patterns(); len(got) != 1 || got[0] != "GET /ok/{id}" {
		t.Fatalf("patterns = %v", got)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/missing", nil))
	if rec.Code != 404 || problemOf(t, rec).Code != errs.NotFound {
		t.Fatalf("404 case: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ok/1", nil))
	if rec.Code != 405 || problemOf(t, rec).Code != errs.MethodNotAllowed {
		t.Fatalf("405 case: %d %s", rec.Code, rec.Body.String())
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Fatalf("Allow = %q", allow)
	}
	if strings.Contains(rec.Body.String(), "page not found") {
		t.Fatal("framework text leaked")
	}
}

func TestStrictErrorHandlers(t *testing.T) {
	var buf bytes.Buffer
	mk := func(fn func(http.ResponseWriter, *http.Request, error), err error) *httptest.ResponseRecorder {
		h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fn(w, r, err) }), Standard(testLogger(&buf))...)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
		return rec
	}

	rec := mk(RequestErrorHandler, io.ErrUnexpectedEOF)
	if rec.Code != 400 || problemOf(t, rec).Code != errs.InvalidRequest || strings.Contains(rec.Body.String(), "unexpected EOF") {
		t.Fatalf("request error: %d %s", rec.Code, rec.Body.String())
	}
	rec = mk(ResponseErrorHandler, errs.New(errs.Conflict, "Already exists."))
	if rec.Code != 409 || problemOf(t, rec).Detail != "Already exists." {
		t.Fatalf("response error (errs): %d %s", rec.Code, rec.Body.String())
	}
	rec = mk(ResponseErrorHandler, io.ErrClosedPipe)
	if rec.Code != 500 || problemOf(t, rec).Code != errs.InternalError || strings.Contains(rec.Body.String(), "closed pipe") {
		t.Fatalf("response error (plain): %d %s", rec.Code, rec.Body.String())
	}
}

func TestServerLimits(t *testing.T) {
	var buf bytes.Buffer
	srv := NewServer(":0", http.NotFoundHandler(), testLogger(&buf))
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 1<<20 {
		t.Fatalf("server limits not set: %+v", srv)
	}
}

func TestServeGracefulShutdown(t *testing.T) {
	var buf bytes.Buffer
	started, release := make(chan struct{}), make(chan struct{})
	var finished atomic.Bool
	srv := NewServer("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		finished.Store(true)
		_, _ = io.WriteString(w, "done")
	}), testLogger(&buf))
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, srv, ln, 5*time.Second) }()

	type result struct {
		body string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			got <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		got <- result{string(b), err}
	}()

	<-started
	cancel() // SIGTERM equivalent: shutdown begins while the request is in flight
	select {
	case err := <-served:
		t.Fatalf("Serve returned %v before the in-flight request finished", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)

	if r := <-got; r.err != nil || r.body != "done" {
		t.Fatalf("in-flight request: %+v", r)
	}
	if err := <-served; err != nil {
		t.Fatalf("Serve = %v, want nil after a clean shutdown", err)
	}
	if !finished.Load() {
		t.Fatal("handler did not finish")
	}
	// The listener is closed: new connections are refused.
	if c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		_ = c.Close()
		t.Fatal("listener still accepting after shutdown")
	}
}

func TestServeShutdownGraceExpires(t *testing.T) {
	var buf bytes.Buffer
	started := make(chan struct{})
	srv := NewServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		time.Sleep(3 * time.Second) // outlives the grace period
	}), testLogger(&buf))
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, srv, ln, 100*time.Millisecond) }()
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started
	cancel()
	select {
	case err := <-served:
		if err == nil {
			t.Fatal("expected an error when the grace period expires")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the grace period")
	}
}
