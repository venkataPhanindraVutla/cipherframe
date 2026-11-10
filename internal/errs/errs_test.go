package errs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// declared lists every Code constant. When adding a constant, add it here and to registry.
var declared = []Code{
	InvalidRequest, Unauthenticated, Forbidden, NotFound, Conflict,
	PayloadTooLarge, RateLimited, InternalError, DependencyUnavailable, Timeout,
}

func marshal(t *testing.T, p Problem) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDeclaredCodesMatchRegistry(t *testing.T) {
	want := slices.Clone(declared)
	slices.Sort(want)
	if got := Codes(); !slices.Equal(got, want) {
		t.Fatalf("registry %v != declared %v", got, want)
	}
	for _, c := range declared {
		i, ok := Lookup(c)
		if !ok || i.Status < 400 || i.Status > 599 || i.Title == "" {
			t.Errorf("bad registry entry for %q: %+v", c, i)
		}
		if string(c) != strings.ToLower(string(c)) || strings.ContainsAny(string(c), " -") {
			t.Errorf("code %q is not lower_snake_case", c)
		}
	}
}

func TestRegistryValues(t *testing.T) {
	cases := map[Code]struct {
		status int
		retry  bool
	}{
		InvalidRequest: {400, false}, Unauthenticated: {401, false}, Forbidden: {403, false},
		NotFound: {404, false}, Conflict: {409, false}, PayloadTooLarge: {413, false},
		RateLimited: {429, true}, InternalError: {500, false},
		DependencyUnavailable: {503, true}, Timeout: {504, true},
	}
	for c, w := range cases {
		i, _ := Lookup(c)
		if i.Status != w.status || i.Retryable != w.retry {
			t.Errorf("%s: got %+v want %+v", c, i, w)
		}
	}
}

func TestGoldenNotFound(t *testing.T) {
	got := marshal(t, ToProblem(New(NotFound, "Asset not found."), "req-1"))
	const want = `{"type":"urn:cipherframe:error:not_found","title":"Not found","status":404,` +
		`"detail":"Asset not found.","code":"not_found","retryable":false,"request_id":"req-1"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestGoldenUnknownErrorHidesText(t *testing.T) {
	leak := "dial tcp 10.0.0.5:5432: pw=hunter2 obj=s3/source/abc.mp4"
	for _, err := range []error{
		errors.New(leak),
		fmt.Errorf("wrapped: %w", errors.New(leak)),
		Wrap(Code("made_up"), "detail with "+leak, errors.New(leak)),
		nil,
	} {
		got := marshal(t, ToProblem(err, "req-2"))
		const want = `{"type":"urn:cipherframe:error:internal_error","title":"Internal error","status":500,` +
			`"detail":"An internal error occurred.","code":"internal_error","retryable":false,"request_id":"req-2"}`
		if got != want {
			t.Fatalf("got  %s\nwant %s", got, want)
		}
		if strings.Contains(got, "hunter2") || strings.Contains(got, "s3/") {
			t.Fatal("internal text leaked")
		}
	}
}

func TestWrappedFoundThroughAs(t *testing.T) {
	inner := Wrap(DependencyUnavailable, "Storage is unavailable.", errors.New("boom: secret"))
	outer := fmt.Errorf("handler: %w", inner)
	var e *Error
	if !errors.As(outer, &e) || e.Code != DependencyUnavailable {
		t.Fatal("errors.As did not find *Error")
	}
	p := ToProblem(outer, "r")
	if p.Code != DependencyUnavailable || p.Status != 503 || !p.Retryable || p.Detail != "Storage is unavailable." {
		t.Fatalf("unexpected problem %+v", p)
	}
}

func TestErrorTextAndUnwrap(t *testing.T) {
	cause := errors.New("secret cause")
	e := Wrap(Conflict, "Already exists.", cause)
	if strings.Contains(e.Error(), "secret") || e.Error() != "conflict: Already exists." {
		t.Fatalf("Error() = %q", e.Error())
	}
	if !errors.Is(e, cause) {
		t.Fatal("cause not reachable")
	}
	if New(Timeout, "").Error() != "timeout" {
		t.Fatal("empty detail form wrong")
	}
}

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, New(RateLimited, "Slow down."), "req-3")
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
	body := rec.Body.String()
	for _, s := range []string{`"code":"rate_limited"`, `"retryable":true`, `"request_id":"req-3"`, `"status":429`} {
		if !strings.Contains(body, s) {
			t.Errorf("body missing %s: %s", s, body)
		}
	}
}

func TestWriteUnknownIs500(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, errors.New("kaboom"), "x")
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "kaboom") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
