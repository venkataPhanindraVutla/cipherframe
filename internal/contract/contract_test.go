// Package contract holds the tests that keep the running server and spec/openapi.yaml in step
// (ADR 0015). It contains only tests: they build the real handler chains of both listeners,
// send real HTTP requests, and validate every request and response against the spec with
// kin-openapi.
//
// This package may import internal/api and internal/edge because the import rule (ADR 0008)
// applies to those packages, not to a test package that exercises both.
package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/reqid"
)

const specPath = "../../spec/openapi.yaml"

func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Fatalf("spec must be OpenAPI 3.1, got %q", doc.OpenAPI)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("spec is not a valid OpenAPI document: %v", err)
	}
	return doc
}

// specRouter matches requests to spec operations by path template and method. It implements
// routers.Router without the gorilla/mux dependency of kin-openapi's own routers.
type specRouter struct{ doc *openapi3.T }

func (sr specRouter) FindRoute(req *http.Request) (*routers.Route, map[string]string, error) {
	reqSegs := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	for _, path := range sr.doc.Paths.InMatchingOrder() {
		params, ok := matchTemplate(strings.Split(strings.Trim(path, "/"), "/"), reqSegs)
		if !ok {
			continue
		}
		item := sr.doc.Paths.Value(path)
		op := item.GetOperation(req.Method)
		if op == nil {
			return nil, nil, routers.ErrMethodNotAllowed
		}
		return &routers.Route{Spec: sr.doc, Path: path, PathItem: item, Method: req.Method, Operation: op}, params, nil
	}
	return nil, nil, routers.ErrPathNotFound
}

func matchTemplate(tmpl, got []string) (map[string]string, bool) {
	if len(tmpl) != len(got) {
		return nil, false
	}
	params := map[string]string{}
	for i, seg := range tmpl {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			params[seg[1:len(seg)-1]] = got[i]
		} else if seg != got[i] {
			return nil, false
		}
	}
	return params, true
}

// operations returns "METHOD path" for every spec operation carrying tag.
func operations(doc *openapi3.T, tag string) []string {
	var out []string
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if slices.Contains(op.Tags, tag) {
				out = append(out, method+" "+path)
			}
		}
	}
	sort.Strings(out)
	return out
}

// listener is one HTTP listener under test.
type listener struct {
	name    string
	handler http.Handler
	routes  []string
}

// build returns both listeners wired with the given readiness checkers.
func build(checkers ...health.Checker) []listener {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ready := health.NewRunner(log, 200*time.Millisecond, checkers...)
	a := api.New(api.Deps{Log: log, Ready: ready})
	e := edge.New(edge.Deps{Log: log, Ready: ready})
	return []listener{
		{"api", a.Handler(), a.Routes()},
		{"edge", e.Handler(), e.Routes()},
	}
}

func okCheck(name string) health.Checker {
	return health.Func(name, func(context.Context) error { return nil })
}

func downCheck(name string) health.Checker {
	return health.Func(name, func(context.Context) error {
		return errors.New("dial tcp 10.0.0.5:5432: password authentication failed")
	})
}

type exchange struct {
	req  *http.Request
	resp *http.Response
	body []byte
}

func do(t *testing.T, base, method, path string, hdr map[string]string) exchange {
	t.Helper()
	return doBody(t, base, method, path, hdr, nil)
}

// doBody is do with a JSON request body (nil for none).
func doBody(t *testing.T, base, method, path string, hdr map[string]string, body []byte) exchange {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil { // the client consumed the body; the spec validator needs to read it again
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	return exchange{req, resp, out}
}

// validate checks the exchange against the spec. When the spec has no operation for the request
// (unknown path, method not allowed), the response must still be a valid Problem. It returns the
// matched operation ID, or "" when none matched.
func validate(t *testing.T, doc *openapi3.T, ex exchange) string {
	t.Helper()
	ctx := context.Background()
	route, params, err := specRouter{doc}.FindRoute(ex.req)
	if err != nil {
		if !errors.Is(err, routers.ErrPathNotFound) && !errors.Is(err, routers.ErrMethodNotAllowed) {
			t.Fatalf("router: %v", err)
		}
		validateProblem(t, doc, ex)
		return ""
	}
	in := &openapi3filter.RequestValidationInput{
		Request:    ex.req,
		PathParams: params,
		Route:      route,
		Options:    &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
	}
	if err := openapi3filter.ValidateRequest(ctx, in); err != nil {
		t.Fatalf("request does not match the spec: %v", err)
	}
	out := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in,
		Status:                 ex.resp.StatusCode,
		Header:                 ex.resp.Header,
		Options:                &openapi3filter.Options{IncludeResponseStatus: true},
	}
	out.SetBodyBytes(ex.body)
	if err := openapi3filter.ValidateResponse(ctx, out); err != nil {
		t.Fatalf("response %d for %s %s does not match the spec: %v\nbody: %s",
			ex.resp.StatusCode, ex.req.Method, ex.req.URL.Path, err, ex.body)
	}
	return route.Operation.OperationID
}

// validateProblem checks a response for a request the spec does not describe against the
// components every error response uses.
func validateProblem(t *testing.T, doc *openapi3.T, ex exchange) {
	t.Helper()
	if ct := ex.resp.Header.Get("Content-Type"); ct != errs.ContentType {
		t.Fatalf("content type = %q, want %q", ct, errs.ContentType)
	}
	var v any
	if err := json.Unmarshal(ex.body, &v); err != nil {
		t.Fatalf("problem body is not JSON: %v: %s", err, ex.body)
	}
	if err := doc.Components.Schemas["Problem"].Value.VisitJSON(v); err != nil {
		t.Fatalf("problem body does not match the Problem schema: %v: %s", err, ex.body)
	}
	hdr := doc.Components.Headers["XRequestId"].Value.Schema.Value
	if err := hdr.VisitJSON(ex.resp.Header.Get("X-Request-Id")); err != nil {
		t.Fatalf("X-Request-Id header does not match the spec: %v", err)
	}
	var p errs.Problem
	if err := json.Unmarshal(ex.body, &p); err != nil || p.Status != ex.resp.StatusCode || p.RequestID != ex.resp.Header.Get("X-Request-Id") {
		t.Fatalf("problem disagrees with the response: %+v (status %d)", p, ex.resp.StatusCode)
	}
}

func TestContract(t *testing.T) {
	doc := loadSpec(t)
	const incoming = "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35"

	type tc struct {
		name, method, path string
		hdr                map[string]string
		status             int
		opID               string
	}
	healthyCases := []tc{
		{"liveness", "GET", "/healthz", nil, 200, "getHealthz"},
		{"liveness with incoming request id", "GET", "/healthz", map[string]string{"X-Request-Id": incoming}, 200, "getHealthz"},
		{"liveness with invalid request id", "GET", "/healthz", map[string]string{"X-Request-Id": "not a uuid"}, 200, "getHealthz"},
		{"readiness ok", "GET", "/readyz", nil, 200, "getReadyz"},
		{"unknown path", "GET", "/nope", nil, 404, ""},
		{"unknown nested path with query", "GET", "/v1/assets/ast_x?token=abc", nil, 404, ""},
		{"method not allowed on healthz", "POST", "/healthz", nil, 405, ""},
		{"method not allowed on readyz", "DELETE", "/readyz", nil, 405, ""},
	}
	unhealthyCases := []tc{
		{"readiness failing", "GET", "/readyz", nil, 503, "getReadyz"},
		{"liveness unaffected by failing dependencies", "GET", "/healthz", nil, 200, "getHealthz"},
	}

	for _, set := range []struct {
		name     string
		checkers []health.Checker
		cases    []tc
	}{
		{"healthy", []health.Checker{okCheck("database"), okCheck("storage_source")}, healthyCases},
		{"unhealthy", []health.Checker{okCheck("database"), downCheck("storage_source")}, unhealthyCases},
	} {
		for _, l := range build(set.checkers...) {
			srv := httptest.NewServer(l.handler)
			t.Cleanup(srv.Close)
			for _, c := range set.cases {
				t.Run(l.name+"/"+set.name+"/"+c.name, func(t *testing.T) {
					ex := do(t, srv.URL, c.method, c.path, c.hdr)
					if ex.resp.StatusCode != c.status {
						t.Fatalf("status = %d, want %d; body %s", ex.resp.StatusCode, c.status, ex.body)
					}
					if got := validate(t, doc, ex); got != c.opID {
						t.Fatalf("matched operation %q, want %q", got, c.opID)
					}
					id := ex.resp.Header.Get("X-Request-Id")
					if want := c.hdr["X-Request-Id"]; want == incoming && id != incoming {
						t.Fatalf("valid incoming request ID not echoed: %q", id)
					}
					if _, ok := reqid.Sanitize(id); !ok {
						t.Fatalf("response request ID %q is not a UUID", id)
					}
					if c.status == 405 && ex.resp.Header.Get("Allow") == "" {
						t.Fatal("405 without an Allow header")
					}
				})
			}
		}
	}
}

// TestReadinessRevealsOnlyCheckNames proves the 503 body carries names and pass/fail, no error
// text, host or credential.
func TestReadinessRevealsOnlyCheckNames(t *testing.T) {
	for _, l := range build(okCheck("database"), downCheck("storage_source")) {
		srv := httptest.NewServer(l.handler)
		t.Cleanup(srv.Close)
		ex := do(t, srv.URL, "GET", "/readyz", nil)
		var got struct {
			Status string
			Checks []struct{ Name, Status string }
		}
		if err := json.Unmarshal(ex.body, &got); err != nil {
			t.Fatal(err)
		}
		if got.Status != "unavailable" || len(got.Checks) != 2 ||
			got.Checks[0] != struct{ Name, Status string }{"database", "ok"} ||
			got.Checks[1] != struct{ Name, Status string }{"storage_source", "unavailable"} {
			t.Fatalf("%s: unexpected body %s", l.name, ex.body)
		}
		for _, banned := range []string{"10.0.0.5", "password", "dial tcp", "authentication"} {
			if bytes.Contains(ex.body, []byte(banned)) {
				t.Fatalf("%s: readiness body leaks %q: %s", l.name, banned, ex.body)
			}
		}
	}
}

// TestRouteCoverage asserts that the operations the spec assigns to a listener are exactly the
// routes registered on it.
func TestRouteCoverage(t *testing.T) {
	doc := loadSpec(t)
	for _, l := range build() {
		want := operations(doc, l.name)
		if len(want) == 0 {
			t.Fatalf("%s: spec has no operations tagged %q", l.name, l.name)
		}
		if !slices.Equal(l.routes, want) {
			t.Errorf("%s: registered routes differ from the spec\n  routes: %v\n  spec:   %v", l.name, l.routes, want)
		}
	}
}

// TestEveryOperationIsServed fails when a spec operation names no listener, because it would then
// be documented but never served.
func TestEveryOperationIsServed(t *testing.T) {
	doc := loadSpec(t)
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if !slices.Contains(op.Tags, "api") && !slices.Contains(op.Tags, "edge") {
				t.Errorf("%s %s has neither the api nor the edge tag", method, path)
			}
			if op.OperationID == "" {
				t.Errorf("%s %s has no operationId", method, path)
			}
		}
	}
}

// TestProblemCodeEnumMatchesRegistry keeps the spec's error-code enum identical to errs.Codes().
func TestProblemCodeEnumMatchesRegistry(t *testing.T) {
	doc := loadSpec(t)
	code := doc.Components.Schemas["Problem"].Value.Properties["code"].Value
	var got []string
	for _, v := range code.Enum {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("enum value %v is not a string", v)
		}
		got = append(got, s)
	}
	var want []string
	for _, c := range errs.Codes() {
		want = append(want, string(c))
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Fatalf("Problem.code enum %v != errs.Codes() %v", got, want)
	}
}
