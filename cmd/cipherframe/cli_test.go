package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

const (
	testKey   = "test-fixture-key-cf_abcdefabcdef_0123456789"
	testToken = "cfu_0123456789012345678901234567890123456789abc"
	testAsset = "ast_0123456789abcdefghjkmnpqrs"
	testReqID = "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35"
)

// fakeServer is an api and edge listener in one httptest server. Every request to a path the spec
// lists as an api operation is validated against spec/openapi.yaml, and so is every answer.
type fakeServer struct {
	t   *testing.T
	doc *openapi3.T
	srv *httptest.Server

	mu         sync.Mutex
	size       int64
	stored     bytes.Buffer
	created    map[string]any // the body of the create request
	patches    int
	heads      int
	interrupt  bool     // cut the second PATCH short once
	states     []string // states GET returns, one per call; the last repeats
	failure    string   // failure_code once state is failed
	commitCode int      // when non-zero, commit answers this status as a problem
	echoKey    bool     // problem details echo the Authorization header (to test scrubbing)
	deleted    bool
	extra      func(w http.ResponseWriter, r *http.Request, body []byte) bool // more routes (rest_test.go)
}

type testRouter struct{ doc *openapi3.T }

func (r testRouter) FindRoute(req *http.Request) (*routers.Route, map[string]string, error) {
	got := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	for _, path := range r.doc.Paths.InMatchingOrder() {
		tmpl := strings.Split(strings.Trim(path, "/"), "/")
		if len(tmpl) != len(got) {
			continue
		}
		params, ok := map[string]string{}, true
		for i, seg := range tmpl {
			if strings.HasPrefix(seg, "{") {
				params[seg[1:len(seg)-1]] = got[i]
			} else if seg != got[i] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		item := r.doc.Paths.Value(path)
		return &routers.Route{Spec: r.doc, Path: path, PathItem: item, Method: req.Method, Operation: item.GetOperation(req.Method)}, params, nil
	}
	return nil, nil, routers.ErrPathNotFound
}

func newFake(t *testing.T) *fakeServer {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("../../spec/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{t: t, doc: doc, states: []string{"ready"}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) problem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	if f.echoKey {
		detail += " " + r.Header.Get("Authorization")
	}
	w.Header().Set("Content-Type", errs.ContentType)
	w.Header().Set("X-Request-Id", testReqID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "urn:cipherframe:error:" + code, "title": http.StatusText(status), "status": status,
		"detail": detail, "code": code, "retryable": status >= 500, "request_id": testReqID,
	})
}

func (f *fakeServer) asset(state string) map[string]any {
	a := map[string]any{
		"id": testAsset, "state": state, "size_bytes": f.size, "upload_method": "tus", "mask_faces": false,
		"created_at": "2026-11-22T10:00:00Z", "updated_at": "2026-11-22T10:00:01Z",
	}
	if state == "failed" {
		a["failure_code"] = f.failure
	}
	if state == "deleting" || state == "deleted" {
		a["deletion"] = map[string]any{"reason": "requested", "requested_at": "2026-11-22T10:00:02Z"}
	}
	return a
}

func (f *fakeServer) reply(w http.ResponseWriter, status int, v any, noStore bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", testReqID)
	if noStore {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// serve validates the exchange against the spec, then answers it.
func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	isTus := strings.HasPrefix(r.URL.Path, "/v1/uploads/tus/")
	// The key reaches api paths only, the upload token edge paths only.
	want := "Bearer " + testKey
	if isTus {
		want = "Bearer " + testToken
	}
	if r.Header.Get("Authorization") != want {
		f.problem(w, r, 401, "unauthenticated", "bad credentials")
		return
	}
	rec := httptest.NewRecorder()
	var in *openapi3filter.RequestValidationInput
	if !isTus {
		r.Body = io.NopCloser(bytes.NewReader(body))
		route, params, err := testRouter{f.doc}.FindRoute(r)
		if err == nil && route.Operation != nil {
			in = &openapi3filter.RequestValidationInput{
				Request: r, PathParams: params, Route: route,
				Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
			}
			if err := openapi3filter.ValidateRequest(context.Background(), in); err != nil {
				f.t.Errorf("request %s %s does not match the spec: %v", r.Method, r.URL.Path, err)
			}
		} else {
			f.t.Errorf("no spec operation for %s %s", r.Method, r.URL.Path)
		}
	}
	f.route(rec, r, body)
	if in != nil {
		out := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: in, Status: rec.Code, Header: rec.Header(),
			Options: &openapi3filter.Options{IncludeResponseStatus: true},
		}
		out.SetBodyBytes(rec.Body.Bytes())
		if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
			f.t.Errorf("response %d for %s %s does not match the spec: %v", rec.Code, r.Method, r.URL.Path, err)
		}
	}
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (f *fakeServer) route(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	switch {
	case r.Method == "POST" && p == "/v1/assets":
		f.created = map[string]any{}
		_ = json.Unmarshal(body, &f.created)
		f.size = int64(f.created["size_bytes"].(float64))
		f.reply(w, 201, map[string]any{"asset": f.asset("created"), "upload": map[string]any{
			"method": "tus", "url": f.srv.URL + "/v1/uploads/tus/", "token": testToken, "expires_at": "2026-11-22T11:00:00Z",
		}}, true)
	case r.Method == "POST" && p == "/v1/uploads/tus/":
		if r.Header.Get("Upload-Length") != strconv.FormatInt(f.size, 10) || r.Header.Get("Tus-Resumable") != "1.0.0" {
			f.problem(w, r, 400, "invalid_request", "bad upload length")
			return
		}
		w.Header().Set("Location", "/v1/uploads/tus/"+testAsset)
		w.WriteHeader(201)
	case r.Method == "HEAD" && p == "/v1/uploads/tus/"+testAsset:
		f.heads++
		w.Header().Set("Upload-Offset", strconv.Itoa(f.stored.Len()))
		w.WriteHeader(200)
	case r.Method == "PATCH" && p == "/v1/uploads/tus/"+testAsset:
		f.patches++
		if r.Header.Get("Upload-Offset") != strconv.Itoa(f.stored.Len()) {
			w.WriteHeader(409)
			return
		}
		if f.interrupt && f.patches == 2 {
			f.stored.Write(body[:len(body)/3]) // part of the chunk arrived, then the connection drops
			f.interrupt = false
			panic(http.ErrAbortHandler)
		}
		f.stored.Write(body)
		w.Header().Set("Upload-Offset", strconv.Itoa(f.stored.Len()))
		w.WriteHeader(204)
	case r.Method == "POST" && p == "/v1/assets/"+testAsset+"/commit":
		switch {
		case f.commitCode != 0:
			f.problem(w, r, f.commitCode, "quota_exceeded", "storage is full")
		case int64(f.stored.Len()) != f.size:
			f.problem(w, r, 409, "conflict", "upload unfinished")
		default:
			f.reply(w, 200, f.asset("committed"), false)
		}
	case r.Method == "GET" && p == "/v1/assets/"+testAsset:
		st := f.states[0]
		if len(f.states) > 1 {
			f.states = f.states[1:]
		}
		f.reply(w, 200, f.asset(st), false)
	case r.Method == "GET" && p == "/v1/assets":
		f.reply(w, 200, map[string]any{"items": []any{f.asset("ready")}, "next_cursor": "c2"}, false)
	case r.Method == "DELETE" && p == "/v1/assets/"+testAsset:
		f.deleted = true
		f.reply(w, 202, f.asset("deleting"), false)
	case r.Method == "GET" && p == "/v1/assets/"+testAsset+"/deletion-record":
		if !f.deleted || f.states[0] != "deleted" {
			f.problem(w, r, 404, "not_deleted", "not deleted yet")
			return
		}
		w.Header().Set("Content-Type", "application/vnd.cipherframe.deletion+json")
		w.Header().Set("X-Request-Id", testReqID)
		_, _ = w.Write([]byte(`{"payloadType":"application/vnd.cipherframe.deletion+json","payload":"e30=","signatures":[{"keyid":"k","sig":"c2ln"}]}`))
	default:
		if f.extra != nil && f.extra(w, r, body) {
			return
		}
		f.problem(w, r, 404, "not_found", "no such asset")
	}
}

// runCLI runs the command line against f and checks that no secret reaches the output.
func runCLI(t *testing.T, f *fakeServer, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("CIPHERFRAME_SERVER", f.srv.URL)
	t.Setenv("CIPHERFRAME_API_KEY", testKey)
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	for _, s := range []string{testKey, testToken, testPlayToken, newKey} {
		if s != allowOutput && strings.Contains(out.String()+errb.String(), s) {
			t.Fatalf("a secret leaked into the output of %v:\nstdout: %s\nstderr: %s", args, out.String(), errb.String())
		}
	}
	return code, out.String(), errb.String()
}

// allowOutput is the one secret a test shows on purpose (it checks that stdout itself).
var allowOutput string

func fastPolling(t *testing.T) {
	t.Helper()
	pmin, pmax, bo := pollMin, pollMax, tusBackoff
	pollMin, pollMax = time.Millisecond, 5*time.Millisecond
	tusBackoff = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { pollMin, pollMax, tusBackoff = pmin, pmax, bo })
}

func sourceFile(t *testing.T, n int) (string, []byte) {
	t.Helper()
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i * 7)
	}
	// A name that would be a privacy problem if it were sent.
	path := filepath.Join(t.TempDir(), "private-holiday-clip.mp4")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func TestUploadResumesAfterInterruption(t *testing.T) {
	fastPolling(t)
	f := newFake(t)
	f.interrupt = true
	path, data := sourceFile(t, 20<<20) // three chunks
	code, out, errb := runCLI(t, f, "upload", path, "--mask-faces", "--ttl", "2d")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errb)
	}
	if strings.TrimSpace(out) != testAsset {
		t.Fatalf("stdout = %q", out)
	}
	if !bytes.Equal(f.stored.Bytes(), data) {
		t.Fatalf("stored %d bytes, want %d identical bytes", f.stored.Len(), len(data))
	}
	if f.heads == 0 || f.patches != 4 {
		t.Fatalf("heads=%d patches=%d, want a HEAD after the cut and 4 PATCHes (3 chunks + 1 retry)", f.heads, f.patches)
	}
	if !strings.Contains(errb, "resuming") {
		t.Fatalf("stderr does not mention the resume: %s", errb)
	}
	// Only size, type and the options go to the server, never the file name.
	if f.created["content_type"] != "video/mp4" || f.created["mask_faces"] != true || f.created["ttl_seconds"] != float64(172800) {
		t.Fatalf("create body = %v", f.created)
	}
	for k := range f.created {
		if k != "size_bytes" && k != "content_type" && k != "upload_method" && k != "mask_faces" && k != "ttl_seconds" {
			t.Fatalf("unexpected create field %q", k)
		}
	}
	if strings.Contains(errb+out, "private-holiday-clip") {
		t.Fatal("the local file name was printed")
	}
}

func TestUploadWait(t *testing.T) {
	fastPolling(t)
	for _, tc := range []struct {
		name   string
		states []string
		args   []string
		code   int
		want   string
	}{
		{"ready", []string{"processing", "processing", "ready"}, []string{"--wait"}, 0, `"state":"ready"`},
		{"failed", []string{"processing", "failed"}, []string{"--wait"}, exitIncomplete, "failed (probe_failed)"},
		{"timeout", []string{"processing"}, []string{"--wait", "--wait-timeout", "40ms"}, exitIncomplete, "timed out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.states, f.failure = tc.states, "probe_failed"
			path, _ := sourceFile(t, 1<<20)
			code, out, errb := runCLI(t, f, append([]string{"upload", path, "--json"}, tc.args...)...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\n%s", code, tc.code, errb)
			}
			if tc.code == 0 && !strings.Contains(strings.ReplaceAll(out, " ", ""), tc.want) {
				t.Fatalf("stdout %q lacks %s", out, tc.want)
			}
			if tc.code != 0 {
				var e struct{ Error struct{ Code, Detail string } }
				last := errb[strings.LastIndex(strings.TrimSpace(errb), "\n")+1:]
				if err := json.Unmarshal([]byte(last), &e); err != nil || e.Error.Code != "incomplete" || !strings.Contains(e.Error.Detail, tc.want) {
					t.Fatalf("stderr's last line = %q (%v)", last, err)
				}
				if out != "" {
					t.Fatalf("stdout should be empty on failure: %q", out)
				}
			}
		})
	}
}

func TestCommitRefusedKeepsTheAssetID(t *testing.T) {
	fastPolling(t)
	f := newFake(t)
	f.commitCode = 409
	path, _ := sourceFile(t, 1<<20)
	code, _, errb := runCLI(t, f, "upload", path)
	if code != exitConflict || !strings.Contains(errb, "quota_exceeded") || !strings.Contains(errb, "cipherframe process "+testAsset) {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestProblemRendering(t *testing.T) {
	f := newFake(t)
	code, out, errb := runCLI(t, f, "status", "ast_aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if code != exitNotFound || out != "" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	for _, s := range []string{"not_found", testReqID, "no such asset"} {
		if !strings.Contains(errb, s) {
			t.Fatalf("stderr lacks %q: %s", s, errb)
		}
	}
	code, _, errb = runCLI(t, f, "status", "ast_aaaaaaaaaaaaaaaaaaaaaaaaaa", "--json")
	var e struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
			ExitCode  int    `json:"exit_code"`
		}
	}
	if err := json.Unmarshal([]byte(errb), &e); err != nil || code != exitNotFound || e.Error.Code != "not_found" || e.Error.RequestID != testReqID || e.Error.ExitCode != exitNotFound {
		t.Fatalf("exit %d, stderr %q (%v)", code, errb, err)
	}
}

func TestKeyIsScrubbedFromProblems(t *testing.T) {
	f := newFake(t)
	f.echoKey = true // a server that repeats the credentials back in its error text
	code, _, errb := runCLI(t, f, "status", "ast_aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if code != exitNotFound || !strings.Contains(errb, "[redacted]") {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestExitCodes(t *testing.T) {
	for status, want := range map[int]int{
		400: exitAPI, 401: exitAPI, 403: exitAPI, 404: exitNotFound, 409: exitConflict, 413: exitAPI,
		429: exitConflict, 500: exitAPI, 502: exitUnavailable, 503: exitUnavailable, 504: exitUnavailable,
	} {
		if got := exitCodeFor(status); got != want {
			t.Errorf("exitCodeFor(%d) = %d, want %d", status, got, want)
		}
	}
	f := newFake(t)
	t.Setenv("CIPHERFRAME_API_KEY", testKey)
	var out, errb bytes.Buffer
	t.Setenv("CIPHERFRAME_SERVER", "")
	if code := run([]string{"status", testAsset}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "CIPHERFRAME_SERVER") {
		t.Errorf("no server: exit %d, %s", code, errb.String())
	}
	t.Setenv("CIPHERFRAME_SERVER", f.srv.URL)
	t.Setenv("CIPHERFRAME_API_KEY", "")
	errb.Reset()
	if code := run([]string{"status", testAsset}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "API key") {
		t.Errorf("no key: exit %d, %s", code, errb.String())
	}
	if code, _, _ := runCLI(t, f, "status"); code != exitUsage {
		t.Errorf("missing argument: exit %d", code)
	}
	if code, _, _ := runCLI(t, f, "status", testAsset, "--bogus"); code != exitUsage {
		t.Errorf("unknown flag: exit %d", code)
	}
	if code, _, _ := runCLI(t, f, "upload", filepath.Join(t.TempDir(), "missing.mp4")); code != exitUsage {
		t.Errorf("missing file: exit %d", code)
	}
	f.srv.Close()
	if code, _, errb := runCLI(t, f, "status", testAsset, "--timeout", "2s"); code != exitUnavailable || !strings.Contains(errb, "cannot reach") {
		t.Errorf("closed server: exit %d, %s", code, errb)
	}
}

func TestKeyFile(t *testing.T) {
	f := newFake(t)
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(testKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CIPHERFRAME_API_KEY", "")
	var out, errb bytes.Buffer
	code := run([]string{"status", testAsset, "--server", f.srv.URL, "--api-key-file", keyFile}, &out, &errb)
	if code != 0 || strings.TrimSpace(out.String()) != testAsset+"  ready" {
		t.Fatalf("exit %d: %s%s", code, out.String(), errb.String())
	}
}

func TestJSONShapes(t *testing.T) {
	f := newFake(t)
	type shape map[string]any
	decode := func(s string) shape {
		var m shape
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("not one JSON document: %q: %v", s, err)
		}
		return m
	}
	_, out, _ := runCLI(t, f, "status", testAsset, "--json")
	if m := decode(out); m["id"] != testAsset || m["state"] != "ready" || len(m) != 3 {
		t.Errorf("status --json = %s", out)
	}
	_, out, _ = runCLI(t, f, "inspect", testAsset, "--json")
	if m := decode(out); m["size_bytes"] != float64(0) || m["upload_method"] != "tus" {
		t.Errorf("inspect --json = %s", out)
	}
	if _, out, _ = runCLI(t, f, "inspect", testAsset); !strings.Contains(out, "\n  \"id\"") {
		t.Errorf("inspect should indent: %s", out)
	}
	code, out, _ := runCLI(t, f, "list", "--limit", "5", "--cursor", "c1", "--json")
	if m := decode(out); code != 0 || m["next_cursor"] != "c2" || len(m["items"].([]any)) != 1 {
		t.Errorf("list --json = %s", out)
	}
	code, out, errb := runCLI(t, f, "list")
	if code != 0 || !strings.Contains(out, testAsset) || !strings.Contains(errb, "--cursor c2") {
		t.Errorf("list: %d %q %q", code, out, errb)
	}
}

func TestProcessWait(t *testing.T) {
	fastPolling(t)
	f := newFake(t)
	f.states = []string{"processing", "ready"}
	f.stored.Write(make([]byte, 10))
	f.size = 10
	code, out, errb := runCLI(t, f, "process", testAsset, "--wait")
	if code != 0 || strings.TrimSpace(out) != testAsset+"  ready" {
		t.Fatalf("exit %d: %q %s", code, out, errb)
	}
}

func TestDeleteWaitPrintsTheRecord(t *testing.T) {
	fastPolling(t)
	f := newFake(t)
	f.states = []string{"deleting", "deleting", "deleted"}
	code, out, errb := runCLI(t, f, "delete", testAsset, "--wait")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	var env struct {
		PayloadType string `json:"payloadType"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.PayloadType != "application/vnd.cipherframe.deletion+json" {
		t.Fatalf("stdout is not the signed record: %q", out)
	}
	// Without --wait the record is not there yet and the asset document is printed.
	f2 := newFake(t)
	f2.states = []string{"deleting"}
	if code, out, _ := runCLI(t, f2, "delete", testAsset); code != 0 || strings.TrimSpace(out) != testAsset+"  deleting" {
		t.Fatalf("delete: %d %q", code, out)
	}
	if code, _, errb := runCLI(t, f2, "deletion-record", testAsset); code != exitNotFound || !strings.Contains(errb, "not_deleted") {
		t.Fatalf("deletion-record: %d %s", code, errb)
	}
	f3 := newFake(t)
	f3.states = []string{"deleting"}
	if code, _, _ := runCLI(t, f3, "delete", testAsset, "--wait", "--wait-timeout", "30ms"); code != exitIncomplete {
		t.Fatalf("delete --wait timeout: exit %d", code)
	}
}

func TestPerCommandHelp(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{{"help", "upload"}, {"upload", "-h"}} {
		out.Reset()
		if code := run(args, &out, &errb); code != 0 || !strings.Contains(out.String(), "--mask-faces") || !strings.Contains(out.String(), "Exit codes:") {
			t.Errorf("%v: exit %d\n%s", args, code, out.String())
		}
	}
	if strings.Contains(out.String(), "-api-key ") {
		t.Error("there must be no flag that takes the key itself")
	}
}

func TestParseTTL(t *testing.T) {
	for in, want := range map[string]int{"90m": 5400, "24h": 86400, "30d": 2592000} {
		if got, err := parseTTL(in); err != nil || got != want {
			t.Errorf("parseTTL(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "1s", "abc", "99999d", "-5h"} {
		if _, err := parseTTL(in); err == nil {
			t.Errorf("parseTTL(%q) should fail", in)
		}
	}
}

func TestTusRefusesLocationOnAnotherHost(t *testing.T) {
	var seen string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("Authorization") }))
	defer evil.Close()
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", evil.URL+"/steal")
		w.WriteHeader(201)
	}))
	defer edge.Close()
	t.Setenv("CIPHERFRAME_SERVER", "http://127.0.0.1:1")
	t.Setenv("CIPHERFRAME_API_KEY", testKey)
	c, err := newCLI(commonFlags{timeout: time.Second}, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := sourceFile(t, 10)
	f, _ := os.Open(path) //nolint:gosec // a temp file of this test
	defer func() { _ = f.Close() }()
	err = c.tusUpload(context.Background(), f, 10, apiclient.UploadInstructions{Url: edge.URL + "/v1/uploads/tus/", Token: testToken})
	var ce *cliError
	if !errors.As(err, &ce) || ce.kind != "bad_response" || seen != "" {
		t.Fatalf("err = %v, token seen by the other host: %q", err, seen)
	}
}
