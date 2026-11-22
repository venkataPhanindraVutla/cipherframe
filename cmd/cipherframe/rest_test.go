package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/proof"
)

const (
	testSession  = "ses_0123456789012345678901234567890123456789012345678901"
	testKeyID    = "key_0123456789abcdefghjkmnpqrs"
	testEndpoint = "whe_0123456789abcdefghjkmnpqrs"
	testDelivery = "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f36"
	testSubID    = "sub_1"
	otherAsset   = "ast_0123456789abcdefghjkmnpqrt"
	// Playback token; the spec sets no pattern for it.
	testPlayToken = "test-fixture-playback-token-v1.payload.kid.mac"
)

// newKey matches the spec's key pattern, so it is built rather than written as a literal.
var newKey = "cf_" + strings.Repeat("a", 12) + "_" + strings.Repeat("B", 43)

// restFake answers the routes of the M8-1b commands and keeps the last request for the tests.
type restFake struct {
	*fakeServer
	transport string // token_transport of created sessions
	body      map[string]any
	form      map[string]string
	filename  string
	verify    func(req map[string]any) map[string]any
	proof     *proof.Proof
	query     url.Values // of the last audit export request
}

func newRest(t *testing.T) *restFake {
	t.Helper()
	r := &restFake{fakeServer: newFake(t), transport: "header"}
	r.extra = r.route2
	return r
}

func (r *restFake) route2(w http.ResponseWriter, req *http.Request, body []byte) bool {
	p, m := req.URL.Path, req.Method
	r.body, r.form, r.filename = nil, nil, ""
	if strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/") {
		req.Body = io.NopCloser(bytes.NewReader(body))
		if err := req.ParseMultipartForm(1 << 20); err != nil { //nolint:gosec // test server, body already read in full
			r.t.Errorf("multipart: %v", err)
			return false
		}
		r.form = map[string]string{}
		for k, v := range req.MultipartForm.Value {
			r.form[k] = v[0]
		}
		for _, fh := range req.MultipartForm.File["file"] {
			r.filename = fh.Filename
			f, _ := fh.Open()
			b, _ := io.ReadAll(f)
			r.form["file"] = string(b)
		}
	} else if len(body) > 0 {
		_ = json.Unmarshal(body, &r.body)
	}
	status := map[string]any{
		"session_id": testSession, "asset_id": testAsset, "viewer_id": "v1", "state": "revoked",
		"created_at": "2026-11-22T10:00:00Z", "last_heartbeat_at": "2026-11-22T10:01:00Z",
		"session_expires_at": "2026-11-22T14:00:00Z", "revoke_reason": "test",
	}
	track := map[string]any{
		"id": testSubID, "asset_id": testAsset, "language": "en", "label": "English", "default": true,
		"origin": "upload", "cue_count": 2, "size_bytes": 40, "sha256": "ab", "created_at": "2026-11-22T10:00:00Z",
	}
	logo := map[string]any{
		"version": "v1", "sha256": "ab", "size_bytes": 10, "width": 64, "height": 32, "corner": "top_left",
		"opacity_percent": 50, "enabled": true, "created_at": "2026-11-22T10:00:00Z", "updated_at": "2026-11-22T10:00:00Z",
	}
	delivery := map[string]any{
		"id": testDelivery, "endpoint_id": testEndpoint, "event_id": testDelivery, "kind": "asset.ready", "status": "pending",
		"attempts": 0, "next_attempt_at": "2026-11-22T10:00:00Z", "created_at": "2026-11-22T10:00:00Z",
	}
	switch {
	case m == "POST" && p == "/v1/playback-sessions":
		if r.body["asset_id"] == "ast_00000000000000000000000001" {
			r.problem(w, req, 409, "asset_not_ready", "the asset is processing")
			return true
		}
		murl := r.srv.URL + "/v1/play/" + testSession + "/master.m3u8"
		if r.transport == "url" {
			murl += "?t=" + url.QueryEscape(testPlayToken)
		}
		r.reply(w, 201, map[string]any{
			"session_id": testSession, "token": testPlayToken, "token_expires_at": "2026-11-22T10:10:00Z",
			"heartbeat_interval_seconds": 20, "session_expires_at": "2026-11-22T14:00:00Z", "manifest_url": murl,
			"token_transport": r.transport, "variant": "original",
		}, true)
	case m == "POST" && p == "/v1/playback-sessions/revoke":
		r.reply(w, 200, map[string]any{"revoked": 2}, false)
	case m == "POST" && p == "/v1/playback-sessions/"+testSession+"/revoke":
		r.reply(w, 200, status, false)
	case m == "GET" && p == "/v1/playback-sessions/"+testSession:
		status["state"] = "active"
		r.reply(w, 200, status, false)
	case strings.HasPrefix(p, "/v1/playback-sessions/"):
		r.problem(w, req, 404, "not_found", "no session "+strings.Split(p, "/")[3])
	case m == "POST" && p == "/v1/verify":
		r.reply(w, 200, r.verify(r.body), false)
	case m == "GET" && p == "/v1/assets/"+testAsset+"/proof":
		if req.URL.Query().Get("path") != r.proof.Path {
			r.problem(w, req, 404, "artifact_not_found", "no such artifact")
			return true
		}
		r.reply(w, 200, r.proof, false)
	case m == "POST" && p == "/v1/assets/"+testAsset+"/subtitles":
		r.reply(w, 201, track, false)
	case m == "POST" && p == "/v1/assets/"+testAsset+"/transcripts":
		track["origin"] = "import"
		r.reply(w, 201, track, false)
	case m == "GET" && p == "/v1/assets/"+testAsset+"/subtitles":
		r.reply(w, 200, map[string]any{"items": []any{track}}, false)
	case m == "DELETE" && p == "/v1/assets/"+testAsset+"/subtitles/"+testSubID:
		w.Header().Set("X-Request-Id", testReqID)
		w.WriteHeader(204)
	case p == "/v1/brand/logo" && m == "DELETE":
		w.Header().Set("X-Request-Id", testReqID)
		w.WriteHeader(204)
	case p == "/v1/brand/logo":
		r.reply(w, 200, logo, false)
	case m == "POST" && p == "/v1/keys/"+testKeyID+"/rotate":
		r.reply(w, 200, map[string]any{
			"id": testKeyID, "client_id": "cli_0123456789abcdefghjkmnpqrs", "name": "k", "prefix": strings.Repeat("a", 12),
			"scopes": []string{"admin"}, "created_at": "2026-11-22T10:00:00Z", "key": newKey,
			"previous_valid_until": "2026-11-22T10:10:00Z",
		}, true)
	case m == "GET" && p == "/v1/audit-events":
		r.query = req.URL.Query()
		ev := func(n string) map[string]any {
			return map[string]any{"id": "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f3" + n, "action": "key.rotate", "created_at": "2026-11-22T10:00:00Z"}
		}
		if req.URL.Query().Get("after") == "" {
			r.reply(w, 200, map[string]any{"items": []any{ev("1"), ev("2")}, "next_cursor": "c2"}, true)
		} else {
			r.reply(w, 200, map[string]any{"items": []any{ev("3")}}, true)
		}
	case m == "GET" && p == "/v1/webhook-deliveries":
		r.reply(w, 200, map[string]any{"items": []any{delivery}, "next_cursor": "c2"}, true)
	case m == "POST" && p == "/v1/webhook-deliveries/"+testDelivery+"/replay":
		r.reply(w, 202, delivery, false)
	case m == "POST" && p == "/v1/webhook-endpoints/"+testEndpoint+"/replay-dead":
		r.reply(w, 200, map[string]any{"replayed": 3}, false)
	default:
		return false
	}
	return true
}

// problemOnly makes every later request answer with one problem.
func (r *restFake) problemOnly(status int, code, detail string) {
	r.extra = func(w http.ResponseWriter, req *http.Request, _ []byte) bool {
		r.problem(w, req, status, code, detail)
		return true
	}
}

func exit(t *testing.T, name string, got, want int, errb string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: exit %d, want %d\nstderr: %s", name, got, want, errb)
	}
}

func usageCases(t *testing.T, f *fakeServer, cases map[string][]string) {
	t.Helper()
	for name, args := range cases {
		if code, _, errb := runCLI(t, f, args...); code != 3 {
			t.Errorf("%s: exit %d, want 3: %s", name, code, errb)
		}
	}
}

func TestSessionCreate(t *testing.T) {
	r := newRest(t)
	code, out, errb := runCLI(t, r.fakeServer, "session", "create", testAsset, "--variant", "masked", "--viewer", "viewer-1")
	exit(t, "create", code, 0, errb)
	if r.body["viewer_id"] != "viewer-1" || r.body["variant"] != "masked" {
		t.Fatalf("request = %v", r.body)
	}
	for _, want := range []string{testSession, "/v1/play/" + testSession + "/master.m3u8", "every 20s", "2026-11-22T14:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	// A random viewer when none is given.
	if code, _, errb = runCLI(t, r.fakeServer, "session", "create", testAsset); code != 0 || !strings.HasPrefix(r.body["viewer_id"].(string), "cli-") {
		t.Fatalf("default viewer: %d %v %s", code, r.body, errb)
	}

	// Token in the URL: cut from the output unless asked for, in both modes (runCLI fails the test
	// when the token appears anywhere).
	r.transport = "url"
	for _, args := range [][]string{{"session", "create", testAsset}, {"session", "create", testAsset, "--json"}} {
		code, out, errb = runCLI(t, r.fakeServer, args...)
		exit(t, "url transport", code, 0, errb)
		if strings.Contains(out, "t=") || strings.Contains(out, `"token"`) {
			t.Errorf("token material in %v output:\n%s", args, out)
		}
	}
	if !strings.Contains(errb, "--show-token") {
		t.Errorf("no hint on stderr: %s", errb)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc["session_id"] != testSession || doc["heartbeat_interval_seconds"] != float64(20) {
		t.Fatalf("json: %v\n%s", err, out)
	}

	allowOutput = testPlayToken
	t.Cleanup(func() { allowOutput = "" })
	code, out, errb = runCLI(t, r.fakeServer, "session", "create", testAsset, "--show-token")
	exit(t, "show-token", code, 0, errb)
	if !strings.Contains(out, testPlayToken) || strings.Contains(errb, testPlayToken) {
		t.Fatalf("token on stdout only:\nstdout: %s\nstderr: %s", out, errb)
	}
	code, out, _ = runCLI(t, r.fakeServer, "session", "create", testAsset, "--show-token", "--json")
	if code != 0 || !strings.Contains(out, testPlayToken) {
		t.Fatalf("json show-token: %d %s", code, out)
	}
	allowOutput = ""

	code, _, errb = runCLI(t, r.fakeServer, "session", "create", "ast_00000000000000000000000001")
	exit(t, "not ready", code, 6, errb)
	if !strings.Contains(errb, "asset_not_ready") {
		t.Errorf("stderr: %s", errb)
	}
	usageCases(t, r.fakeServer, map[string][]string{"bad variant": {"session", "create", testAsset, "--variant", "x"}})
}

func TestSessionRevokeShowAndGaps(t *testing.T) {
	r := newRest(t)
	code, out, errb := runCLI(t, r.fakeServer, "session", "revoke", testSession, "--reason", "test")
	exit(t, "by id", code, 0, errb)
	if r.body["reason"] != "test" || !strings.Contains(out, "revoked") {
		t.Fatalf("%v\n%s", r.body, out)
	}
	code, out, errb = runCLI(t, r.fakeServer, "session", "revoke", "--viewer", "v1", "--asset", testAsset)
	exit(t, "filter", code, 0, errb)
	if r.body["viewer_id"] != "v1" || r.body["asset_id"] != testAsset || !strings.Contains(out, "revoked 2 session(s)") {
		t.Fatalf("%v\n%s", r.body, out)
	}
	_, out, _ = runCLI(t, r.fakeServer, "session", "revoke", "--asset", testAsset, "--json")
	if strings.TrimSpace(out) != `{"revoked":2}` {
		t.Fatalf("json: %s", out)
	}
	code, out, errb = runCLI(t, r.fakeServer, "session", "show", testSession)
	exit(t, "show", code, 0, errb)
	if !strings.Contains(out, "active") {
		t.Fatal(out)
	}
	// An unknown session: not found, and the ID is not echoed even though the server did.
	other := "ses_" + strings.Repeat("1", 52)
	code, out, errb = runCLI(t, r.fakeServer, "session", "show", other)
	exit(t, "unknown", code, 5, errb)
	if strings.Contains(errb+out, other) {
		t.Fatalf("session ID in an error: %s", errb)
	}
	usageCases(t, r.fakeServer, map[string][]string{
		"nothing":    {"session", "revoke"},
		"id+filter":  {"session", "revoke", testSession, "--viewer", "v"},
		"two ids":    {"session", "revoke", testSession, testSession},
		"list (gap)": {"session", "list"},
		"unknown":    {"session", "frob"},
	})
	if _, _, errb = runCLI(t, r.fakeServer, "session", "list"); !strings.Contains(errb, "no call that lists") {
		t.Errorf("gap text: %s", errb)
	}
	// Help, per command and per group.
	code, out, _ = runCLI(t, r.fakeServer, "help", "session", "create")
	if code != 0 || !strings.Contains(out, "--show-token") || !strings.Contains(out, "Exit codes") {
		t.Errorf("help session create: %d\n%s", code, out)
	}
	if code, out, _ = runCLI(t, r.fakeServer, "help", "session"); code != 0 || !strings.Contains(out, "session revoke") {
		t.Errorf("help session: %d\n%s", code, out)
	}
	if code, out, _ = runCLI(t, r.fakeServer, "session"); code != 3 || out != "" {
		t.Errorf("bare group: %d %q", code, out)
	}
}

func TestVerifyFileAndProofRoundTrip(t *testing.T) {
	e := setup(t)
	r := newRest(t)
	const path = "720p/seg-2.m4s"
	file := filepath.Join(e.f.Original, "720p", "seg-2.m4s")
	pr, err := proof.Build(e.f.Built.Manifest, "original", path)
	if err != nil {
		t.Fatal(err)
	}
	r.proof = pr
	asset := testAsset
	r.verify = func(req map[string]any) map[string]any {
		switch {
		case req["sha256"] != pr.SHA256 && req["path"] != nil:
			return map[string]any{"outcome": "modified", "asset_id": testAsset, "path": path, "variant": "original"}
		case req["sha256"] != pr.SHA256:
			return map[string]any{"outcome": "cannot_say", "reason": "no_match"}
		}
		return map[string]any{"outcome": "ours", "asset_id": asset, "path": path, "variant": "original"}
	}

	// proof, in both modes, feeds verify --proof.
	for _, args := range [][]string{{"proof", testAsset, path}, {"proof", testAsset, path, "--json"}} {
		code, out, errb := runCLI(t, r.fakeServer, args...)
		exit(t, "proof", code, 0, errb)
		pf := write(t, e.dir, "p.json", []byte(out))
		code, vout, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, "--proof", pf, file)
		if code != 0 || !strings.Contains(vout, "ours        "+path) {
			t.Fatalf("verify --proof of %v: %d\n%s", args, code, vout)
		}
		if code, _, _ = do("verify", "--manifest", e.manifest, "--keys", e.keys, "--proof", pf, filepath.Join(e.f.Masked, "720p", "seg-2.m4s")); code != 1 {
			t.Errorf("another file against the proof: %d", code)
		}
	}
	code, _, errb := runCLI(t, r.fakeServer, "proof", testAsset, "nope/seg.m4s")
	exit(t, "unknown path", code, 5, errb)

	// verify-file: ours 0, modified 1, cannot say 2.
	code, out, errb := runCLI(t, r.fakeServer, "verify-file", testAsset, file, "--path", path)
	if code != 0 || !strings.Contains(out, "ours        "+path) || r.body["asset_id"] != testAsset || r.body["path"] != path {
		t.Fatalf("ours: %d %v\n%s%s", code, r.body, out, errb)
	}
	if len(r.body["sha256"].(string)) != 64 {
		t.Fatalf("hash not sent: %v", r.body)
	}
	if code, _, _ = runCLI(t, r.fakeServer, "verify-file", testAsset, file); code != 0 || r.body["asset_id"] != nil {
		t.Fatalf("hash only: %d %v", code, r.body)
	}
	flipped := write(t, e.dir, "flipped.m4s", []byte("not the segment"))
	if code, out, _ = runCLI(t, r.fakeServer, "verify-file", testAsset, flipped, "--path", path); code != 1 || !strings.Contains(out, "modified") {
		t.Fatalf("modified: %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, r.fakeServer, "verify-file", testAsset, flipped, "--json")
	if code != 2 || !strings.Contains(out, `"reason":"no_match"`) {
		t.Fatalf("cannot say: %d\n%s", code, out)
	}
	asset = otherAsset
	if code, out, _ = runCLI(t, r.fakeServer, "verify-file", testAsset, file); code != 2 || !strings.Contains(out, "another asset") {
		t.Fatalf("another asset's artifact: %d\n%s", code, out)
	}
	usageCases(t, r.fakeServer, map[string][]string{
		"no file":         {"verify-file", testAsset},
		"variant no path": {"verify-file", testAsset, file, "--variant", "masked"},
		"missing file":    {"verify-file", testAsset, filepath.Join(e.dir, "nope")},
		"proof usage":     {"proof", testAsset},
	})
	// The server's problem keeps its exit code (a key without the scope).
	r.problemOnly(403, "forbidden", "scope assets:read is required")
	if code, _, errb = runCLI(t, r.fakeServer, "verify-file", testAsset, file); code != 4 || !strings.Contains(errb, "forbidden") {
		t.Errorf("403: %d %s", code, errb)
	}
}

func TestSubtitles(t *testing.T) {
	r := newRest(t)
	dir := t.TempDir()
	vtt := write(t, dir, "private-talk.vtt", []byte("WEBVTT\n\n00:00.000 --> 00:01.000\nhello\n"))
	code, out, errb := runCLI(t, r.fakeServer, "subtitles", "import", testAsset, vtt, "--language", "en", "--label", "English", "--default")
	exit(t, "import vtt", code, 0, errb)
	if r.form["language"] != "en" || r.form["label"] != "English" || r.form["default"] != "true" || !strings.HasPrefix(r.form["file"], "WEBVTT") {
		t.Fatalf("form = %v", r.form)
	}
	if strings.Contains(r.filename, "private-talk") || strings.Contains(out+errb, "private-talk") {
		t.Fatalf("the local file name leaked: %q", r.filename)
	}
	if !strings.Contains(out, testSubID) || !strings.Contains(out, "default") {
		t.Fatalf("stdout: %s", out)
	}
	// The label defaults to the language; no default field unless asked.
	if code, _, errb = runCLI(t, r.fakeServer, "subtitles", "import", testAsset, vtt, "--language", "pt-BR"); code != 0 || r.form["label"] != "pt-BR" || r.form["default"] != "" {
		t.Fatalf("defaults: %d %v %s", code, r.form, errb)
	}
	tr := write(t, dir, "t.json", []byte(`{"cues":[{"start":0,"end":1.5,"text":"hi","speaker":"Ann"}]}`))
	code, out, errb = runCLI(t, r.fakeServer, "subtitles", "import", testAsset, tr, "--language", "en", "--json")
	exit(t, "import json", code, 0, errb)
	cues := r.body["cues"].([]any)
	if r.body["language"] != "en" || r.body["label"] != "en" || len(cues) != 1 || !strings.Contains(out, `"origin":"import"`) {
		t.Fatalf("transcript body = %v\n%s", r.body, out)
	}
	bare := write(t, dir, "b.json", []byte(`[{"start":0,"end":1,"text":"x"}]`))
	if code, _, errb = runCLI(t, r.fakeServer, "subtitles", "import", testAsset, bare, "--language", "en"); code != 0 {
		t.Fatalf("bare list: %d %s", code, errb)
	}
	bad := write(t, dir, "bad.json", []byte(`{"cues":[]}`))
	usageCases(t, r.fakeServer, map[string][]string{
		"no language":   {"subtitles", "import", testAsset, vtt},
		"empty cues":    {"subtitles", "import", testAsset, bad, "--language", "en"},
		"missing file":  {"subtitles", "import", testAsset, filepath.Join(dir, "none.vtt"), "--language", "en"},
		"delete usage":  {"subtitles", "delete", testAsset},
		"unknown sub":   {"subtitles", "frob"},
		"list no asset": {"subtitles", "list"},
	})
	code, out, errb = runCLI(t, r.fakeServer, "subtitles", "list", testAsset)
	if code != 0 || !strings.Contains(out, "English") {
		t.Fatalf("list: %d %s %s", code, out, errb)
	}
	code, out, errb = runCLI(t, r.fakeServer, "subtitles", "delete", testAsset, testSubID, "--json")
	if code != 0 || strings.TrimSpace(out) != `{"deleted":true}` {
		t.Fatalf("delete: %d %s %s", code, out, errb)
	}
	r.problemOnly(409, "asset_not_ready", "the asset is not ready")
	code, _, errb = runCLI(t, r.fakeServer, "subtitles", "import", testAsset, vtt, "--language", "en")
	exit(t, "not ready", code, 6, errb)
}

func TestBrand(t *testing.T) {
	r := newRest(t)
	dir := t.TempDir()
	png := write(t, dir, "company-secret-logo.png", []byte("\x89PNG fake"))
	code, out, errb := runCLI(t, r.fakeServer, "brand", "set-logo", png, "--corner", "top_left", "--opacity", "50")
	exit(t, "set-logo", code, 0, errb)
	if r.form["corner"] != "top_left" || r.form["opacity"] != "50" || r.form["file"] != "\x89PNG fake" || strings.Contains(r.filename, "secret") {
		t.Fatalf("form = %v %q", r.form, r.filename)
	}
	if !strings.Contains(out, "64x32") || !strings.Contains(out, "50%") {
		t.Fatalf("stdout: %s", out)
	}
	if code, _, _ = runCLI(t, r.fakeServer, "brand", "set-logo", png); code != 0 || r.form["corner"] != "" || r.form["opacity"] != "" {
		t.Fatalf("defaults are left to the server: %v", r.form)
	}
	_, out, _ = runCLI(t, r.fakeServer, "brand", "show", "--json")
	var doc map[string]any
	if json.Unmarshal([]byte(out), &doc) != nil || doc["corner"] != "top_left" {
		t.Fatalf("show json: %s", out)
	}
	if code, out, _ = runCLI(t, r.fakeServer, "brand", "remove"); code != 0 || strings.TrimSpace(out) != "removed" {
		t.Fatalf("remove: %d %s", code, out)
	}
	if _, out, _ = runCLI(t, r.fakeServer, "brand", "remove", "--json"); strings.TrimSpace(out) != `{"removed":true}` {
		t.Fatalf("remove json: %s", out)
	}
	usageCases(t, r.fakeServer, map[string][]string{
		"corner":   {"brand", "set-logo", png, "--corner", "middle"},
		"opacity":  {"brand", "set-logo", png, "--opacity", "5"},
		"no file":  {"brand", "set-logo"},
		"show arg": {"brand", "show", "x"},
	})
	r.problemOnly(403, "forbidden", "admin scope is required")
	code, _, errb = runCLI(t, r.fakeServer, "brand", "show", "--json")
	exit(t, "403", code, 4, errb)
	var e struct{ Error struct{ Code string } }
	if json.Unmarshal([]byte(errb), &e) != nil || e.Error.Code != "forbidden" {
		t.Fatalf("json error: %s", errb)
	}
}

func TestRotateAPIKey(t *testing.T) {
	r := newRest(t)
	allowOutput = newKey
	t.Cleanup(func() { allowOutput = "" })
	code, out, errb := runCLI(t, r.fakeServer, "keys", "rotate-api-key", testKeyID, "--overlap", "5m")
	exit(t, "rotate", code, 0, errb)
	if strings.TrimSpace(out) != newKey || strings.Contains(errb, newKey) {
		t.Fatalf("the key must be alone on stdout and absent from stderr:\nstdout: %q\nstderr: %s", out, errb)
	}
	if !strings.Contains(errb, "cannot be shown again") || !strings.Contains(errb, "works until") {
		t.Fatalf("no warning: %s", errb)
	}
	if r.body["overlap_seconds"] != float64(300) {
		t.Fatalf("request = %v", r.body)
	}
	code, out, errb = runCLI(t, r.fakeServer, "keys", "rotate-api-key", testKeyID, "--json")
	exit(t, "rotate json", code, 0, errb)
	if _, ok := r.body["overlap_seconds"]; ok || !strings.Contains(out, `"key":"`+newKey+`"`) || strings.Contains(errb, newKey) {
		t.Fatalf("json: body %v\nstdout %s\nstderr %s", r.body, out, errb)
	}
	allowOutput = ""
	// An unknown key (the server echoes the Authorization header in the problem): scrubbed, exit 5.
	r.echoKey = true
	code, _, errb = runCLI(t, r.fakeServer, "keys", "rotate-api-key", "key_00000000000000000000000000")
	exit(t, "unknown key", code, 5, errb)
	usageCases(t, r.fakeServer, map[string][]string{
		"no id":      {"keys", "rotate-api-key"},
		"overlap":    {"keys", "rotate-api-key", testKeyID, "--overlap", "25h"},
		"rewrap gap": {"keys", "rewrap"},
	})
	if _, _, errb = runCLI(t, r.fakeServer, "keys", "rewrap"); !strings.Contains(errb, "cipherframe-server admin kms-rewrap") {
		t.Errorf("rewrap gap text: %s", errb)
	}
}

func TestWebhooks(t *testing.T) {
	r := newRest(t)
	code, out, errb := runCLI(t, r.fakeServer, "webhooks", "replay", testDelivery)
	if code != 0 || !strings.Contains(out, "pending") {
		t.Fatalf("replay: %d %s %s", code, out, errb)
	}
	code, out, errb = runCLI(t, r.fakeServer, "webhooks", "replay", "--endpoint", testEndpoint, "--dead")
	if code != 0 || !strings.Contains(out, "queued 3 delivery(ies)") {
		t.Fatalf("replay dead: %d %s %s", code, out, errb)
	}
	_, out, _ = runCLI(t, r.fakeServer, "webhooks", "replay", "--endpoint", testEndpoint, "--dead", "--json")
	if strings.TrimSpace(out) != `{"replayed":3}` {
		t.Fatalf("json: %s", out)
	}
	code, out, errb = runCLI(t, r.fakeServer, "webhooks", "list", "--status", "dead", "--endpoint", testEndpoint, "--limit", "5")
	if code != 0 || !strings.Contains(out, testDelivery) || !strings.Contains(errb, "--cursor c2") {
		t.Fatalf("list: %d\n%s\n%s", code, out, errb)
	}
	if _, out, _ = runCLI(t, r.fakeServer, "webhooks", "list", "--json"); !strings.Contains(out, `"next_cursor":"c2"`) {
		t.Fatalf("list json: %s", out)
	}
	usageCases(t, r.fakeServer, map[string][]string{
		"no id":         {"webhooks", "replay"},
		"not a uuid":    {"webhooks", "replay", "abc"},
		"dead no ep":    {"webhooks", "replay", "--dead"},
		"endpoint only": {"webhooks", "replay", testDelivery, "--endpoint", testEndpoint},
		"bad status":    {"webhooks", "list", "--status", "x"},
	})
	r.problemOnly(409, "conflict", "the delivery is still pending")
	code, _, errb = runCLI(t, r.fakeServer, "webhooks", "replay", testDelivery)
	exit(t, "pending", code, 6, errb)
}

func TestMissingCredentialsAreUsageErrors(t *testing.T) {
	t.Setenv("CIPHERFRAME_SERVER", "")
	t.Setenv("CIPHERFRAME_API_KEY", "")
	var out, errb bytes.Buffer
	if code := run([]string{"session", "create", testAsset}, &out, &errb); code != 3 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}

func TestAuditExport(t *testing.T) {
	r := newRest(t)
	code, out, errb := runCLI(t, r.fakeServer, "audit", "export", "--since", "2026-11-01T00:00:00Z", "--until", "2026-12-01T00:00:00Z")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 3 || errb != "" {
		t.Fatalf("export: %d\n%s\n%s", code, out, errb)
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) || strings.Contains(l, " ") {
			t.Fatalf("not one compact JSON object per line: %q", l)
		}
	}
	if r.query.Get("after") != "c2" || r.query.Get("limit") != "500" || r.query.Get("since") == "" || r.query.Get("until") == "" {
		t.Fatalf("last query = %v", r.query)
	}
	usageCases(t, r.fakeServer, map[string][]string{
		"bad since": {"audit", "export", "--since", "yesterday"},
		"argument":  {"audit", "export", "x"},
	})
}
