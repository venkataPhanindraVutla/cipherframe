//go:build integration

package contract

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
)

// ---- a small tus 1.0.0 client ---------------------------------------------------------------

func (e *upEnv) tusReq(method, url, token string, extra map[string]string, body io.Reader) *http.Request {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Tus-Resumable", tusProtocolVer)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return req
}

// tusCreate sends the creation request and returns the status and the Location header.
func (e *upEnv) tusCreate(u upload, length int64, meta string) (int, string, exchange) {
	e.t.Helper()
	h := map[string]string{"Upload-Length": itoa(length)}
	if meta != "" {
		h["Upload-Metadata"] = meta
	}
	ex, _ := e.send(e.tusReq(http.MethodPost, u.url, u.token, h, nil), nil, false)
	e.validateTus(ex, http.StatusCreated, "createTusUpload")
	return ex.resp.StatusCode, ex.resp.Header.Get("Location"), ex
}

// tusOffset sends HEAD and returns the offset the server reports.
func (e *upEnv) tusOffset(loc, token string) (int64, int) {
	e.t.Helper()
	ex, _ := e.send(e.tusReq(http.MethodHead, loc, token, nil, nil), nil, false)
	e.validateTus(ex, http.StatusOK, "headTusUpload")
	if ex.resp.StatusCode != http.StatusOK {
		return -1, ex.resp.StatusCode
	}
	n, err := strconv.ParseInt(ex.resp.Header.Get("Upload-Offset"), 10, 64)
	if err != nil {
		e.t.Fatalf("HEAD gave Upload-Offset %q", ex.resp.Header.Get("Upload-Offset"))
	}
	return n, ex.resp.StatusCode
}

// tusPatch sends data at offset and returns the status and the new offset.
func (e *upEnv) tusPatch(loc, token string, offset int64, data []byte) (int, int64) {
	e.t.Helper()
	h := map[string]string{"Content-Type": "application/offset+octet-stream", "Upload-Offset": itoa(offset)}
	ex, _ := e.send(e.tusReq(http.MethodPatch, loc, token, h, bytes.NewReader(data)), nil, false)
	e.validateTus(ex, http.StatusNoContent, "patchTusUpload")
	if ex.resp.StatusCode != http.StatusNoContent {
		return ex.resp.StatusCode, -1
	}
	n, err := strconv.ParseInt(ex.resp.Header.Get("Upload-Offset"), 10, 64)
	if err != nil {
		e.t.Fatalf("PATCH gave Upload-Offset %q", ex.resp.Header.Get("Upload-Offset"))
	}
	return ex.resp.StatusCode, n
}

// validateTus checks a successful tus exchange against the spec's documentation of the mount and
// records that the operation was exercised.
func (e *upEnv) validateTus(ex exchange, okStatus int, wantOp string) {
	e.t.Helper()
	if ex.resp.StatusCode != okStatus {
		return
	}
	if op := validate(e.t, e.doc, ex); op != wantOp {
		e.t.Fatalf("%s %s matched spec operation %q, want %q", ex.req.Method, ex.req.URL.Path, op, wantOp)
	}
	e.tusSeen[wantOp] = true
}

// stallingBody yields n bytes of data and then blocks until its context is cancelled, like a
// connection that dies mid-chunk.
type stallingBody struct {
	data   []byte
	n      int
	sent   int
	ctx    context.Context
	onSent func()
	once   sync.Once
}

func (s *stallingBody) Read(p []byte) (int, error) {
	if s.sent < s.n {
		c := copy(p, s.data[s.sent:s.n])
		s.sent += c
		return c, nil
	}
	s.once.Do(s.onSent)
	<-s.ctx.Done()
	return 0, s.ctx.Err()
}

// tusPatchInterrupted sends the first n bytes of data for a chunk that claims len(data) bytes, then
// kills the connection. It returns once the client has given up.
func (e *upEnv) tusPatchInterrupted(loc, token string, offset int64, data []byte, n int) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &stallingBody{data: data, n: n, ctx: ctx, onSent: func() {
		time.AfterFunc(300*time.Millisecond, cancel) // let the server read what was sent
	}}
	req := e.tusReq(http.MethodPatch, loc, token, map[string]string{
		"Content-Type": "application/offset+octet-stream", "Upload-Offset": itoa(offset),
	}, body)
	req = req.WithContext(ctx)
	req.ContentLength = int64(len(data))
	if resp, err := e.client.Do(req); err == nil { // the server answered before the cut: fine
		_ = resp.Body.Close()
	}
}

// resumeOffset polls HEAD until the offset is at least min (the server notices the dropped
// connection asynchronously) and returns it.
func (e *upEnv) resumeOffset(loc, token string, min int64) int64 {
	e.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		off, status := e.tusOffset(loc, token)
		if status == http.StatusOK && off >= min {
			return off
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("HEAD offset %d (status %d), wanted at least %d", off, status, min)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// tusUploadAll uploads data[from:] in chunks of chunk bytes.
func (e *upEnv) tusUploadAll(loc, token string, data []byte, from int64, chunk int) {
	e.t.Helper()
	off := from
	for off < int64(len(data)) {
		end := min(off+int64(chunk), int64(len(data)))
		status, next := e.tusPatch(loc, token, off, data[off:end])
		if status != http.StatusNoContent || next != end {
			e.t.Fatalf("PATCH at %d: status %d, offset %d, want 204 and %d", off, status, next, end)
		}
		off = next
	}
}

// ---- multipart helpers ----------------------------------------------------------------------

func (e *upEnv) putPart(u upload, n int, data []byte, want int) map[string]any {
	e.t.Helper()
	m, _ := e.edgeCall(u.token, "PUT", "/v1/uploads/multipart/"+u.assetID+"/parts/"+strconv.Itoa(n), data, want)
	return m
}

func (e *upEnv) listParts(u upload, want int) map[string]any {
	e.t.Helper()
	m, _ := e.edgeCall(u.token, "GET", "/v1/uploads/multipart/"+u.assetID+"/parts", nil, want)
	return m
}

func partNumbers(m map[string]any) []int {
	var out []int
	for _, it := range m["items"].([]any) {
		out = append(out, int(it.(map[string]any)["part_number"].(float64)))
	}
	return out
}

// ---- the tests ------------------------------------------------------------------------------

// TestUploadLifecycleAndSourceIsNeverAddressable runs create, upload (both methods), commit,
// get, list and abort through the real listeners, validating every API and edge exchange against
// the spec, then scans every response, header and log line for anything that would address the
// source: its object key, the source bucket's name, an upload token after the response that issued
// it, the object store's upload IDs, or a presigned URL (invariant I4, M3-9).
func TestUploadLifecycleAndSourceIsNeverAddressable(t *testing.T) {
	e := newUpEnv(t)
	key := e.admin

	// ---- multipart: a missing part, then resume, then commit.
	mpSize := int64(2*testPartBytes + 17)
	mp := e.create(key, mpSize, "multipart")
	if mp.partSize != testPartBytes || !strings.HasSuffix(mp.url, "/v1/uploads/multipart/"+mp.assetID+"/parts/") {
		t.Fatalf("multipart instructions: %+v", mp)
	}
	mpData := randomBytes(t, int(mpSize))
	part := func(n int) []byte {
		lo := int64(n-1) * testPartBytes
		return mpData[lo:min(lo+testPartBytes, mpSize)]
	}
	e.assertState(key, mp.assetID, "created")
	e.putPart(mp, 1, part(1), 200)
	e.putPart(mp, 3, part(3), 200)
	e.assertState(key, mp.assetID, "uploading")
	if got := partNumbers(e.listParts(mp, 200)); len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("received parts = %v, want [1 3]", got)
	}
	e.call(key, "POST", "/v1/assets/"+mp.assetID+"/commit", nil, 409) // part 2 is missing
	e.assertState(key, mp.assetID, "uploading")
	if n, _ := e.processJobs(); n != 0 {
		t.Fatalf("a refused commit enqueued %d jobs", n)
	}
	e.putPart(mp, 2, part(2), 200)
	e.putPart(mp, 2, part(2), 200) // sending a part again replaces it
	m, _ := e.call(key, "POST", "/v1/assets/"+mp.assetID+"/commit", nil, 200)
	if m["state"] != "committed" || m["committed_at"] == nil {
		t.Fatalf("commit response: %v", m)
	}
	mpAsset := e.dbAsset(mp.assetID)
	if got := e.sourceObject(mpAsset); sum(got) != sum(mpData) {
		t.Fatal("the assembled multipart object differs from what was uploaded")
	}
	e.call(key, "POST", "/v1/assets/"+mp.assetID+"/commit", nil, 200) // idempotent
	if n, _ := e.processJobs(); n != 1 {
		t.Fatalf("%d asset.process jobs after committing one asset twice, want 1", n)
	}
	e.edgeCall(mp.token, "GET", "/v1/uploads/multipart/"+mp.assetID+"/parts", nil, 401) // token ended with commit

	// ---- tus: interrupt, HEAD, resume, finish, commit.
	tusSize := int64(2*testPartBytes + 123)
	tu := e.create(key, tusSize, "tus")
	if !strings.HasSuffix(tu.url, "/v1/uploads/tus/") || tu.partSize != 0 {
		t.Fatalf("tus instructions: %+v", tu)
	}
	tusData := randomBytes(t, int(tusSize))
	status, loc, _ := e.tusCreate(tu, tusSize, "filename dGVzdC5tcDQ=,secret c2VjcmV0")
	if status != http.StatusCreated || loc != e.edgeSrv.URL+"/v1/uploads/tus/"+tu.assetID {
		t.Fatalf("tus create: status %d, Location %q", status, loc)
	}
	e.assertState(key, tu.assetID, "uploading")
	e.tusPatchInterrupted(loc, tu.token, 0, tusData[:testPartBytes], 3*mib)
	off := e.resumeOffset(loc, tu.token, 1)
	if off <= 0 || off > 3*mib {
		t.Fatalf("offset after the interruption = %d, want 1..%d", off, 3*mib)
	}
	e.tusUploadAll(loc, tu.token, tusData, off, 4*mib)
	if off, _ := e.tusOffset(loc, tu.token); off != tusSize {
		t.Fatalf("final offset %d, want %d", off, tusSize)
	}
	tuAsset := e.dbAsset(tu.assetID)

	// Both tusd objects live under the asset's source prefix, and nothing else does.
	objs := e.sourceObjects(tuAsset)
	wantObjs := map[string]bool{tuAsset.SourceKey: true, tuAsset.SourceKey + ".info": true}
	for _, o := range objs {
		if !wantObjs[o] {
			t.Errorf("unexpected object %q under the asset's source prefix", o)
		}
		delete(wantObjs, o)
		covered := false
		for _, p := range keys.AssetPrefixes(tuAsset.TenantID, tuAsset.ID) {
			if p.Bucket == keys.Source && strings.HasPrefix(o, p.Prefix) {
				covered = true
			}
		}
		if !covered {
			t.Errorf("object %q is not covered by keys.AssetPrefixes", o)
		}
	}
	if len(wantObjs) != 0 {
		t.Errorf("tusd objects missing from the source prefix: %v (found %v)", wantObjs, objs)
	}
	info := e.sourceObjectByKey(tuAsset.SourceKey + ".info")
	for _, banned := range []string{"filename", "dGVzdC5tcDQ", "test.mp4", "secret"} {
		if strings.Contains(info, banned) {
			t.Errorf("the .info object keeps client metadata %q: %s", banned, info)
		}
	}
	status2, _, _ := e.tusCreate(tu, tusSize, "") // one upload per asset
	if status2 != http.StatusConflict {
		t.Fatalf("a second tus creation: status %d, want 409", status2)
	}
	e.call(key, "POST", "/v1/assets/"+tu.assetID+"/commit", nil, 200)
	if got := e.sourceObject(tuAsset); sum(got) != sum(tusData) {
		t.Fatal("the tus object differs from what was uploaded")
	}
	if n, _ := e.processJobs(); n != 2 {
		t.Fatalf("%d asset.process jobs, want 2", n)
	}
	if status, _ := e.tusPatch(loc, tu.token, tusSize, []byte("x")); status != http.StatusUnauthorized {
		t.Fatalf("PATCH after commit: status %d, want 401", status)
	}

	// ---- abort a tus upload with a partial chunk, and a multipart upload with a part.
	ab := e.create(key, tusSize, "tus")
	_, abLoc, _ := e.tusCreate(ab, tusSize, "")
	e.tusPatchInterrupted(abLoc, ab.token, 0, tusData[:testPartBytes], 3*mib)
	e.resumeOffset(abLoc, ab.token, 1)
	abAsset := e.dbAsset(ab.assetID)
	if len(e.sourceObjects(abAsset)) == 0 || e.openMultipartUploads(abAsset) == 0 {
		t.Fatal("expected partial objects before the abort")
	}
	m, _ = e.call(key, "POST", "/v1/assets/"+ab.assetID+"/abort", nil, 200)
	if m["state"] != "failed" || m["failure_code"] != "upload_aborted" {
		t.Fatalf("abort response: %v", m)
	}
	if objs := e.sourceObjects(abAsset); len(objs) != 0 || e.openMultipartUploads(abAsset) != 0 {
		t.Fatalf("abort left %v and %d open multipart uploads", objs, e.openMultipartUploads(abAsset))
	}
	e.call(key, "POST", "/v1/assets/"+ab.assetID+"/abort", nil, 200) // repeating is safe
	if off, status := e.tusOffset(abLoc, ab.token); status == http.StatusOK {
		t.Fatalf("HEAD after abort: offset %d", off)
	}

	ab2 := e.create(key, mpSize, "multipart")
	e.putPart(ab2, 1, part(1), 200)
	ab2Asset := e.dbAsset(ab2.assetID)
	if e.openMultipartUploads(ab2Asset) != 1 {
		t.Fatal("expected one open multipart upload before the abort")
	}
	e.call(key, "POST", "/v1/assets/"+ab2.assetID+"/abort", nil, 200)
	if e.openMultipartUploads(ab2Asset) != 0 || len(e.sourceObjects(ab2Asset)) != 0 {
		t.Fatal("abort left multipart state behind")
	}
	e.edgeCall(ab2.token, "GET", "/v1/uploads/multipart/"+ab2.assetID+"/parts", nil, 401)
	e.call(key, "POST", "/v1/assets/"+mp.assetID+"/abort", nil, 409) // committed assets cannot be aborted

	// ---- get and list.
	e.assertState(key, ab2.assetID, "failed")
	var seen []string
	cursor := ""
	for page := 0; page < 10; page++ {
		path := "/v1/assets?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		m, _ := e.call(key, "GET", path, nil, 200)
		for _, it := range m["items"].([]any) {
			seen = append(seen, it.(map[string]any)["id"].(string))
		}
		next, _ := m["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	want := []string{mp.assetID, tu.assetID, ab.assetID, ab2.assetID}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("list returned %v, want %v (oldest first)", seen, want)
	}

	e.assertEveryUploadOperationExercised()

	// ---- the scan.
	e.assertSourceNeverAddressable([]db.Asset{mpAsset, tuAsset, abAsset, ab2Asset}, []upload{mp, tu, ab, ab2})
}

func (e *upEnv) sourceObjectByKey(key string) string {
	e.t.Helper()
	rc, _, err := e.buckets.Source.Get(context.Background(), key, nil)
	if err != nil {
		e.t.Fatalf("read an object: %v", err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

// assertSourceNeverAddressable scans everything the clients saw and everything that was logged.
func (e *upEnv) assertSourceNeverAddressable(assets []db.Asset, ups []upload) {
	e.t.Helper()
	var secrets []string // what must appear nowhere
	for _, a := range assets {
		rnd := strings.TrimPrefix(a.SourceKey, keys.SourcePrefix(a.TenantID, a.ID))
		secrets = append(secrets, a.SourceKey, rnd, keys.SourcePrefix(a.TenantID, a.ID))
		if a.S3UploadID != "" {
			secrets = append(secrets, a.S3UploadID)
		}
	}
	secrets = append(secrets, storagetest.SourceBucket)
	cfg := e.sw.Config()
	secrets = append(secrets, cfg.AccessKeyID.Secret().Reveal(), cfg.SecretAccessKey.Secret().Reveal())
	secrets = append(secrets, e.apiKeys...)
	presigned := []string{"X-Amz-Signature", "X-Amz-Credential", "X-Amz-Algorithm", "X-Amz-Expires", "AWSAccessKeyId", "Signature="}

	exchanges := e.rec.snapshot()
	if len(exchanges) < 30 {
		e.t.Fatalf("only %d exchanges were captured; the scan would prove little", len(exchanges))
	}
	for _, ex := range exchanges {
		for _, s := range secrets {
			if s != "" && strings.Contains(ex.text, s) {
				e.t.Errorf("%s: a response contains %q", ex.label, s)
			}
		}
		for _, p := range presigned {
			if strings.Contains(ex.text, p) {
				e.t.Errorf("%s: a response looks like a presigned URL (%q)", ex.label, p)
			}
		}
		for _, u := range ups {
			// The token may appear in exactly the response that issued it.
			if !ex.issuesToken && strings.Contains(ex.text, u.token) {
				e.t.Errorf("%s: a response repeats an upload token", ex.label)
			}
		}
	}
	// Positive controls: the capture does see bodies, so the scan above can fail. Each token
	// appears in exactly one captured response, the one that issued it, and each asset ID appears.
	issued := 0
	for _, ex := range exchanges {
		if ex.issuesToken {
			issued++
		}
	}
	if issued != len(ups) {
		e.t.Errorf("%d token-issuing responses, want %d", issued, len(ups))
	}
	for _, u := range ups {
		withToken, withID := 0, 0
		for _, ex := range exchanges {
			if strings.Contains(ex.text, u.token) {
				withToken++
			}
			if strings.Contains(ex.text, u.assetID) {
				withID++
			}
		}
		if withToken != 1 || withID == 0 {
			e.t.Errorf("control: token seen in %d responses (want 1), asset ID in %d (want some)", withToken, withID)
		}
	}

	logs := e.logs.String()
	if logs == "" {
		e.t.Fatal("no log lines were captured")
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(logs, s) {
			e.t.Errorf("the logs contain %q", s)
		}
	}
	for _, u := range ups {
		if strings.Contains(logs, u.token) {
			e.t.Error("the logs contain an upload token")
		}
	}
	for _, p := range presigned {
		if strings.Contains(logs, p) {
			e.t.Errorf("the logs look like they hold a presigned URL (%q)", p)
		}
	}
}

func TestUploadTokenExpiry(t *testing.T) {
	e := newUpEnv(t)
	for _, method := range []string{"multipart", "tus"} {
		u := e.create(e.admin, 100, method)
		// Valid now, refused once the TTL has passed.
		if method == "multipart" {
			e.edgeCall(u.token, "GET", "/v1/uploads/multipart/"+u.assetID+"/parts", nil, 200)
		} else if status, _, _ := e.tusCreate(upload{url: u.url, token: "cfu_" + strings.Repeat("A", 43)}, 100, ""); status != 401 {
			t.Fatalf("unknown token on tus: status %d", status)
		}
		e.clk.Advance(testTokenTTL - time.Second)
		if method == "multipart" {
			e.edgeCall(u.token, "GET", "/v1/uploads/multipart/"+u.assetID+"/parts", nil, 200)
		}
		e.clk.Advance(2 * time.Second)
		if method == "multipart" {
			_, ex := e.edgeCall(u.token, "GET", "/v1/uploads/multipart/"+u.assetID+"/parts", nil, 401)
			if ex.resp.Header.Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("401 without WWW-Authenticate")
			}
			e.edgeCall(u.token, "PUT", "/v1/uploads/multipart/"+u.assetID+"/parts/1", []byte("x"), 401)
		} else if status, _, _ := e.tusCreate(u, 100, ""); status != 401 {
			t.Fatalf("expired token on tus: status %d, want 401", status)
		}
		// The API key is unaffected: the asset can still be read and aborted.
		e.assertState(e.admin, u.assetID, "created")
		e.call(e.admin, "POST", "/v1/assets/"+u.assetID+"/abort", nil, 200)
	}
}

func TestUploadCrossTenantIsolation(t *testing.T) {
	e := newUpEnv(t)
	other := e.newTenant("other")
	a := e.create(e.admin, 100, "multipart")
	b := e.create(other, 100, "multipart")

	for _, path := range []string{"", "/commit", "/abort"} {
		method := "POST"
		if path == "" {
			method = "GET"
		}
		e.call(other, method, "/v1/assets/"+a.assetID+path, nil, 404)
	}
	e.assertState(e.admin, a.assetID, "created")
	m, _ := e.call(other, "GET", "/v1/assets", nil, 200)
	items := m["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != b.assetID {
		t.Fatalf("tenant B lists %v, want only its own asset", items)
	}

	// A token works for its own asset only.
	e.edgeCall(a.token, "GET", "/v1/uploads/multipart/"+b.assetID+"/parts", nil, 404)
	e.edgeCall(a.token, "PUT", "/v1/uploads/multipart/"+b.assetID+"/parts/1", []byte("x"), 404)
	e.edgeCall(a.token, "GET", "/v1/uploads/multipart/"+a.assetID+"/parts", nil, 200)
	// Neither an API key nor a token of another asset opens tus.
	tu := e.create(e.admin, 100, "tus")
	for _, tok := range []string{e.admin, b.token} {
		if status, _, _ := e.tusCreate(upload{url: tu.url, token: tok}, 100, ""); status != 401 && status != 409 {
			t.Fatalf("a foreign credential on tus: status %d", status)
		}
	}
	if _, status := e.tusOffset(e.edgeSrv.URL+"/v1/uploads/tus/"+tu.assetID, b.token); status != 401 && status != 404 {
		t.Fatalf("HEAD with another asset's token: status %d", status)
	}
	if _, status := e.tusOffset(e.edgeSrv.URL+"/v1/uploads/tus/"+b.assetID, tu.token); status != 404 {
		t.Fatalf("HEAD of another asset with this token: status %d, want 404", status)
	}
}

func TestUploadSizeAndPartRules(t *testing.T) {
	e := newUpEnv(t)
	key := e.admin
	e.call(key, "POST", "/v1/assets", map[string]any{"size_bytes": testMaxSource + 1, "upload_method": "tus"}, 413)
	e.call(key, "POST", "/v1/assets", map[string]any{"size_bytes": testMaxSource, "upload_method": "tus"}, 201)
	e.call(key, "POST", "/v1/assets", map[string]any{"size_bytes": 0, "upload_method": "tus"}, 400)
	e.call(key, "POST", "/v1/assets", map[string]any{"size_bytes": 1, "upload_method": "ftp"}, 400)
	e.call(key, "POST", "/v1/assets", map[string]any{"size_bytes": 1, "upload_method": "tus", "content_type": "Video/MP4"}, 400)
	e.call("", "POST", "/v1/assets", map[string]any{"size_bytes": 1, "upload_method": "tus"}, 401)

	// A key without the scope is refused.
	res, err := e.mgr.CreateKey(context.Background(), e.tenant.ID, auth.Actor{}, auth.CreateKeyInput{
		ClientID: e.clientID, Name: "reader", Scopes: []db.Scope{db.ScopeAssetsRead},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader := res.Secret.Reveal()
	e.apiKeys = append(e.apiKeys, reader)
	e.call(reader, "POST", "/v1/assets", map[string]any{"size_bytes": 1, "upload_method": "tus"}, 403)
	e.call(reader, "GET", "/v1/assets", nil, 200)

	// Multipart parts.
	size := int64(2*testPartBytes + 1)
	u := e.create(key, size, "multipart")
	e.putPart(u, 1, make([]byte, testPartBytes+1), 413) // larger than the part size
	e.putPart(u, 0, []byte("x"), 400)
	e.putPart(u, 10001, []byte("x"), 400)
	e.putPart(u, 1, nil, 400) // no Content-Length
	e.putPart(u, 1, make([]byte, testPartBytes), 200)
	e.putPart(u, 2, make([]byte, testPartBytes), 200)
	e.putPart(u, 3, make([]byte, 2), 400) // the parts would exceed the declared size
	e.putPart(u, 3, make([]byte, 1), 200)
	m := e.listParts(u, 200)
	if got := partNumbers(m); len(got) != 3 || int64(m["part_size_bytes"].(float64)) != testPartBytes {
		t.Fatalf("parts %v, part size %v", got, m["part_size_bytes"])
	}

	// A short part that is not the last cannot be assembled.
	short := e.create(key, int64(testPartBytes+10), "multipart")
	e.putPart(short, 1, make([]byte, 100), 200)
	e.putPart(short, 2, make([]byte, testPartBytes+10-100), 200)
	e.call(key, "POST", "/v1/assets/"+short.assetID+"/commit", nil, 409)

	// Methods do not mix.
	tu := e.create(key, 10, "tus")
	e.putPart(tu, 1, []byte("x"), 409)
	e.edgeCall(tu.token, "GET", "/v1/uploads/multipart/"+tu.assetID+"/parts", nil, 409)
	if status, _, _ := e.tusCreate(upload{url: tu.url, token: u.token}, 10, ""); status != http.StatusConflict {
		t.Fatalf("tus creation with a multipart asset's token: status %d, want 409", status)
	}
	if status, _, _ := e.tusCreate(tu, 11, ""); status != http.StatusBadRequest {
		t.Fatalf("a wrong Upload-Length: status %d, want 400", status)
	}
	if status, _, _ := e.tusCreate(tu, 10, ""); status != http.StatusCreated {
		t.Fatalf("tus creation: status %d", status)
	}
	// A tus upload that has not finished cannot be committed.
	e.call(key, "POST", "/v1/assets/"+tu.assetID+"/commit", nil, 409)
	// The source is never served back, and termination is off.
	loc := e.edgeSrv.URL + "/v1/uploads/tus/" + tu.assetID
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		ex, _ := e.send(e.tusReq(method, loc, tu.token, nil, nil), nil, false)
		if ex.resp.StatusCode < 400 || ex.resp.StatusCode == 401 {
			t.Fatalf("%s on a tus upload: status %d, want a refusal", method, ex.resp.StatusCode)
		}
	}
	// A new asset that never started cannot be committed either.
	fresh := e.create(key, 10, "multipart")
	e.call(key, "POST", "/v1/assets/"+fresh.assetID+"/commit", nil, 409)
}

func TestCommitEnqueuesExactlyOnceUnderConcurrency(t *testing.T) {
	e := newUpEnv(t)
	u := e.create(e.admin, 100, "multipart")
	e.putPart(u, 1, make([]byte, 100), 200)

	var wg sync.WaitGroup
	statuses := make([]int, 8)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := e.newReq("POST", e.apiSrv.URL, "/v1/assets/"+u.assetID+"/commit", map[string]string{"Authorization": "Bearer " + e.admin}, nil)
			resp, err := e.client.Do(req)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			statuses[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	for i, s := range statuses {
		if s != 200 && s != 409 {
			t.Fatalf("commit %d: status %d", i, s)
		}
	}
	n, args := e.processJobs()
	if n != 1 {
		t.Fatalf("%d asset.process jobs after 8 concurrent commits, want 1", n)
	}
	a := e.dbAsset(u.assetID)
	if !strings.Contains(args[0], a.ID.String()) || strings.Contains(args[0], a.SourceKey) || len(args[0]) > 200 {
		t.Fatalf("job arguments %s", args[0])
	}
	e.assertState(e.admin, u.assetID, "committed")
}

func TestCreateAssetMaskFaces(t *testing.T) {
	e := newUpEnv(t)
	// Default: no masking, and the response says so.
	plain := e.create(e.admin, 100, "multipart")
	m, _ := e.call(e.admin, "GET", "/v1/assets/"+plain.assetID, nil, 200)
	if m["mask_faces"] != false || m["masking"] != nil {
		t.Fatalf("a default asset: %v", m)
	}

	// mask_faces: true is stored and shown, with a pending masked variant from the start.
	created, _ := e.call(e.admin, "POST", "/v1/assets", map[string]any{"size_bytes": 100, "upload_method": "multipart", "mask_faces": true}, 201)
	asset := created["asset"].(map[string]any)
	masking, _ := asset["masking"].(map[string]any)
	if asset["mask_faces"] != true || masking["state"] != "pending" || masking["faces_detected"] != nil {
		t.Fatalf("a masking asset: %v", asset)
	}
	if !e.dbAsset(asset["id"].(string)).MaskFaces {
		t.Fatal("mask_faces was not stored")
	}
	got, _ := e.call(e.admin, "GET", "/v1/assets/"+asset["id"].(string), nil, 200)
	if got["mask_faces"] != true || got["masking"].(map[string]any)["state"] != "pending" {
		t.Fatalf("GET: %v", got)
	}
	// A bad type is a 400.
	e.call(e.admin, "POST", "/v1/assets", map[string]any{"size_bytes": 100, "upload_method": "multipart", "mask_faces": "yes"}, 400)
}

// A committed mask_faces asset gets asset.process and asset.mask in the same transaction, on their
// own queues (ADR 0037); an asset without it gets asset.process only.
func TestCommitEnqueuesMaskJobOnlyForMaskFaces(t *testing.T) {
	e := newUpEnv(t)
	created, _ := e.call(e.admin, "POST", "/v1/assets", map[string]any{"size_bytes": 100, "upload_method": "multipart", "content_type": "video/mp4", "mask_faces": true}, 201)
	masking := upload{
		assetID: created["asset"].(map[string]any)["id"].(string), token: created["upload"].(map[string]any)["token"].(string),
		url: created["upload"].(map[string]any)["url"].(string), method: "multipart", size: 100,
	}
	e.putPart(masking, 1, make([]byte, 100), 200)
	plain := e.create(e.admin, 100, "multipart")
	e.putPart(plain, 1, make([]byte, 100), 200)

	jobsOf := func(kind string) (n int, queue string) {
		t.Helper()
		rows, err := e.pool.Query(context.Background(), `SELECT queue FROM river_job WHERE kind = $1`, kind)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			if err := rows.Scan(&queue); err != nil {
				t.Fatal(err)
			}
			n++
		}
		return n, queue
	}
	e.call(e.admin, "POST", "/v1/assets/"+plain.assetID+"/commit", nil, 200)
	if p, _ := jobsOf("asset.process"); p != 1 {
		t.Fatalf("%d asset.process jobs, want 1", p)
	}
	if n, _ := jobsOf("asset.mask"); n != 0 {
		t.Fatalf("%d asset.mask jobs for an asset without mask_faces", n)
	}
	e.call(e.admin, "POST", "/v1/assets/"+masking.assetID+"/commit", nil, 200)
	e.call(e.admin, "POST", "/v1/assets/"+masking.assetID+"/commit", nil, 200) // idempotent
	if p, q := jobsOf("asset.process"); p != 2 || q != "media" {
		t.Fatalf("asset.process: %d jobs on %q", p, q)
	}
	if n, q := jobsOf("asset.mask"); n != 1 || q != "mask" {
		t.Fatalf("asset.mask: %d jobs on %q, want 1 on mask", n, q)
	}
	// Pending from the start, before the original is ready.
	got, _ := e.call(e.admin, "GET", "/v1/assets/"+masking.assetID, nil, 200)
	if got["masking"].(map[string]any)["state"] != "pending" {
		t.Fatalf("GET: %v", got)
	}
}
