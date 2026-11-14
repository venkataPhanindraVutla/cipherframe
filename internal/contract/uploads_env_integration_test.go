//go:build integration

package contract

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

const mib = 1 << 20

// Test limits: the smallest legal part size keeps multipart tests quick.
const (
	testPartBytes  = 5 * mib
	testMaxSource  = 64 * mib
	testTokenTTL   = time.Hour
	tusProtocolVer = "1.0.0"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

func (s *syncBuf) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// captured is one HTTP exchange as a client saw the response: status line, headers and body.
type captured struct {
	label       string
	text        string
	issuesToken bool // the one response that may carry an upload token
}

// recorder is an http.RoundTripper that keeps every response, headers included.
type recorder struct {
	mu   sync.Mutex
	all  []captured
	next http.RoundTripper
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var hdr strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&hdr, "%s: %s\n", k, v)
		}
	}
	c := captured{
		label:       req.Method + " " + req.URL.Path,
		text:        resp.Status + "\n" + hdr.String() + "\n" + string(body),
		issuesToken: req.Method == http.MethodPost && req.URL.Path == "/v1/assets" && resp.StatusCode == http.StatusCreated,
	}
	r.mu.Lock()
	r.all = append(r.all, c)
	r.mu.Unlock()
	return resp, rerr
}

func (r *recorder) snapshot() []captured {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]captured(nil), r.all...)
}

// upEnv is the api and edge listeners over a real Postgres and SeaweedFS.
type upEnv struct {
	t        *testing.T
	doc      *openapi3.T
	pool     *pgxpool.Pool
	repos    *db.Repos
	sw       *storagetest.Seaweed
	s3       *s3.Client
	buckets  *storage.Buckets
	apiSrv   *httptest.Server
	edgeSrv  *httptest.Server
	clk      *clock
	logs     *syncBuf
	rec      *recorder
	client   *http.Client
	svc      *uploads.Service
	mgr      *auth.Manager
	admin    string // full admin key of the first tenant
	tenant   db.Tenant
	clientID id.ClientID
	apiKeys  []string
	tusSeen  map[string]bool // tus operations that were exercised and validated against the spec
	covered  map[string]bool // spec operations that answered 2xx and matched the spec
}

func newUpEnv(t *testing.T) *upEnv {
	t.Helper()
	return newUpEnvWith(t, uploads.Limits{MaxSourceBytes: testMaxSource, PartBytes: testPartBytes, TokenTTL: testTokenTTL})
}

func newUpEnvWith(t *testing.T, limits uploads.Limits) *upEnv {
	t.Helper()
	ctx := context.Background()
	e := &upEnv{t: t, doc: loadSpec(t), pool: dbtest.NewMigrated(t), sw: storagetest.Shared(t), logs: &syncBuf{}, tusSeen: map[string]bool{}, covered: map[string]bool{}}
	e.repos = db.New(e.pool)
	e.s3 = e.sw.Client()
	e.clk = &clock{t: time.Now().UTC().Truncate(time.Microsecond)}
	e.rec = &recorder{next: http.DefaultTransport}
	e.client = &http.Client{Transport: e.rec, Timeout: 2 * time.Minute}

	var err error
	if e.buckets, err = storage.New(ctx, e.sw.Config()); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The edge's address is needed for the create response, so reserve the listener first.
	e.edgeSrv = httptest.NewUnstartedServer(nil)
	edgeURL := "http://" + e.edgeSrv.Listener.Addr().String()

	reg := jobs.NewRegistry()
	if err := jobs.Declare[uploads.ProcessArgs](reg, jobs.KindConfig{Queue: jobs.QueueMedia}); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Declare[uploads.MaskArgs](reg, jobs.KindConfig{Queue: jobs.QueueMask}); err != nil {
		t.Fatal(err)
	}
	queue, err := jobs.NewQueue(e.pool, reg, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	e.svc, err = uploads.NewService(uploads.Deps{
		Pool: e.pool, Source: e.buckets.Source, Queue: queue, Limits: limits, EdgeURL: edgeURL, Log: log, Now: e.clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.mgr = auth.NewManager(e.pool, onePepper{}, e.clk.Now)
	a := api.New(api.Deps{
		Log: log, Verifier: auth.NewVerifier(e.repos, onePepper{}, log, e.clk.Now), Manager: e.mgr, Assets: e.svc,
	})
	e.apiSrv = httptest.NewServer(a.Handler())
	t.Cleanup(e.apiSrv.Close)

	s3c, err := storage.NewS3Client(ctx, e.sw.Config())
	if err != nil {
		t.Fatal(err)
	}
	tus, err := uploads.NewTusStore(uploads.TusDeps{
		Pool: e.pool, S3: s3c, Bucket: storagetest.SourceBucket, Limits: limits, Now: e.clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ed := edge.New(edge.Deps{Log: log, Uploads: &edge.Uploads{
		Authz:     uploads.NewAuthorizer(e.repos, e.clk.Now),
		Parts:     uploads.NewReceiver(e.repos, e.buckets.Source, limits, e.clk.Now),
		Tus:       tus,
		Locker:    uploads.NewLocker(e.pool),
		Limits:    limits,
		PublicURL: edgeURL,
	}})
	e.edgeSrv.Config.Handler = ed.Handler()
	e.edgeSrv.Start()
	t.Cleanup(e.edgeSrv.Close)

	res, err := e.mgr.Bootstrap(ctx, "uploads", "uploads client")
	if err != nil {
		t.Fatal(err)
	}
	e.admin, e.tenant, e.clientID = res.Secret.Reveal(), res.Tenant, res.Client.ID
	e.apiKeys = append(e.apiKeys, e.admin)
	return e
}

// newTenant bootstraps another tenant and returns its admin key.
func (e *upEnv) newTenant(name string) string {
	e.t.Helper()
	res, err := e.mgr.Bootstrap(context.Background(), name, name+" client")
	if err != nil {
		e.t.Fatal(err)
	}
	k := res.Secret.Reveal()
	e.apiKeys = append(e.apiKeys, k)
	return k
}

// send sends req through the recording client and returns the exchange. When validateSpec is true
// the exchange is also checked against the spec and its operation ID returned.
func (e *upEnv) send(req *http.Request, body []byte, validateSpec bool) (exchange, string) {
	e.t.Helper()
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	ex := exchange{req, resp, out}
	op := ""
	if validateSpec {
		op = validate(e.t, e.doc, ex)
		if op != "" && resp.StatusCode < 300 {
			e.covered[op] = true
		}
	}
	return ex, op
}

func (e *upEnv) newReq(method, base, path string, hdr map[string]string, body []byte) *http.Request {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, base+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

// call is an API call with an API key (empty for none), validated against the spec. It returns the
// decoded JSON object and the exchange.
func (e *upEnv) call(key, method, path string, in any, wantStatus int) (map[string]any, exchange) {
	e.t.Helper()
	var raw []byte
	hdr := map[string]string{}
	if in != nil {
		raw, _ = json.Marshal(in)
		hdr["Content-Type"] = "application/json"
	}
	if key != "" {
		hdr["Authorization"] = "Bearer " + key
	}
	// A request that breaks the spec's own constraints is sent without request validation; the 400
	// answer must still be a valid Problem.
	ex, _ := e.send(e.newReq(method, e.apiSrv.URL, path, hdr, raw), raw, wantStatus != http.StatusBadRequest)
	if ex.resp.StatusCode != wantStatus {
		e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, ex.resp.StatusCode, wantStatus, ex.body)
	}
	if wantStatus == http.StatusBadRequest {
		validateProblem(e.t, e.doc, ex)
	}
	var m map[string]any
	_ = json.Unmarshal(ex.body, &m)
	return m, ex
}

// edgeCall is an edge call authorised by an upload token (empty for none), validated against the
// spec when the spec describes it.
func (e *upEnv) edgeCall(token, method, path string, body []byte, wantStatus int) (map[string]any, exchange) {
	e.t.Helper()
	hdr := map[string]string{}
	if body != nil {
		hdr["Content-Type"] = "application/octet-stream"
	}
	if token != "" {
		hdr["Authorization"] = "Bearer " + token
	}
	ex, _ := e.send(e.newReq(method, e.edgeSrv.URL, path, hdr, body), body, wantStatus != http.StatusBadRequest)
	if ex.resp.StatusCode != wantStatus {
		e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, ex.resp.StatusCode, wantStatus, ex.body)
	}
	if wantStatus == http.StatusBadRequest {
		validateProblem(e.t, e.doc, ex)
	}
	var m map[string]any
	_ = json.Unmarshal(ex.body, &m)
	return m, ex
}

// upload is the result of creating an asset.
type upload struct {
	assetID  string
	token    string
	url      string
	partSize int64
	method   string
	size     int64
}

func (e *upEnv) create(key string, size int64, method string) upload {
	e.t.Helper()
	m, _ := e.call(key, "POST", "/v1/assets", map[string]any{"size_bytes": size, "upload_method": method, "content_type": "video/mp4"}, 201)
	asset := m["asset"].(map[string]any)
	ins := m["upload"].(map[string]any)
	u := upload{
		assetID: asset["id"].(string), token: ins["token"].(string), url: ins["url"].(string),
		method: ins["method"].(string), size: size,
	}
	if ps, ok := ins["part_size_bytes"].(float64); ok {
		u.partSize = int64(ps)
	}
	return u
}

// dbAsset reads the asset row, source key included, for assertions only.
func (e *upEnv) dbAsset(assetID string) db.Asset {
	e.t.Helper()
	aid, err := id.Parse[id.AssetKind](assetID)
	if err != nil {
		e.t.Fatal(err)
	}
	a, err := e.repos.GetAsset(context.Background(), e.tenant.ID, aid)
	if err != nil {
		e.t.Fatalf("asset %s not found in the first tenant: %v", assetID, err)
	}
	return a
}

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func sum(b []byte) [32]byte { return sha256.Sum256(b) }

// sourceObject reads the assembled source object straight from the bucket.
func (e *upEnv) sourceObject(a db.Asset) []byte {
	e.t.Helper()
	rc, _, err := e.buckets.Source.Get(context.Background(), a.SourceKey, nil)
	if err != nil {
		e.t.Fatalf("read the source object: %v", err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// sourceObjects lists every key under the asset's source prefix.
func (e *upEnv) sourceObjects(a db.Asset) []string {
	e.t.Helper()
	var out []string
	for o, err := range storage.ListAll(context.Background(), e.buckets.Source, keys.SourcePrefix(a.TenantID, a.ID)) {
		if err != nil {
			e.t.Fatal(err)
		}
		out = append(out, o.Key)
	}
	return out
}

// openMultipartUploads counts unfinished multipart uploads under the asset's source prefix.
func (e *upEnv) openMultipartUploads(a db.Asset) int {
	e.t.Helper()
	out, err := e.s3.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket: aws.String(storagetest.SourceBucket), Prefix: aws.String(keys.SourcePrefix(a.TenantID, a.ID)),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return len(out.Uploads)
}

func (e *upEnv) processJobs() (count int, args []string) {
	e.t.Helper()
	rows, err := e.pool.Query(context.Background(), `SELECT args::text FROM river_job WHERE kind = 'asset.process' ORDER BY id`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			e.t.Fatal(err)
		}
		args = append(args, a)
	}
	return len(args), args
}

func (e *upEnv) assertState(key, assetID, want string) map[string]any {
	e.t.Helper()
	m, _ := e.call(key, "GET", "/v1/assets/"+assetID, nil, 200)
	if m["state"] != want {
		e.t.Fatalf("asset %s: state %v, want %s", assetID, m["state"], want)
	}
	return m
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// assertEveryUploadOperationExercised fails when an asset or upload operation of the spec was not
// called with a 2xx answer that matched the spec (tus operations are checked on their own list).
func (e *upEnv) assertEveryUploadOperationExercised() {
	e.t.Helper()
	for path, item := range e.doc.Paths.Map() {
		for method, op := range item.Operations() {
			if !strings.HasPrefix(path, "/v1/assets") && !strings.HasPrefix(path, "/v1/uploads/") {
				continue
			}
			if strings.HasSuffix(path, "/access-log") {
				continue // exercised by TestAccessLogAndPrivacyOperationsMatchSpec
			}
			if strings.HasSuffix(path, "/manifest") || strings.HasSuffix(path, "/manifest/timestamp") || strings.HasSuffix(path, "/proof") {
				continue // exercised by TestIntegrityOperationsMatchSpec
			}
			tus := false
			for _, tag := range op.Tags {
				tus = tus || tag == "tus"
			}
			switch {
			case tus && !e.tusSeen[op.OperationID]:
				e.t.Errorf("%s %s (%s) was not exercised against the tus mount", method, path, op.OperationID)
			case !tus && !e.covered[op.OperationID]:
				e.t.Errorf("%s %s (%s) was not exercised with a 2xx response", method, path, op.OperationID)
			}
		}
	}
}
