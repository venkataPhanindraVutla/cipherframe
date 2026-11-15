//go:build integration

package api_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/webhook"
)

const hookURL = "https://hooks.example.com/cipherframe"

// receiver is a TLS server that records every webhook request and answers by a script.
type receiver struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  []hit
	reply func(n int) (status int, body string, delay time.Duration)
}

type hit struct {
	hdr  http.Header
	body []byte
}

func newReceiver(t *testing.T, reply func(n int) (int, string, time.Duration)) *receiver {
	t.Helper()
	r := &receiver{reply: reply}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.hits = append(r.hits, hit{hdr: req.Header.Clone(), body: body})
		n := len(r.hits)
		r.mu.Unlock()
		status, text, delay := r.reply(n)
		time.Sleep(delay)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func ok(int) (int, string, time.Duration) { return 200, "ok", 0 }

func (r *receiver) got() []hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.hits)
}

func (r *receiver) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(r.srv.Certificate())
	return p
}

// verified reports which of the secrets (as "whsec_..." text) a signature in the request header
// matches, and fails when the request is not a well-formed Standard Webhooks request.
func verified(t *testing.T, h hit, secrets ...string) []string {
	t.Helper()
	msgID := h.hdr.Get("webhook-id")
	ts, err := strconv.ParseInt(h.hdr.Get("webhook-timestamp"), 10, 64)
	if err != nil || msgID == "" {
		t.Fatalf("webhook-id %q, webhook-timestamp %q", msgID, h.hdr.Get("webhook-timestamp"))
	}
	var env struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(h.body, &env); err != nil || env.ID != msgID {
		t.Fatalf("payload id %q != webhook-id %q (%v)", env.ID, msgID, err)
	}
	sigs := strings.Fields(h.hdr.Get("webhook-signature"))
	var out []string
	for _, s := range secrets {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, viewerauth.SecretPrefix))
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(sigs, viewerauth.Signature(raw, msgID, time.Unix(ts, 0), h.body)) {
			out = append(out, s)
		}
	}
	return out
}

// dispatcher builds a delivery worker that trusts the receiver's certificate and may reach
// loopback, with the harness clock and a jitter-free backoff.
func (h *harness) dispatcher(r *receiver) *webhook.Dispatcher {
	opts := outbound.Options{Timeout: 5 * time.Second, AllowLoopback: true}
	if r != nil {
		opts.RootCAs = r.roots()
	}
	return &webhook.Dispatcher{
		Pool: h.pool, Secrets: viewerauth.NewSecretBox(h.reg), Client: outbound.New(opts),
		Log: slog.New(slog.DiscardHandler), Now: h.clk.Now, Unit: func() float64 { return 0.5 },
	}
}

// drain runs the dispatcher until nothing is due.
func (h *harness) drain(d *webhook.Dispatcher) {
	h.t.Helper()
	for range 50 {
		n, err := d.RunOnce(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
	h.t.Fatal("the dispatcher never ran dry")
}

func (h *harness) createEndpoint(key string, body map[string]any) (endpointID, secret string) {
	h.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	if _, ok := body["url"]; !ok {
		body["url"] = hookURL
	}
	r := h.mustOK(h.do(key, "POST", "/v1/webhook-endpoints", body), 201)
	ep := r.m["endpoint"].(map[string]any)
	return str(ep, "id"), str(r.m, "secret")
}

// point sends an endpoint's deliveries to url. The API refuses the loopback address of a test
// server (that is the point of it), so the tests register a public name and move it here.
func (h *harness) point(endpointID, to string) {
	h.t.Helper()
	eid, err := id.Parse[id.WebhookEndpointKind](endpointID)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.pool.Exec(context.Background(), `UPDATE webhook_endpoints SET url = $2 WHERE id = $1`, eid.UUID(), to); err != nil {
		h.t.Fatal(err)
	}
}

// events returns the kinds and data of the tenant's outbox, oldest first.
func (h *harness) events(res auth.BootstrapResult) (kinds []string, data []map[string]any) {
	h.t.Helper()
	rows, err := h.pool.Query(context.Background(),
		`SELECT kind, data FROM webhook_events WHERE tenant_id = $1 ORDER BY occurred_at, created_at`, res.Tenant.ID.UUID())
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var raw []byte
		if err := rows.Scan(&k, &raw); err != nil {
			h.t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(raw, &m); err != nil {
			h.t.Fatal(err)
		}
		kinds, data = append(kinds, k), append(data, m)
	}
	return kinds, data
}

func (h *harness) deliveries(key, query string) []map[string]any {
	h.t.Helper()
	return items(h.t, h.mustOK(h.do(key, "GET", "/v1/webhook-deliveries"+query, nil), 200))
}

func (h *harness) emitReady(res auth.BootstrapResult) db.Asset { return h.newAsset(res, db.AssetReady) }

func TestWebhookEndpointsAPI(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, _ := h.bootstrap("other")

	r := h.mustOK(h.do(key, "POST", "/v1/webhook-endpoints", map[string]any{"url": hookURL, "events": []string{"asset.ready", "asset.ready", "session.revoked"}}), 201)
	if r.hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", r.hdr.Get("Cache-Control"))
	}
	ep := r.m["endpoint"].(map[string]any)
	eid, secret := str(ep, "id"), str(r.m, "secret")
	if !strings.HasPrefix(eid, "whe_") || !strings.HasPrefix(secret, "whsec_") || len(secret) != len("whsec_")+44 {
		t.Fatalf("id %q, secret %q", eid, secret)
	}
	if got := ep["events"].([]any); len(got) != 2 || ep["enabled"] != true || ep["secret_version"] != 1.0 {
		t.Fatalf("endpoint = %v", ep)
	}

	// The secret is shown once: no read returns it, and the database holds only the wrapped form.
	for _, p := range []string{"/v1/webhook-endpoints", "/v1/webhook-endpoints/" + eid} {
		if g := h.mustOK(h.do(key, "GET", p, nil), 200); strings.Contains(string(g.raw), secret) || strings.Contains(string(g.raw), "whsec_") {
			t.Errorf("GET %s returned a secret: %s", p, g.raw)
		}
	}
	plain, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	var envelope []byte
	if err := h.pool.QueryRow(context.Background(), `SELECT secret_envelope FROM webhook_endpoints`).Scan(&envelope); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, plain) {
		t.Error("the stored secret contains the plain secret")
	}
	if strings.Contains(h.logs.String(), secret) || strings.Contains(h.logs.String(), hookURL) {
		t.Error("a secret or an endpoint URL reached the log")
	}

	// Defaults: every kind, enabled.
	d := h.mustOK(h.do(key, "POST", "/v1/webhook-endpoints", map[string]any{"url": hookURL + "/2"}), 201).m["endpoint"].(map[string]any)
	if len(d["events"].([]any)) != 0 || d["enabled"] != true {
		t.Errorf("defaults = %v", d)
	}

	// Validation: https only, a public address, no credentials, known kinds. The error never
	// repeats the submitted URL.
	for _, bad := range []string{
		"http://hooks.example.com/x", "ftp://hooks.example.com/x", "https://127.0.0.1/x", "https://localhost@evil.example.com/x",
		"https://10.1.2.3/x", "https://192.168.0.9/x", "https://169.254.169.254/latest", "https://[::1]/x", "https://[fd00::1]/x",
		"https://u:p@hooks.example.com/x", "hooks.example.com", "", "https://hooks.example.com/" + strings.Repeat("a", 2100),
	} {
		g := h.do(key, "POST", "/v1/webhook-endpoints", map[string]any{"url": bad})
		h.wantStatus(g, 400, "invalid_request")
		if bad != "" && len(bad) < 100 && strings.Contains(string(g.raw), strings.TrimPrefix(bad, "https://")) {
			t.Errorf("the error for %q repeats it: %s", bad, g.raw)
		}
	}
	h.wantStatus(h.do(key, "POST", "/v1/webhook-endpoints", map[string]any{"url": hookURL, "events": []string{"asset.exploded"}}), 400, "invalid_request")

	// Update.
	u := h.mustOK(h.do(key, "PATCH", "/v1/webhook-endpoints/"+eid, map[string]any{"enabled": false, "events": []string{}}), 200)
	if u.m["enabled"] != false || len(u.m["events"].([]any)) != 0 || str(u.m, "url") != hookURL {
		t.Errorf("update = %s", u.raw)
	}
	h.wantStatus(h.do(key, "PATCH", "/v1/webhook-endpoints/"+eid, map[string]any{"url": "http://hooks.example.com/x"}), 400, "invalid_request")

	// Tenant isolation: another tenant's endpoint does not exist for the caller.
	for _, c := range [][2]string{
		{"GET", "/v1/webhook-endpoints/" + eid},
		{"PATCH", "/v1/webhook-endpoints/" + eid},
		{"DELETE", "/v1/webhook-endpoints/" + eid},
		{"POST", "/v1/webhook-endpoints/" + eid + "/rotate-secret"},
		{"POST", "/v1/webhook-endpoints/" + eid + "/replay-dead"},
		{"GET", "/v1/webhook-endpoints/whe_nonsense"},
	} {
		var body any
		if c[0] == "PATCH" {
			body = map[string]any{"enabled": true}
		}
		h.wantStatus(h.do(otherKey, c[0], c[1], body), 404, "not_found")
	}
	if l := items(t, h.mustOK(h.do(otherKey, "GET", "/v1/webhook-endpoints", nil), 200)); len(l) != 0 {
		t.Errorf("another tenant lists %d endpoints", len(l))
	}
	if l := items(t, h.mustOK(h.do(key, "GET", "/v1/webhook-endpoints", nil), 200)); len(l) != 2 {
		t.Errorf("the tenant lists %d endpoints, want 2", len(l))
	}

	// Scopes: the endpoints need webhooks:manage; assets:read is not enough.
	client := h.newClient(key, "reader")
	reader := str(h.newKey(key, client, "reader", []string{"assets:read"}).m, "key")
	h.wantStatus(h.do(reader, "GET", "/v1/webhook-endpoints", nil), 403, "forbidden")
	hooker := str(h.newKey(key, client, "hooker", []string{"webhooks:manage"}).m, "key")
	h.mustOK(h.do(hooker, "GET", "/v1/webhook-endpoints", nil), 200)

	// Delete.
	if g := h.do(key, "DELETE", "/v1/webhook-endpoints/"+eid, nil); g.status != 204 {
		t.Fatalf("delete: %d %s", g.status, g.raw)
	}
	h.wantStatus(h.do(key, "GET", "/v1/webhook-endpoints/"+eid, nil), 404, "not_found")

	actions := map[string]bool{}
	evs, err := h.repos.ListAuditEvents(context.Background(), res.Tenant.ID, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range evs {
		actions[a.Action] = true
		if strings.Contains(a.Target, "https://") || strings.Contains(a.Target, "whsec_") {
			t.Errorf("audit target %q names a URL or a secret", a.Target)
		}
	}
	for _, want := range []string{webhook.AuditEndpointCreate, webhook.AuditEndpointUpdate, webhook.AuditEndpointDelete} {
		if !actions[want] {
			t.Errorf("no audit event %q", want)
		}
	}
}

func TestWebhookEndpointCap(t *testing.T) {
	h := newHarness(t)
	key, _ := h.bootstrap("acme")
	otherKey, _ := h.bootstrap("other")
	for i := range db.MaxWebhookEndpoints {
		h.createEndpoint(key, map[string]any{"url": hookURL + "/" + strconv.Itoa(i)})
	}
	h.wantStatus(h.do(key, "POST", "/v1/webhook-endpoints", map[string]any{"url": hookURL}), 409, "conflict")
	h.createEndpoint(otherKey, nil) // the cap is per tenant
}

func TestWebhookEmissionAtEveryEventPoint(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, otherRes := h.bootstrap("other")
	h.createEndpoint(key, nil)
	h.createEndpoint(otherKey, nil)
	filtered, _ := h.createEndpoint(key, map[string]any{"events": []string{"asset.ready"}})
	disabled, _ := h.createEndpoint(key, map[string]any{"enabled": false})
	ctx := context.Background()

	// asset.ready and asset.failed.
	ready := h.newAsset(res, db.AssetReady)
	processing := h.newAsset(res, db.AssetProcessing)
	if _, err := h.repos.TransitionAsset(ctx, res.Tenant.ID, processing.ID, db.Transition{From: db.AssetProcessing, To: db.AssetFailed, FailureCode: "unsupported_codec"}); err != nil {
		t.Fatal(err)
	}
	// session.revoked, through the API, and session.anomaly.
	sid := str(h.mustOK(h.createSession(key, ready.ID.String(), "viewer-1"), 201).m, "session_id")
	h.mustOK(h.do(key, "POST", "/v1/playback-sessions/"+sid+"/revoke", map[string]any{"reason": "fraud"}), 200)
	parsed, _ := id.ParseSession(sid)
	h.seedEvent(res, ready, db.SessionHash(parsed), "", db.EventKeyReplay, h.clk.Now(), map[string]int64{"limit": 20})
	// retention.expired, then asset.deleted.
	if _, err := h.repos.RequestAssetDeletion(ctx, res.Tenant.ID, ready.ID, db.DeletionRetention, h.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.repos.CompleteAssetDeletion(ctx, res.Tenant.ID, ready.ID, h.clk.Now()); err != nil {
		t.Fatal(err)
	}

	kinds, data := h.events(res)
	want := []string{"asset.ready", "asset.failed", "session.revoked", "session.anomaly", "retention.expired", "asset.deleted"}
	slices.Sort(want)
	got := slices.Clone(kinds)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("event kinds = %v, want %v", got, want)
	}

	// Payloads: IDs, states, codes and small numbers; no address, user agent, file name, key or token.
	allowed := map[string][]string{
		"asset.ready": {"asset_id", "state"}, "asset.failed": {"asset_id", "state", "failure_code"},
		"asset.deleted": {"asset_id", "state", "reason"}, "retention.expired": {"asset_id", "state", "expires_at"},
		"session.revoked": {"asset_id", "viewer_id", "session", "reason"}, "session.anomaly": {"kind", "asset_id", "viewer_id", "session", "detail"},
	}
	for i, k := range kinds {
		for f := range data[i] {
			if !slices.Contains(allowed[k], f) {
				t.Errorf("%s carries an unexpected field %q", k, f)
			}
		}
		raw, _ := json.Marshal(data[i])
		for _, secret := range []string{sid, sid[4:], "test-fixture-source", "127.0.0.1"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("%s payload contains %q", k, secret)
			}
		}
		switch k {
		case "asset.failed":
			if data[i]["failure_code"] != "unsupported_codec" || data[i]["state"] != "failed" {
				t.Errorf("asset.failed = %v", data[i])
			}
		case "asset.deleted":
			if data[i]["reason"] != "retention" || data[i]["state"] != "deleted" {
				t.Errorf("asset.deleted = %v", data[i])
			}
		case "session.revoked":
			if data[i]["viewer_id"] != "viewer-1" || data[i]["reason"] != "fraud" || len(data[i]["session"].(string)) != 8 {
				t.Errorf("session.revoked = %v", data[i])
			}
		}
	}

	// The anomaly's webhook event is the playback event: the same ID.
	var same int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM webhook_events w JOIN playback_events p ON p.id = w.id WHERE w.kind = 'session.anomaly'`).Scan(&same); err != nil || same != 1 {
		t.Errorf("anomaly events sharing an ID with playback_events = %d (%v)", same, err)
	}

	// Another tenant's endpoint saw none of it, the filter held and the disabled endpoint got nothing.
	if k, _ := h.events(otherRes); len(k) != 0 {
		t.Errorf("another tenant has events: %v", k)
	}
	if l := h.deliveries(otherKey, ""); len(l) != 0 {
		t.Errorf("another tenant lists %d deliveries", len(l))
	}
	if l := h.deliveries(key, "?endpoint_id="+filtered); len(l) != 1 || kinds2(l)[0] != "asset.ready" {
		t.Errorf("the filtered endpoint has deliveries %v", kinds2(l))
	}
	if l := h.deliveries(key, "?endpoint_id="+disabled); len(l) != 0 {
		t.Errorf("the disabled endpoint has %d deliveries", len(l))
	}
	if l := h.deliveries(key, ""); len(l) != 6+1 {
		t.Errorf("the tenant has %d deliveries, want 7 (6 for the open endpoint, 1 for the filtered one)", len(l))
	}
}

func kinds2(l []map[string]any) []string { return kinds(l) }

// An event exists if and only if the change that caused it committed.
func TestWebhookEventsAreWrittenInTheTransactionOfTheChange(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	h.createEndpoint(key, nil)
	processing := h.newAsset(res, db.AssetProcessing)
	ctx := context.Background()

	rollback := db.Tx(ctx, h.pool, func(tx *db.Repos) error {
		if _, err := tx.TransitionAsset(ctx, res.Tenant.ID, processing.ID, db.Transition{From: db.AssetProcessing, To: db.AssetReady}); err != nil {
			return err
		}
		return pgx.ErrTxClosed // any error: roll back
	})
	if rollback == nil {
		t.Fatal("the transaction should have rolled back")
	}
	if k, _ := h.events(res); len(k) != 0 {
		t.Fatalf("a rolled-back change left events %v", k)
	}
	if err := db.Tx(ctx, h.pool, func(tx *db.Repos) error {
		_, err := tx.TransitionAsset(ctx, res.Tenant.ID, processing.ID, db.Transition{From: db.AssetProcessing, To: db.AssetReady})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if k, _ := h.events(res); !slices.Equal(k, []string{"asset.ready"}) {
		t.Fatalf("a committed change left events %v", k)
	}
}

func TestWebhookDeliveryIsSignedAndRetriedUntilItSucceeds(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	rcv := newReceiver(t, func(n int) (int, string, time.Duration) {
		switch n {
		case 1:
			return 503, "try \x00 later\r\n<b>soon</b>", 30 * time.Millisecond
		case 2:
			return 500, strings.Repeat("x", 5000), 0
		}
		return 200, "ok", 0
	})
	eid, secret := h.createEndpoint(key, nil)
	h.point(eid, rcv.srv.URL+"/hook")
	asset := h.emitReady(res)
	h.clk.Advance(time.Minute)
	d := h.dispatcher(rcv)

	h.drain(d)
	if n := len(rcv.got()); n != 1 {
		t.Fatalf("%d requests after the first pass, want 1", n)
	}
	del := h.deliveries(key, "")[0]
	if del["status"] != "pending" || del["attempts"] != 1.0 || del["last_status_code"] != 503.0 {
		t.Fatalf("after the first failure: %v", del)
	}
	// Exponential backoff: the first retry is due 10 seconds after the attempt (no jitter in the test).
	next, err := time.Parse(time.RFC3339Nano, str(del, "next_attempt_at"))
	if err != nil || !next.Equal(h.clk.Now().Add(10*time.Second)) {
		t.Fatalf("next attempt at %v (%v), want %v", next, err, h.clk.Now().Add(10*time.Second))
	}
	h.drain(d)
	if n := len(rcv.got()); n != 1 {
		t.Fatalf("the retry came early: %d requests", n)
	}

	h.clk.Advance(11 * time.Second)
	h.drain(d)
	h.clk.Advance(31 * time.Second)
	h.drain(d)
	hits := rcv.got()
	if len(hits) != 3 {
		t.Fatalf("%d requests, want 3", len(hits))
	}
	for i, hh := range hits {
		if m := verified(t, hh, secret); len(m) != 1 {
			t.Errorf("request %d is not signed with the endpoint secret", i+1)
		}
		if hh.hdr.Get("webhook-id") != hits[0].hdr.Get("webhook-id") || !bytes.Equal(hh.body, hits[0].body) {
			t.Errorf("request %d is not the same event and body as the first (receivers deduplicate on the ID)", i+1)
		}
		if hh.hdr.Get("Content-Type") != "application/json" || hh.hdr.Get("User-Agent") != webhook.UserAgent {
			t.Errorf("headers = %v", hh.hdr)
		}
	}
	// The timestamp is fresh on each attempt, for the receiver's replay window.
	if hits[0].hdr.Get("webhook-timestamp") == hits[2].hdr.Get("webhook-timestamp") {
		t.Error("the timestamp did not change between attempts")
	}
	var env struct {
		ID         string         `json:"id"`
		Type       string         `json:"type"`
		OccurredAt string         `json:"occurred_at"`
		TenantID   string         `json:"tenant_id"`
		Data       map[string]any `json:"data"`
	}
	if err := json.Unmarshal(hits[2].body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != "asset.ready" || env.TenantID != res.Tenant.ID.String() || env.Data["asset_id"] != asset.ID.String() || env.Data["state"] != "ready" || env.OccurredAt == "" {
		t.Errorf("payload = %s", hits[2].body)
	}
	if len(env.Data) != 2 {
		t.Errorf("payload data = %v: ids and states only", env.Data)
	}

	del = h.deliveries(key, "")[0]
	if del["status"] != "succeeded" || del["attempts"] != 3.0 || del["completed_at"] == nil {
		t.Fatalf("after success: %v", del)
	}
	detail := h.mustOK(h.do(key, "GET", "/v1/webhook-deliveries/"+str(del, "id"), nil), 200)
	attempts := detail.m["attempts"].([]any)
	if len(attempts) != 3 {
		t.Fatalf("%d attempts recorded", len(attempts))
	}
	a1, a2, a3 := attempts[0].(map[string]any), attempts[1].(map[string]any), attempts[2].(map[string]any)
	if a1["status_code"] != 503.0 || a1["error"] != "status" || a1["duration_ms"].(float64) < 25 || a2["status_code"] != 500.0 || a3["status_code"] != 200.0 || a3["error"] != nil {
		t.Errorf("attempts = %v", attempts)
	}
	// The response is kept only as a small sanitized excerpt: printable, one line, at most 200 characters.
	if ex := str(a1, "excerpt"); ex != "try later <b>soon</b>" {
		t.Errorf("excerpt = %q", ex)
	}
	if ex := str(a2, "excerpt"); len(ex) != webhook.MaxExcerptChars {
		t.Errorf("a long response is kept as %d characters", len(ex))
	}
	for _, leak := range []string{secret, rcv.srv.URL} {
		if strings.Contains(string(detail.raw), leak) || strings.Contains(h.logs.String(), leak) {
			t.Errorf("a secret or URL leaked into the delivery detail or the log")
		}
	}

	// Tenant isolation: another tenant cannot read or replay the delivery.
	otherKey, _ := h.bootstrap("other")
	h.wantStatus(h.do(otherKey, "GET", "/v1/webhook-deliveries/"+str(del, "id"), nil), 404, "not_found")
	h.wantStatus(h.do(otherKey, "POST", "/v1/webhook-deliveries/"+str(del, "id")+"/replay", nil), 404, "not_found")
}

func TestWebhookDeadLetterAndReplay(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	failing := true
	rcv := newReceiver(t, func(int) (int, string, time.Duration) {
		if failing {
			return 500, "down", 0
		}
		return 200, "ok", 0
	})
	eid, secret := h.createEndpoint(key, nil)
	h.point(eid, rcv.srv.URL)
	h.emitReady(res)
	h.emitReady(res)
	h.clk.Advance(time.Minute)
	d := h.dispatcher(rcv)

	var total time.Duration
	for i := range webhook.MaxAttempts {
		h.drain(d)
		if i < webhook.MaxAttempts-1 {
			wait := webhook.Delay(i + 1)
			total += wait
			h.clk.Advance(wait)
		}
	}
	if total < 20*time.Hour || total > 24*time.Hour {
		t.Fatalf("the last attempt was %v after the first, want about a day", total)
	}
	if n := len(rcv.got()); n != 2*webhook.MaxAttempts {
		t.Fatalf("%d requests, want %d (two deliveries, each tried %d times)", n, 2*webhook.MaxAttempts, webhook.MaxAttempts)
	}
	h.clk.Advance(48 * time.Hour)
	h.drain(d)
	if n := len(rcv.got()); n != 2*webhook.MaxAttempts {
		t.Fatalf("a dead delivery was tried again: %d requests", n)
	}

	dead := h.deliveries(key, "?status=dead")
	if len(dead) != 2 || dead[0]["attempts"] != float64(webhook.MaxAttempts) || dead[0]["completed_at"] == nil || dead[0]["status"] != "dead" {
		t.Fatalf("dead-letter list = %v", dead)
	}
	if l := h.deliveries(key, "?status=pending"); len(l) != 0 {
		t.Errorf("%d deliveries still pending", len(l))
	}
	if l := h.deliveries(key, "?status=dead&endpoint_id="+eid); len(l) != 2 {
		t.Errorf("filter by endpoint: %d", len(l))
	}
	h.wantStatus(h.do(key, "GET", "/v1/webhook-deliveries?status=gone", nil), 400, "invalid_request")
	h.wantStatus(h.do(key, "GET", "/v1/webhook-deliveries?endpoint_id=nope", nil), 400, "invalid_request")

	// Pagination.
	page := h.mustOK(h.do(key, "GET", "/v1/webhook-deliveries?limit=1", nil), 200)
	if len(items(t, page)) != 1 || str(page.m, "next_cursor") == "" {
		t.Fatalf("page = %s", page.raw)
	}
	next := h.mustOK(h.do(key, "GET", "/v1/webhook-deliveries?limit=1&cursor="+url.QueryEscape(str(page.m, "next_cursor")), nil), 200)
	if len(items(t, next)) != 1 || items(t, next)[0]["id"] == items(t, page)[0]["id"] || next.m["next_cursor"] != nil {
		t.Fatalf("next page = %s", next.raw)
	}

	// Replay one: pending again with a fresh budget; the receiver, now healthy, gets the same event.
	failing = false
	first := str(dead[0], "id")
	before := len(rcv.got())
	r := h.mustOK(h.do(key, "POST", "/v1/webhook-deliveries/"+first+"/replay", nil), 202)
	if r.m["status"] != "pending" || r.m["attempts"] != 0.0 {
		t.Fatalf("replayed = %s", r.raw)
	}
	h.wantStatus(h.do(key, "POST", "/v1/webhook-deliveries/"+first+"/replay", nil), 409, "conflict") // still pending
	h.clk.Advance(time.Second)
	h.drain(d)
	hits := rcv.got()
	if len(hits) != before+1 {
		t.Fatalf("%d requests after the replay, want %d", len(hits), before+1)
	}
	last := hits[len(hits)-1]
	if m := verified(t, last, secret); len(m) != 1 || last.hdr.Get("webhook-id") != str(dead[0], "event_id") {
		t.Errorf("the replay is not the same signed event (webhook-id %q, event %q)", last.hdr.Get("webhook-id"), str(dead[0], "event_id"))
	}
	if g := h.mustOK(h.do(key, "GET", "/v1/webhook-deliveries/"+first, nil), 200); g.m["delivery"].(map[string]any)["status"] != "succeeded" || len(g.m["attempts"].([]any)) != webhook.MaxAttempts+1 {
		t.Errorf("after the replay: %s", g.raw)
	}

	// Replay every dead delivery of the endpoint: the one left (the other was replayed above).
	failing = true
	if r = h.mustOK(h.do(key, "POST", "/v1/webhook-endpoints/"+eid+"/replay-dead", nil), 200); r.m["replayed"] != 1.0 {
		t.Fatalf("replay-dead = %s", r.raw)
	}
	if r = h.mustOK(h.do(key, "POST", "/v1/webhook-endpoints/"+eid+"/replay-dead", nil), 200); r.m["replayed"] != 0.0 {
		t.Fatalf("second replay-dead = %s", r.raw)
	}
	// A delivery that succeeded can be replayed too.
	r = h.mustOK(h.do(key, "POST", "/v1/webhook-deliveries/"+first+"/replay", nil), 202)
	if r.m["status"] != "pending" {
		t.Fatalf("replay of a succeeded delivery = %s", r.raw)
	}
}

func TestWebhookDeliveryRefusesPrivateDestinations(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	rcv := newReceiver(t, ok)
	eid, _ := h.createEndpoint(key, nil)
	// The URL passed the check at registration; it now resolves to loopback. The production client
	// (no AllowLoopback) refuses to dial it, whatever the DNS said at registration.
	h.point(eid, rcv.srv.URL)
	h.emitReady(res)
	h.clk.Advance(time.Minute)
	d := h.dispatcher(rcv)
	d.Client = outbound.New(outbound.Options{Timeout: time.Second})
	h.drain(d)
	if n := len(rcv.got()); n != 0 {
		t.Fatalf("a private destination was reached: %d requests", n)
	}
	del := h.deliveries(key, "")[0]
	detail := h.mustOK(h.do(key, "GET", "/v1/webhook-deliveries/"+str(del, "id"), nil), 200)
	a := detail.m["attempts"].([]any)[0].(map[string]any)
	if del["status"] != "pending" || a["error"] != "blocked_address" || a["status_code"] != nil {
		t.Fatalf("delivery = %v, attempt = %v", del, a)
	}
}

func TestWebhookSecretRotationSignsWithBothSecretsForADay(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	rcv := newReceiver(t, ok)
	eid, old := h.createEndpoint(key, nil)
	h.point(eid, rcv.srv.URL)
	d := h.dispatcher(rcv)
	h.clk.Advance(time.Minute)

	h.emitReady(res)
	h.clk.Advance(time.Minute)
	h.drain(d)

	r := h.mustOK(h.do(key, "POST", "/v1/webhook-endpoints/"+eid+"/rotate-secret", nil), 200)
	if r.hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", r.hdr.Get("Cache-Control"))
	}
	fresh := str(r.m, "secret")
	if !strings.HasPrefix(fresh, "whsec_") || fresh == old || r.m["version"] != 2.0 {
		t.Fatalf("rotation = %s", r.raw)
	}
	if g := h.mustOK(h.do(key, "GET", "/v1/webhook-endpoints/"+eid, nil), 200); g.m["secret_version"] != 2.0 || g.m["previous_secret_valid_until"] == nil || strings.Contains(string(g.raw), fresh) {
		t.Errorf("endpoint after rotation = %s", g.raw)
	}

	h.emitReady(res)
	h.clk.Advance(time.Minute)
	h.drain(d)
	h.emitReady(res)
	h.clk.Advance(25 * time.Hour)
	h.drain(d)

	hits := rcv.got()
	if len(hits) != 3 {
		t.Fatalf("%d requests, want 3", len(hits))
	}
	if m := verified(t, hits[0], old, fresh); !slices.Equal(m, []string{old}) || len(strings.Fields(hits[0].hdr.Get("webhook-signature"))) != 1 {
		t.Errorf("before the rotation: verified by %v", m)
	}
	if m := verified(t, hits[1], old, fresh); !slices.Equal(m, []string{old, fresh}) || len(strings.Fields(hits[1].hdr.Get("webhook-signature"))) != 2 {
		t.Errorf("just after the rotation both secrets must sign, verified by %v", m)
	}
	if m := verified(t, hits[2], old, fresh); !slices.Equal(m, []string{fresh}) || len(strings.Fields(hits[2].hdr.Get("webhook-signature"))) != 1 {
		t.Errorf("a day after the rotation only the new secret signs, verified by %v", m)
	}
	if g := h.mustOK(h.do(key, "GET", "/v1/webhook-endpoints/"+eid, nil), 200); g.m["previous_secret_valid_until"] != nil {
		t.Errorf("the previous secret is still reported valid: %s", g.raw)
	}
}

// A wrapped secret is bound to its endpoint: an envelope copied to another endpoint of the same
// tenant does not open, so nothing is sent with it and the attempt is not counted.
func TestWebhookSecretEnvelopeIsBoundToItsEndpoint(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	rcv := newReceiver(t, ok)
	a, _ := h.createEndpoint(key, nil)
	b, _ := h.createEndpoint(key, nil)
	h.point(a, rcv.srv.URL+"/a")
	h.point(b, rcv.srv.URL+"/b")
	ea, _ := id.Parse[id.WebhookEndpointKind](a)
	eb, _ := id.Parse[id.WebhookEndpointKind](b)
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE webhook_endpoints SET secret_envelope = (SELECT secret_envelope FROM webhook_endpoints WHERE id = $1) WHERE id = $2`, ea.UUID(), eb.UUID()); err != nil {
		t.Fatal(err)
	}
	h.emitReady(res)
	h.clk.Advance(time.Minute)
	h.drain(h.dispatcher(rcv))
	if n := len(rcv.got()); n != 1 {
		t.Fatalf("%d requests, want 1 (endpoint a only)", n)
	}
	for _, del := range h.deliveries(key, "?endpoint_id="+b) {
		if del["attempts"] != 0.0 || del["status"] != "pending" {
			t.Errorf("the delivery with a foreign envelope = %v", del)
		}
	}
}

func TestWebhookDeliveryWaitsWhileTheEndpointIsDisabled(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	rcv := newReceiver(t, ok)
	eid, _ := h.createEndpoint(key, nil)
	h.point(eid, rcv.srv.URL)
	h.emitReady(res)
	h.clk.Advance(time.Minute)
	h.mustOK(h.do(key, "PATCH", "/v1/webhook-endpoints/"+eid, map[string]any{"enabled": false}), 200)
	d := h.dispatcher(rcv)
	h.drain(d)
	if n := len(rcv.got()); n != 0 {
		t.Fatalf("a disabled endpoint received %d requests", n)
	}
	h.mustOK(h.do(key, "PATCH", "/v1/webhook-endpoints/"+eid, map[string]any{"enabled": true}), 200)
	h.drain(d)
	if n := len(rcv.got()); n != 1 {
		t.Fatalf("after enabling: %d requests, want 1", n)
	}
}

// Deleting an endpoint takes its deliveries with it, and the retention sweep removes events and
// deliveries past the window.
func TestWebhookRetentionDeletesOldEventsWithTheirDeliveries(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	h.createEndpoint(key, nil)
	h.emitReady(res)
	h.emitReady(res)
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx, `UPDATE webhook_events SET created_at = now() - interval '100 days' WHERE id = (SELECT id FROM webhook_events ORDER BY id LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	n, err := h.repos.DeleteWebhookEventsBefore(ctx, time.Now().AddDate(0, 0, -90), 100)
	if err != nil || n != 1 {
		t.Fatalf("deleted %d events (%v), want 1", n, err)
	}
	var events, deliveries int
	if err := h.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM webhook_events), (SELECT count(*) FROM webhook_deliveries)`).Scan(&events, &deliveries); err != nil {
		t.Fatal(err)
	}
	if events != 1 || deliveries != 1 {
		t.Errorf("%d events and %d deliveries left, want 1 and 1", events, deliveries)
	}
}
