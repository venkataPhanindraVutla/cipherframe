//go:build integration

package api_test

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/quota"
)

// quotaHarness is a harness whose API has the quota service and the per-key rate limiter, and that
// keeps the playback service to start sessions the way the edge does for a viewer's browser.
func quotaHarness(t *testing.T) (*harness, *playback.Service) {
	t.Helper()
	var pb *playback.Service
	h := newHarnessWith(t, func(d *api.Deps, h *harness) {
		pb = d.Playback
		d.Quota = quota.NewService(h.pool, h.clk.Now)
		d.Limiter = quota.NewLimiter(db.New(h.pool), nil, h.clk.Now)
	})
	return h, pb
}

func (h *harness) putQuotas(key, path string, body map[string]any) resp {
	h.t.Helper()
	return h.mustOK(h.do(key, "PUT", path, body), 200)
}

// clientKey makes a client of the bootstrapped tenant with a key that may create sessions.
func (h *harness) clientKey(admin, name string) (clientID, key string) {
	h.t.Helper()
	clientID = h.newClient(admin, name)
	k := h.newKey(admin, clientID, name, []string{"sessions:write"})
	return clientID, str(k.m, "key")
}

func TestQuotasDefaultToUnlimited(t *testing.T) {
	h, _ := quotaHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)

	r := h.mustOK(h.do(key, "GET", "/v1/quotas", nil), 200)
	if len(r.m) != 0 {
		t.Fatalf("a tenant that set nothing has limits: %s", r.raw)
	}
	u := h.mustOK(h.do(key, "GET", "/v1/usage", nil), 200)
	for _, f := range []string{"storage_bytes", "transcode_milliseconds", "concurrent_sessions"} {
		if _, has := u.m[f].(map[string]any)["limit"]; has {
			t.Fatalf("%s has a limit by default: %s", f, u.raw)
		}
	}
	// With no limit, sessions and requests are never refused (the per-viewer limit aside).
	for i := range 40 {
		h.mustOK(h.createSession(key, asset.ID.String(), fmt.Sprintf("viewer-%d", i)), 201)
	}
}

func TestQuotaAdminEndpoints(t *testing.T) {
	h, _ := quotaHarness(t)
	admin, res := h.bootstrap("acme")
	otherAdmin, otherRes := h.bootstrap("other")
	cli, _ := h.clientKey(admin, "svc")
	otherCli := h.newClient(otherAdmin, "theirs")

	put := h.putQuotas(admin, "/v1/quotas", map[string]any{"storage_bytes": 5000, "concurrent_sessions": 4, "requests_per_minute": 600, "transcode_minutes_per_month": 90})
	if put.m["storage_bytes"] != 5000.0 || put.m["concurrent_sessions"] != 4.0 || put.m["requests_per_minute"] != 600.0 ||
		put.m["transcode_minutes_per_month"] != 90.0 || str(put.m, "updated_at") == "" {
		t.Fatalf("PUT = %s", put.raw)
	}
	got := h.mustOK(h.do(admin, "GET", "/v1/quotas", nil), 200)
	if string(got.raw) != string(put.raw) {
		t.Fatalf("GET %s != PUT %s", got.raw, put.raw)
	}
	// A PUT replaces: what is not sent is unlimited again.
	again := h.putQuotas(admin, "/v1/quotas", map[string]any{"concurrent_sessions": 2})
	if _, has := again.m["storage_bytes"]; has || again.m["concurrent_sessions"] != 2.0 {
		t.Fatalf("replace = %s", again.raw)
	}
	// Another tenant sees none of it.
	if o := h.mustOK(h.do(otherAdmin, "GET", "/v1/quotas", nil), 200); len(o.m) != 0 {
		t.Fatalf("another tenant's quotas = %s", o.raw)
	}

	// Validation: every present limit is at least 1.
	bad := h.do(admin, "PUT", "/v1/quotas", map[string]any{"storage_bytes": 0, "concurrent_sessions": -1, "requests_per_minute": 3000000000})
	h.wantStatus(bad, 400, "invalid_request")
	if f := fieldErrors(bad); len(f) != 3 {
		t.Fatalf("field errors = %v", f)
	}
	h.wantStatus(h.do(admin, "PUT", "/v1/quotas", nil), 400, "invalid_request")

	// Client overrides: lower only, and only for the tenant's own clients.
	co := h.putQuotas(admin, "/v1/clients/"+cli+"/quotas", map[string]any{"concurrent_sessions": 1})
	if str(co.m, "client_id") != cli || co.m["concurrent_sessions"] != 1.0 {
		t.Fatalf("client PUT = %s", co.raw)
	}
	h.wantStatus(h.do(admin, "PUT", "/v1/clients/"+cli+"/quotas", map[string]any{"concurrent_sessions": 3}), 400, "invalid_request")
	if r := h.do(admin, "GET", "/v1/clients/"+cli+"/quotas", nil); r.status != 200 || r.m["concurrent_sessions"] != 1.0 {
		t.Fatalf("client GET = %s", r.raw)
	}
	for _, path := range []string{"/v1/clients/" + otherCli + "/quotas", "/v1/clients/not-a-client/quotas", "/v1/usage?client_id=" + otherCli} {
		h.wantStatus(h.do(admin, "GET", path, nil), 404, "not_found")
	}
	h.wantStatus(h.do(admin, "PUT", "/v1/clients/"+otherCli+"/quotas", map[string]any{"concurrent_sessions": 1}), 404, "not_found")
	if q := h.mustOK(h.do(otherAdmin, "GET", "/v1/clients/"+otherCli+"/quotas", nil), 200); len(q.m) != 1 {
		t.Fatalf("the other tenant's untouched client has overrides: %s", q.raw)
	}

	// Admin only.
	_, sessionsKey := h.clientKey(admin, "svc2")
	for _, p := range [][2]string{{"GET", "/v1/quotas"}, {"PUT", "/v1/quotas"}, {"GET", "/v1/usage"}, {"GET", "/v1/clients/" + cli + "/quotas"}} {
		h.wantStatus(h.do(sessionsKey, p[0], p[1], map[string]any{}), 403, "forbidden")
	}

	// Each replacement is audited with the caller and no limit values.
	var n int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action IN ('quotas.update', 'client_quotas.update') AND client_id = $2",
		res.Tenant.ID.UUID(), res.Client.ID.UUID()).Scan(&n); err != nil || n != 3 {
		t.Fatalf("audit events = %d, %v; want 3", n, err)
	}
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action LIKE '%quotas%'", otherRes.Tenant.ID.UUID()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("another tenant has %d quota audit events", n)
	}
}

func TestConcurrentSessionQuotaJustUnderAtAndOver(t *testing.T) {
	h, _ := quotaHarness(t)
	admin, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	h.putQuotas(admin, "/v1/quotas", map[string]any{"concurrent_sessions": 3})

	var ids []string
	for i := range 3 { // under (1, 2) and at (3) the limit
		r := h.mustOK(h.createSession(admin, asset.ID.String(), "viewer-"+strconv.Itoa(i)), 201)
		ids = append(ids, str(r.m, "session_id"))
	}
	over := h.createSession(admin, asset.ID.String(), "viewer-3")
	h.wantStatus(over, 409, "quota_exceeded")
	if over.m["limit"] != "concurrent_sessions" || over.m["retryable"] != false {
		t.Fatalf("problem = %s", over.raw)
	}
	if over.status != 409 || len(over.raw) > 600 {
		t.Fatalf("problem is too chatty: %s", over.raw)
	}
	// A session that ends frees its place; the others stay.
	h.mustOK(h.do(admin, "POST", "/v1/playback-sessions/"+ids[0]+"/revoke", map[string]any{}), 200)
	h.mustOK(h.createSession(admin, asset.ID.String(), "viewer-3"), 201)
	h.wantStatus(h.createSession(admin, asset.ID.String(), "viewer-4"), 409, "quota_exceeded")

	// Sessions idle past the timeout stop counting (the limit counts active sessions only).
	h.clk.Advance(10 * time.Minute) // ten minutes: past the default 300 s idle timeout
	h.mustOK(h.createSession(admin, asset.ID.String(), "viewer-5"), 201)

	// Lowering the limit ends nothing and refuses new sessions.
	h.putQuotas(admin, "/v1/quotas", map[string]any{"concurrent_sessions": 1})
	h.wantStatus(h.createSession(admin, asset.ID.String(), "viewer-6"), 409, "quota_exceeded")
	u := h.mustOK(h.do(admin, "GET", "/v1/usage", nil), 200)
	if c := u.m["concurrent_sessions"].(map[string]any); c["used"] != 1.0 || c["limit"] != 1.0 {
		t.Fatalf("usage = %s", u.raw)
	}
}

func TestConcurrentSessionQuotaClientOverrideAndBrowserPaths(t *testing.T) {
	h, pb := quotaHarness(t)
	admin, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	cliA, keyA := h.clientKey(admin, "a")
	_, keyB := h.clientKey(admin, "b")
	h.putQuotas(admin, "/v1/quotas", map[string]any{"concurrent_sessions": 6})
	h.putQuotas(admin, "/v1/clients/"+cliA+"/quotas", map[string]any{"concurrent_sessions": 2})

	h.mustOK(h.createSession(keyA, asset.ID.String(), "a1"), 201)
	h.mustOK(h.createSession(keyA, asset.ID.String(), "a2"), 201)
	h.wantStatus(h.createSession(keyA, asset.ID.String(), "a3"), 409, "quota_exceeded") // the client's own, lower limit
	// Another client is not held back by it, up to the tenant's limit.
	h.mustOK(h.createSession(keyB, asset.ID.String(), "b1"), 201)
	h.mustOK(h.createSession(keyB, asset.ID.String(), "b2"), 201)

	// The viewer's browser (JWT and signed callback) starts sessions through the same service and
	// counts toward the tenant's limit, not the client's.
	for i, method := range []string{db.AuthMethodJWT, db.AuthMethodCallback} {
		_, err := pb.CreateSession(context.Background(), playback.CreateInput{
			TenantID: res.Tenant.ID, AuthMethod: method, AssetID: asset.ID, ViewerID: "browser-" + strconv.Itoa(i),
		})
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
	}
	// Six active sessions now: the tenant is full for every path.
	h.wantStatus(h.createSession(keyB, asset.ID.String(), "b3"), 409, "quota_exceeded")
	for _, method := range []string{db.AuthMethodJWT, db.AuthMethodCallback} {
		_, err := pb.CreateSession(context.Background(), playback.CreateInput{
			TenantID: res.Tenant.ID, AuthMethod: method, AssetID: asset.ID, ViewerID: "browser-x-" + method,
		})
		if err == nil || err.Error() == "" {
			t.Fatalf("%s: session created past the tenant's limit", method)
		}
	}
	ua := h.mustOK(h.do(admin, "GET", "/v1/usage?client_id="+cliA, nil), 200)
	if ua.m["client_id"] != cliA {
		t.Fatalf("usage = %s", ua.raw)
	}
	if c := ua.m["concurrent_sessions"].(map[string]any); c["used"] != 2.0 || c["limit"] != 2.0 {
		t.Fatalf("client usage = %s", ua.raw)
	}
	ut := h.mustOK(h.do(admin, "GET", "/v1/usage", nil), 200)
	if c := ut.m["concurrent_sessions"].(map[string]any); c["used"] != 6.0 || c["limit"] != 6.0 {
		t.Fatalf("tenant usage = %s", ut.raw)
	}
}

// Racing creations (different viewers, so the per-viewer lock does not serialise them) cannot pass
// the tenant's limit.
func TestConcurrentSessionQuotaRace(t *testing.T) {
	h, _ := quotaHarness(t)
	admin, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	h.putQuotas(admin, "/v1/quotas", map[string]any{"concurrent_sessions": 5})

	var ok, refused atomic.Int32
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch r := h.createSession(admin, asset.ID.String(), "racer-"+strconv.Itoa(i)); {
			case r.status == 201:
				ok.Add(1)
			case r.status == 409 && r.code() == "quota_exceeded":
				refused.Add(1)
			default:
				t.Errorf("status %d: %s", r.status, r.raw)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 5 || refused.Load() != 19 {
		t.Fatalf("%d sessions created and %d refused, want 5 and 19", ok.Load(), refused.Load())
	}
}

func TestUsageTenantIsolation(t *testing.T) {
	h, _ := quotaHarness(t)
	admin, res := h.bootstrap("acme")
	otherAdmin, otherRes := h.bootstrap("other")
	asset := h.newAsset(res, db.AssetReady) // 1000 bytes
	h.newAsset(otherRes, db.AssetReady)
	h.newAsset(otherRes, db.AssetReady)
	h.mustOK(h.createSession(admin, asset.ID.String(), "v"), 201)

	u := h.mustOK(h.do(admin, "GET", "/v1/usage", nil), 200)
	if s := u.m["storage_bytes"].(map[string]any); s["used"] != 1000.0 {
		t.Fatalf("storage = %s", u.raw)
	}
	if s := u.m["concurrent_sessions"].(map[string]any); s["used"] != 1.0 {
		t.Fatalf("sessions = %s", u.raw)
	}
	o := h.mustOK(h.do(otherAdmin, "GET", "/v1/usage", nil), 200)
	if s := o.m["storage_bytes"].(map[string]any); s["used"] != 2000.0 {
		t.Fatalf("other storage = %s", o.raw)
	}
	if s := o.m["concurrent_sessions"].(map[string]any); s["used"] != 0.0 {
		t.Fatalf("other sessions = %s", o.raw)
	}
	// A quota problem names the limit and never a figure.
	h.putQuotas(admin, "/v1/quotas", map[string]any{"concurrent_sessions": 1})
	r := h.createSession(admin, asset.ID.String(), "w")
	h.wantStatus(r, 409, "quota_exceeded")
	for k := range r.m {
		switch k {
		case "type", "title", "status", "detail", "code", "retryable", "request_id", "limit":
		default:
			t.Fatalf("unexpected member %q in %s", k, r.raw)
		}
	}
}

func TestRequestRateLimitPerKey(t *testing.T) {
	h, _ := quotaHarness(t)
	admin, _ := h.bootstrap("acme")
	otherAdmin, _ := h.bootstrap("other")
	cli := h.newClient(admin, "limited")
	limited := str(h.newKey(admin, cli, "k", nil).m, "key")
	h.putQuotas(admin, "/v1/clients/"+cli+"/quotas", map[string]any{"requests_per_minute": 3})
	// Nothing is limited at the tenant level, so only that client's keys are.
	for range 10 {
		h.mustOK(h.do(admin, "GET", "/v1/whoami", nil), 200)
	}
	for range 3 {
		h.mustOK(h.do(limited, "GET", "/v1/whoami", nil), 200)
	}
	r := h.do(limited, "GET", "/v1/whoami", nil)
	h.wantStatus(r, 429, "rate_limited")
	if ra, err := strconv.Atoi(r.hdr.Get("Retry-After")); err != nil || ra < 1 || ra > 60 {
		t.Fatalf("Retry-After = %q", r.hdr.Get("Retry-After"))
	}
	if r.hdr.Get("X-Request-Id") == "" || r.m["retryable"] != true || r.hdr.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("429 = %v %s", r.hdr, r.raw)
	}
	// A request that does not authenticate is answered 401, not counted and not limited.
	h.wantStatus(h.do("garbage", "GET", "/v1/whoami", nil), 401, "unauthenticated")
	// Time refills the bucket: 20 seconds per request at 3 a minute.
	h.clk.Advance(21 * time.Second)
	h.mustOK(h.do(limited, "GET", "/v1/whoami", nil), 200)
	h.wantStatus(h.do(limited, "GET", "/v1/whoami", nil), 429, "rate_limited")
	// Other tenants and clients are unaffected.
	for range 10 {
		h.mustOK(h.do(otherAdmin, "GET", "/v1/whoami", nil), 200)
	}
}
