//go:build integration

package contract

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// createWanting// refusal.
func (e *upEnv) createWanting(key string, size int64, want int) map[string]any {
	e.t.Helper()
	m, _ := e.call(key, "POST", "/v1/assets", map[string]any{"size_bytes": size, "upload_method": "multipart", "content_type": "video/mp4"}, want)
	return m
}

func usedAndLimit(t *testing.T, m map[string]any, field string) (used, limit float64, hasLimit bool) {
	t.Helper()
	c, _ := m[field].(map[string]any)
	used, _ = c["used"].(float64)
	limit, hasLimit = c["limit"].(float64)
	return
}

// TestStorageQuotaThroughTheUploadAPI runs the quota endpoints and the storage checks at asset
// creation and commit through the real listeners, validating every exchange against the spec.
func TestStorageQuotaThroughTheUploadAPI(t *testing.T) {
	e := newUpEnv(t)
	key := e.admin

	// Nothing is limited until a limit is set.
	if m, _ := e.call(key, "GET", "/v1/quotas", nil, 200); len(m) != 0 {
		t.Fatalf("default quotas = %v", m)
	}
	e.create(key, 5000, "multipart")
	u, _ := e.call(key, "GET", "/v1/usage", nil, 200)
	if used, _, has := usedAndLimit(t, u, "storage_bytes"); used != 5000 || has {
		t.Fatalf("usage with no limit = %v", u)
	}

	// A fresh tenant: 1000 bytes. Just under, at and over at creation.
	other := e.newTenant("storage")
	e.call(other, "PUT", "/v1/quotas", map[string]any{"storage_bytes": 1000}, 200)
	first := e.create(other, 599, "multipart")
	second := e.create(other, 401, "multipart") // exactly 1000
	over := e.createWanting(other, 1, 409)
	if over["code"] != "quota_exceeded" || over["limit"] != "storage_bytes" || over["retryable"] != false {
		t.Fatalf("problem = %v", over)
	}
	u, _ = e.call(other, "GET", "/v1/usage", nil, 200)
	if used, limit, has := usedAndLimit(t, u, "storage_bytes"); used != 1000 || limit != 1000 || !has {
		t.Fatalf("usage = %v", u)
	}
	// The refused request made no asset, and the first tenant's usage is its own.
	if used, _, _ := usedAndLimit(t, mustCall(e, key, "/v1/usage"), "storage_bytes"); used != 5000 {
		t.Fatalf("another tenant's usage leaked: %d", int(used))
	}

	// Aborting an upload gives its room back (its source objects are removed).
	e.call(other, "POST", "/v1/assets/"+first.assetID+"/abort", nil, 200)
	e.create(other, 599, "multipart")
	e.createWanting(other, 1, 409)

	// Commit checks again, with the verified size, under the same lock: a limit lowered since
	// creation refuses the commit and leaves the asset uploading, and committing again after room
	// was made works.
	e.putPart(second, 1, make([]byte, 401), 200)
	e.call(other, "PUT", "/v1/quotas", map[string]any{"storage_bytes": 900}, 200)
	refused, _ := e.call(other, "POST", "/v1/assets/"+second.assetID+"/commit", nil, 409)
	if refused["code"] != "quota_exceeded" || refused["limit"] != "storage_bytes" {
		t.Fatalf("commit problem = %v", refused)
	}
	e.assertState(other, second.assetID, "uploading")
	e.call(other, "PUT", "/v1/quotas", map[string]any{"storage_bytes": 1000}, 200)
	e.call(other, "POST", "/v1/assets/"+second.assetID+"/commit", nil, 200)
	e.assertState(other, second.assetID, "committed")
}

func mustCall(e *upEnv, key, path string) map[string]any {
	e.t.Helper()
	m, _ := e.call(key, "GET", path, nil, 200)
	return m
}

func TestStorageQuotaClientOverrideAndRace(t *testing.T) {
	e := newUpEnv(t)
	admin := e.newTenant("clients")
	cli, _ := e.call(admin, "POST", "/v1/clients", map[string]any{"name": "small"}, 201)
	small, _ := e.call(admin, "POST", "/v1/keys", map[string]any{"client_id": cli["id"], "name": "small"}, 201)
	smallKey := small["key"].(string)

	e.call(admin, "PUT", "/v1/quotas", map[string]any{"storage_bytes": 10000}, 200)
	over, _ := e.call(admin, "PUT", "/v1/clients/"+cli["id"].(string)+"/quotas", map[string]any{"storage_bytes": 20000}, 400)
	if over["code"] != "invalid_request" {
		t.Fatalf("override above the tenant: %v", over)
	}
	got, _ := e.call(admin, "PUT", "/v1/clients/"+cli["id"].(string)+"/quotas", map[string]any{"storage_bytes": 500}, 200)
	if got["client_id"] != cli["id"] || got["storage_bytes"] != 500.0 {
		t.Fatalf("client quotas = %v", got)
	}
	if g, _ := e.call(admin, "GET", "/v1/clients/"+cli["id"].(string)+"/quotas", nil, 200); g["storage_bytes"] != 500.0 {
		t.Fatalf("client quotas GET = %v", g)
	}

	// The small client is held to its own, lower, limit; the tenant's admin client is not.
	e.create(smallKey, 500, "multipart")
	e.createWanting(smallKey, 1, 409)
	e.create(admin, 5000, "multipart")
	cu, _ := e.call(admin, "GET", "/v1/usage?client_id="+cli["id"].(string), nil, 200)
	if used, limit, has := usedAndLimit(t, cu, "storage_bytes"); used != 500 || limit != 500 || !has || cu["client_id"] != cli["id"] {
		t.Fatalf("client usage = %v", cu)
	}

	// Racing creations cannot pass the check on the same room: 3 of 12 fit in 1000 bytes.
	racing := e.newTenant("racing")
	e.call(racing, "PUT", "/v1/quotas", map[string]any{"storage_bytes": 1000}, 200)
	var ok, refused atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := e.newReq("POST", e.apiSrv.URL, "/v1/assets", map[string]string{"Authorization": "Bearer " + racing, "Content-Type": "application/json"},
				[]byte(`{"size_bytes":300,"upload_method":"multipart"}`))
			resp, err := e.client.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case 201:
				ok.Add(1)
			case 409:
				refused.Add(1)
			default:
				t.Errorf("status %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 3 || refused.Load() != 9 {
		t.Fatalf("%d creations passed and %d refused, want 3 and 9", ok.Load(), refused.Load())
	}
}

// The 429 of the request rate limit matches the spec, including its Retry-After header.
func TestRateLimitedMatchesSpec(t *testing.T) {
	e := newUpEnv(t)
	admin := e.newTenant("rate")
	e.call(admin, "PUT", "/v1/quotas", map[string]any{"requests_per_minute": 2}, 200)
	e.clk.Advance(16 * time.Second)              // a key reads its limit at most every 15 seconds
	e.call(admin, "GET", "/v1/quotas", nil, 200) // loads the limit and takes the first token
	e.call(admin, "GET", "/v1/quotas", nil, 200)
	m, ex := e.call(admin, "GET", "/v1/quotas", nil, 429)
	if m["code"] != "rate_limited" || m["retryable"] != true {
		t.Fatalf("problem = %v", m)
	}
	if n, err := strconv.Atoi(ex.resp.Header.Get("Retry-After")); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q", ex.resp.Header.Get("Retry-After"))
	}
	// Another tenant has its own bucket.
	other := e.newTenant("rate-other")
	e.call(other, "GET", "/v1/quotas", nil, 200)
}
