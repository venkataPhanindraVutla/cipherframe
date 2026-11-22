//go:build integration

package api_test

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuditEventsExport(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	_, rival := h.bootstrap("rival")
	cid := h.newClient(admin, "reader")
	reader := str(h.newKey(admin, cid, "reader", []string{"assets:read"}).m, "key")
	h.wantStatus(h.do(reader, "GET", "/v1/audit-events", nil), 403, "forbidden")

	all := h.mustOK(h.do(admin, "GET", "/v1/audit-events", nil), 200)
	items := all.m["items"].([]any)
	if len(items) < 3 || all.m["next_cursor"] != nil {
		t.Fatalf("export = %s", all.raw)
	}

	// Page by one, following the cursor: the same rows in the same order, nothing repeated.
	var ids []string
	path := "/v1/audit-events?limit=1"
	for pages := 0; pages < 50; pages++ {
		p := h.mustOK(h.do(admin, "GET", path, nil), 200)
		got := p.m["items"].([]any)
		if len(got) != 1 {
			t.Fatalf("page = %s", p.raw)
		}
		ids = append(ids, got[0].(map[string]any)["id"].(string))
		next, ok := p.m["next_cursor"].(string)
		if !ok {
			break
		}
		path = "/v1/audit-events?limit=1&after=" + url.QueryEscape(next)
	}
	if len(ids) != len(items) {
		t.Fatalf("paged %d rows, want %d", len(ids), len(items))
	}
	for i, it := range items {
		if it.(map[string]any)["id"] != ids[i] {
			t.Fatalf("row %d differs between paged and whole export", i)
		}
	}

	// Time range: since inclusive, until exclusive.
	last := items[len(items)-1].(map[string]any)["created_at"].(string)
	if _, err := time.Parse(time.RFC3339Nano, last); err != nil {
		t.Fatal(err)
	}
	r := h.mustOK(h.do(admin, "GET", "/v1/audit-events?since="+url.QueryEscape(last), nil), 200)
	if n := len(r.m["items"].([]any)); n < 1 || n > len(items) {
		t.Fatalf("since returned %d rows", n)
	}
	r = h.mustOK(h.do(admin, "GET", "/v1/audit-events?until=2000-01-01T00:00:00Z", nil), 200)
	if len(r.m["items"].([]any)) != 0 {
		t.Fatalf("until in the past returned rows: %s", r.raw)
	}

	// Tenants never see each other's rows.
	if strings.Contains(string(all.raw), rival.Tenant.ID.String()) {
		t.Fatal("export leaks another tenant")
	}
	for _, q := range []string{"limit=0", "limit=501", "after=garbage", "since=yesterday", "since=2030-01-02T00:00:00Z&until=2030-01-01T00:00:00Z"} {
		h.wantStatus(h.do(admin, "GET", "/v1/audit-events?"+q, nil), 400, "invalid_request")
	}
}
