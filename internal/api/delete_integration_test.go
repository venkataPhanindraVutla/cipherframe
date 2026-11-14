//go:build integration

package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

func (h *harness) purgeJobs() int {
	h.t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM river_job WHERE kind = 'asset.delete'`).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestDeleteAssetEndpoint(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")
	otherAdmin, _ := h.bootstrap("other")
	a, _ := h.readyAssetWithManifest(res, false)
	path := "/v1/assets/" + a.ID.String()

	// Scopes: assets:write deletes, assets:read does not; no key at all is 401.
	reader := str(h.newKey(admin, res.Client.ID.String(), "reader", []string{"assets:read"}).m, "key")
	h.wantStatus(h.do(reader, "DELETE", path, nil), 403, "forbidden")
	h.wantStatus(h.do("", "DELETE", path, nil), 401, "unauthenticated")
	// Another tenant cannot delete it and cannot tell it exists.
	h.wantStatus(h.do(otherAdmin, "DELETE", path, nil), 404, "not_found")
	h.wantStatus(h.do(admin, "DELETE", "/v1/assets/ast_00000000000000000000000000", nil), 404, "not_found")
	if got, _ := h.repos.GetAsset(context.Background(), a.TenantID, a.ID); got.State != db.AssetReady {
		t.Fatalf("a refused request changed the asset: %s", got.State)
	}

	r := h.mustOK(h.do(admin, "DELETE", path, nil), 202)
	d, _ := r.m["deletion"].(map[string]any)
	if r.m["state"] != "deleting" || d["reason"] != "requested" || d["requested_at"] == nil || d["completed_at"] != nil {
		t.Fatalf("response = %s", r.raw)
	}
	// The manifest refuses a deleting asset (GET /v1/assets/{id} is covered with storage in the
	// contract tests).
	h.wantStatus(h.do(reader, "GET", path+"/manifest", nil), 404, "not_found")
	// Idempotent: the same answer, and still one job.
	if again := h.mustOK(h.do(admin, "DELETE", path, nil), 202); again.m["state"] != "deleting" {
		t.Fatalf("second DELETE = %s", again.raw)
	}
	if n := h.purgeJobs(); n != 1 {
		t.Fatalf("%d purge jobs, want 1", n)
	}
	events, _ := h.repos.ListAuditEvents(context.Background(), res.Tenant.ID, nil, 50)
	deletes := 0
	for _, e := range events {
		if e.Action == "asset.delete" && e.Target == a.ID.String() {
			deletes++
		}
	}
	if deletes != 1 {
		t.Fatalf("%d asset.delete audit events, want 1", deletes)
	}

	// Once the purge completed, the same call answers with the tombstone and queues nothing.
	if _, err := h.repos.CompleteAssetDeletion(context.Background(), a.TenantID, a.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	again := h.mustOK(h.do(admin, "DELETE", path, nil), 202)
	d, _ = again.m["deletion"].(map[string]any)
	if again.m["state"] != "deleted" || d["completed_at"] == nil {
		t.Fatalf("DELETE of a tombstone = %s", again.raw)
	}
	if n := h.purgeJobs(); n != 1 {
		t.Fatalf("%d purge jobs after deleting a tombstone, want 1", n)
	}
}
