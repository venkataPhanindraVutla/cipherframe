//go:build integration

package api_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/deletion"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
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

	// No record before the deletion is done: not_deleted for a live or deleting asset, not_found
	// for another tenant's, and the scope is assets:read.
	h.wantStatus(h.do(reader, "GET", path+"/deletion-record", nil), 404, "not_deleted")
	h.wantStatus(h.do(otherAdmin, "GET", path+"/deletion-record", nil), 404, "not_found")
	h.wantStatus(h.do("", "GET", path+"/deletion-record", nil), 401, "unauthenticated")

	// Once the purge completed (its record stored with the tombstone), the same call answers with
	// the tombstone and queues nothing.
	built, err := deletion.Build(deletion.Input{
		AssetID: a.ID.String(), TenantID: a.TenantID.String(), RequestedAt: time.Now().Add(-time.Minute), CompletedAt: time.Now(),
		Reason: deletion.ReasonRequested, PipelineVersion: "v0.0.0-test",
		Objects: []deletion.ObjectCount{{Bucket: "delivery", Kind: "segment", Variant: "original", Count: 3, Bytes: 30}},
		Keys:    []deletion.KeyRef{{ID: "cky_00000000000000000000000001", Variant: "original"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	keyID, sig, err := h.signing.Sign(context.Background(), dsse.PAE(deletion.PayloadType, built.Canonical))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := (&dsse.Envelope{PayloadType: deletion.PayloadType, Payload: built.Canonical, Signatures: []dsse.Signature{{KeyID: keyID, Sig: sig}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(built.Canonical)
	if err := h.repos.InsertDeletionRecord(context.Background(), db.DeletionRecord{
		AssetID: a.ID, TenantID: a.TenantID, Reason: db.DeletionRequested, RequestedAt: time.Now().Add(-time.Minute), CompletedAt: time.Now(),
		KeyID: keyID, PayloadSHA256: sum[:], Envelope: envelope,
	}); err != nil {
		t.Fatal(err)
	}
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

	// The record is served as stored, with its own media type, and verifies with the public keys.
	rec := h.do(reader, "GET", path+"/deletion-record", nil)
	if rec.status != 200 || rec.hdr.Get("Content-Type") != "application/vnd.cipherframe.deletion+json; profile=dsse" {
		t.Fatalf("record: status %d, type %q: %s", rec.status, rec.hdr.Get("Content-Type"), rec.raw)
	}
	pub, err := h.signing.PublicKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keySet := offline.KeySet{}
	for _, k := range pub {
		keySet[k.KeyID] = k.PublicKey
	}
	signed, err := offline.OpenDeletion(rec.raw, keySet)
	if err != nil || signed.Record.AssetID != a.ID.String() || signed.Record.ObjectsDeleted != 3 {
		t.Fatalf("served record: %+v, %v", signed, err)
	}
	h.wantStatus(h.do(otherAdmin, "GET", path+"/deletion-record", nil), 404, "not_found")
}
