//go:build integration

package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// failedAsset makes an asset that processing failed for a reason that was not the file's fault: its
// original is in the source bucket, and it carries what a failed run leaves on the row.
func (e *upEnv) failedAsset(maskFaces bool) db.Asset {
	e.t.Helper()
	ctx := context.Background()
	body := map[string]any{"size_bytes": 100, "upload_method": "multipart", "mask_faces": maskFaces}
	m, _ := e.call(e.admin, "POST", "/v1/assets", body, 201)
	a := e.dbAsset(m["asset"].(map[string]any)["id"].(string))
	if err := e.buckets.Source.Put(ctx, a.SourceKey, bytes.NewReader(make([]byte, 100)), 100, "video/mp4"); err != nil {
		e.t.Fatal(err)
	}
	for _, step := range [][2]db.AssetState{
		{db.AssetCreated, db.AssetUploading}, {db.AssetUploading, db.AssetCommitted}, {db.AssetCommitted, db.AssetProcessing},
	} {
		if _, err := e.repos.TransitionAsset(ctx, a.TenantID, a.ID, db.Transition{From: step[0], To: step[1]}); err != nil {
			e.t.Fatal(err)
		}
	}
	if _, err := e.repos.ChargeTranscode(ctx, a.TenantID, a.ID, time.Minute, time.Now().UTC()); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE assets SET progress = 40 WHERE id = $1::uuid`, a.ID.UUID()); err != nil {
		e.t.Fatal(err)
	}
	if maskFaces { // the masker noticed the failure
		if _, err := e.repos.SetAssetMasking(ctx, a.TenantID, a.ID, db.MaskingFailed, nil, time.Now().UTC()); err != nil {
			e.t.Fatal(err)
		}
	}
	if _, err := e.repos.TransitionAsset(ctx, a.TenantID, a.ID, db.Transition{From: db.AssetProcessing, To: db.AssetFailed, FailureCode: "processing_failed"}); err != nil {
		e.t.Fatal(err)
	}
	return e.dbAsset(a.ID.String())
}

func (e *upEnv) jobsFor(kind string, a db.Asset) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'asset_id' = $2`, kind, a.ID.String()).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *upEnv) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func problemCode(ex exchange) string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(ex.body, &p)
	return p.Code
}

// A failed asset with its original goes back to committed with a clean row, one process job (and a
// mask job for mask_faces) and an audit event naming the actor; the first run's transcode charge is
// taken back so the new run charges again.
func TestReprocessQueuesOneCleanRun(t *testing.T) {
	e := newUpEnv(t)
	for _, mask := range []bool{false, true} {
		a := e.failedAsset(mask)
		if a.State != db.AssetFailed || a.FailureCode == "" || a.FailedAt == nil {
			t.Fatalf("setup: %+v", a)
		}
		m, ex := e.call(e.admin, "POST", "/v1/assets/"+a.ID.String()+"/reprocess", nil, 202)
		if m["state"] != "committed" || m["failure_code"] != nil || m["failed_at"] != nil || ex.resp.Header.Get("X-Request-Id") == "" {
			t.Fatalf("response: %v", m)
		}
		cur := e.dbAsset(a.ID.String())
		if cur.State != db.AssetCommitted || cur.FailureCode != "" || cur.FailedAt != nil || cur.Progress != 0 ||
			len(cur.ExtraCodecFailures) != 0 || cur.MaskingState != "" || cur.CommittedAt == nil {
			t.Fatalf("row after reprocess: %+v", cur)
		}
		if n := e.jobsFor("asset.process", a); n != 1 {
			t.Fatalf("mask=%v: %d process jobs, want 1", mask, n)
		}
		wantMask := 0
		if mask {
			wantMask = 1
		}
		if n := e.jobsFor("asset.mask", a); n != wantMask {
			t.Fatalf("mask=%v: %d mask jobs, want %d", mask, n, wantMask)
		}
		if n := e.count(`SELECT count(*) FROM transcode_charges WHERE asset_id = $1::uuid`, a.ID.UUID()); n != 0 {
			t.Fatalf("the failed run's charge is still there")
		}
		if n := e.count(`SELECT count(*) FROM audit_events WHERE action = 'asset.reprocess_requested' AND target = $1 AND client_id = $2::uuid`,
			a.ID.String(), e.clientID.UUID()); n != 1 {
			t.Fatalf("%d audit events with the actor, want 1", n)
		}
		// The asset is committed now, so asking again is refused and starts nothing.
		_, ex = e.call(e.admin, "POST", "/v1/assets/"+a.ID.String()+"/reprocess", nil, 409)
		if problemCode(ex) != "asset_not_failed" || e.jobsFor("asset.process", a) != 1 {
			t.Fatalf("second call: %s", ex.body)
		}
	}
}

// Anything but a failed asset is asset_not_failed; a deleted one is not_found.
func TestReprocessRefusesAssetsThatHaveNotFailed(t *testing.T) {
	e := newUpEnv(t)
	ctx := context.Background()
	deleting := e.failedAsset(false)
	// A ready asset: build one the way the pipeline does, on a fresh asset.
	a := e.failedAsset(false)
	if _, err := e.pool.Exec(ctx, `UPDATE assets SET state = 'processing', failed_at = NULL, failure_code = NULL WHERE id = $1::uuid`, a.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repos.CompleteProcessing(ctx, a.TenantID, a.ID, db.Completion{Duration: time.Second, Renditions: []byte("[]")}); err != nil {
		t.Fatal(err)
	}
	_, ex := e.call(e.admin, "POST", "/v1/assets/"+a.ID.String()+"/reprocess", nil, 409)
	if problemCode(ex) != "asset_not_failed" {
		t.Fatalf("ready asset: %s", ex.body)
	}
	if got := e.dbAsset(a.ID.String()).State; got != db.AssetReady {
		t.Fatalf("state after the refusal = %s", got)
	}
	// Created, uploading and committed assets are refused too.
	created := e.create(e.admin, 100, "multipart")
	_, ex = e.call(e.admin, "POST", "/v1/assets/"+created.assetID+"/reprocess", nil, 409)
	if problemCode(ex) != "asset_not_failed" {
		t.Fatalf("created asset: %s", ex.body)
	}
	// Deleting is a conflict, a missing or foreign asset is not_found.
	if _, err := e.repos.RequestAssetDeletion(ctx, deleting.TenantID, deleting.ID, db.DeletionRequested, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	_, ex = e.call(e.admin, "POST", "/v1/assets/"+deleting.ID.String()+"/reprocess", nil, 409)
	if problemCode(ex) != "conflict" {
		t.Fatalf("deleting asset: %s", ex.body)
	}
	_, ex = e.call(e.admin, "POST", "/v1/assets/"+id.New[id.AssetKind]().String()+"/reprocess", nil, 404)
	if problemCode(ex) != "not_found" {
		t.Fatalf("unknown asset: %s", ex.body)
	}
	if n := e.count(`SELECT count(*) FROM river_job WHERE kind = 'asset.process'`); n != 0 {
		t.Fatalf("%d process jobs after refusals, want 0", n)
	}
}

// With the original gone there is nothing to run again: dropped by keep_source, missing from the
// bucket although the row does not say so, or never complete (aborted).
func TestReprocessNeedsTheOriginal(t *testing.T) {
	e := newUpEnv(t)
	ctx := context.Background()

	// keep_source was off (H-3): the drop job removed the original and recorded it.
	dropped := e.failedAsset(false)
	if err := e.buckets.Source.DeleteBatch(ctx, []string{dropped.SourceKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE assets SET keep_source = false, source_deleted_at = now() WHERE id = $1::uuid`, dropped.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	// The column says nothing: the object is simply missing.
	missing := e.failedAsset(false)
	if err := e.buckets.Source.DeleteBatch(ctx, []string{missing.SourceKey}); err != nil {
		t.Fatal(err)
	}
	// An aborted upload.
	up := e.create(e.admin, 100, "multipart")
	e.call(e.admin, "POST", "/v1/assets/"+up.assetID+"/abort", nil, 200)

	for name, a := range map[string]string{"dropped": dropped.ID.String(), "missing object": missing.ID.String(), "aborted": up.assetID} {
		_, ex := e.call(e.admin, "POST", "/v1/assets/"+a+"/reprocess", nil, 409)
		if problemCode(ex) != "source_unavailable" {
			t.Errorf("%s: %s", name, ex.body)
		}
		if got := e.dbAsset(a).State; got != db.AssetFailed {
			t.Errorf("%s: state %s after the refusal, want failed", name, got)
		}
	}
	if n := e.count(`SELECT count(*) FROM river_job WHERE kind IN ('asset.process', 'asset.mask')`); n != 0 {
		t.Fatalf("%d jobs queued by refused requests", n)
	}
}

// Two calls at the same moment start exactly one run.
func TestReprocessConcurrentCallsStartOneRun(t *testing.T) {
	e := newUpEnv(t)
	a := e.failedAsset(true)
	const callers = 8
	statuses := make([]int, callers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := e.newReq(http.MethodPost, e.apiSrv.URL, "/v1/assets/"+a.ID.String()+"/reprocess", map[string]string{"Authorization": "Bearer " + e.admin}, nil)
			<-start
			resp, err := e.client.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()
			statuses[i] = resp.StatusCode
		}()
	}
	close(start)
	wg.Wait()
	accepted, refused := 0, 0
	for _, s := range statuses {
		switch s {
		case http.StatusAccepted:
			accepted++
		case http.StatusConflict:
			refused++
		default:
			t.Errorf("unexpected status %d", s)
		}
	}
	if accepted != 1 || refused != callers-1 {
		t.Fatalf("%d accepted and %d refused, want 1 and %d (%v)", accepted, refused, callers-1, statuses)
	}
	if p, m := e.jobsFor("asset.process", a), e.jobsFor("asset.mask", a); p != 1 || m != 1 {
		t.Fatalf("%d process and %d mask jobs, want 1 and 1", p, m)
	}
	if n := e.count(`SELECT count(*) FROM audit_events WHERE action = 'asset.reprocess_requested' AND target = $1`, a.ID.String()); n != 1 {
		t.Fatalf("%d audit events, want 1", n)
	}
}
