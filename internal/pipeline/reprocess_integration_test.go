//go:build integration && media

package pipeline_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// An asset that failed because its source could not be read (an outage; here the object is missing for
// a moment) is moved back to committed by the reprocess request and then reaches ready with real
// FFmpeg, a complete registry and a manifest, under a content key made once.
func TestPipelineReprocessAfterFailureReachesReady(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	src := generate(t, testmedia.Spec{Name: "small.mp4", Width: 320, Height: 180, Duration: 5 * time.Second, FPS: 25})
	asset, _ := r.commit(src)
	data, err := os.ReadFile(src) //nolint:gosec // a fixture the test just generated
	if err != nil {
		t.Fatal(err)
	}
	if err := r.buckets.Source.DeleteBatch(ctx, []string{asset.SourceKey}); err != nil {
		t.Fatal(err)
	}
	if err := r.process(asset); err == nil {
		t.Fatal("processed an asset without its source")
	}
	failed, err := r.repos.GetAsset(ctx, asset.TenantID, asset.ID)
	if err != nil || failed.State != db.AssetFailed || failed.FailureCode != pipeline.FailureSourceMissing {
		t.Fatalf("asset = %s/%s (%v)", failed.State, failed.FailureCode, err)
	}

	// The outage ends: the object is back and the reprocess request runs.
	if err := r.buckets.Source.Put(ctx, asset.SourceKey, bytes.NewReader(data), int64(len(data)), "video/mp4"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.repos.RequeueFailedAsset(ctx, asset.TenantID, asset.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := r.process(asset); err != nil {
		t.Fatalf("asset.process after the reprocess: %v\n%s", err, r.logs.String())
	}
	a, err := r.repos.GetAsset(ctx, asset.TenantID, asset.ID)
	if err != nil || a.State != db.AssetReady || a.FailureCode != "" || a.FailedAt != nil {
		t.Fatalf("asset = %s/%s (%v)", a.State, a.FailureCode, err)
	}
	if _, err := r.repos.GetManifest(ctx, asset.ID); err != nil {
		t.Fatalf("no manifest after the reprocess: %v", err)
	}
	if got := r.get(r.buckets.Delivery, keys.Master(a.TenantID, a.ID)); len(got) == 0 {
		t.Fatal("no master playlist")
	}
	if es, _ := os.ReadDir(r.workDir); len(es) != 0 {
		t.Errorf("work directory not empty: %v", es)
	}
}
