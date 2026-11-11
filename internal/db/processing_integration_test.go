//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func processingAsset(t *testing.T, r *db.Repos, f fixture) db.Asset {
	t.Helper()
	ctx := context.Background()
	a := newUploadAsset(t, r, f, db.UploadMultipart)
	for _, step := range [][2]db.AssetState{
		{db.AssetCreated, db.AssetUploading}, {db.AssetUploading, db.AssetCommitted}, {db.AssetCommitted, db.AssetProcessing},
	} {
		var err error
		if a, err = r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: step[0], To: step[1]}); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func TestRecordSourceAndProgressOnlyWhileProcessing(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	fresh := newUploadAsset(t, r, f, db.UploadMultipart)
	sum := sha256.Sum256([]byte("source"))

	// Not processing yet: the compare-and-set refuses.
	if err := r.RecordSource(ctx, f.tenant.ID, fresh.ID, sum[:], 1234); !errors.Is(err, db.ErrStateChanged) {
		t.Fatalf("RecordSource on a created asset: %v", err)
	}

	a := processingAsset(t, r, f)
	if err := r.RecordSource(ctx, f.tenant.ID, a.ID, sum[:], 1234); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetAsset(ctx, f.tenant.ID, a.ID)
	if err != nil || !bytes.Equal(got.SourceSHA256, sum[:]) || got.SourceSizeBytes != 1234 {
		t.Fatalf("after RecordSource: %+v, %v", got, err)
	}
	// Another tenant cannot write it.
	other := newFixture(t, r, "other")
	if err := r.RecordSource(ctx, other.tenant.ID, a.ID, sum[:], 1); !errors.Is(err, db.ErrStateChanged) {
		t.Fatalf("RecordSource across tenants: %v", err)
	}
	// Bad input never reaches the database.
	if r.RecordSource(ctx, f.tenant.ID, a.ID, sum[:5], 1) == nil || r.RecordSource(ctx, f.tenant.ID, a.ID, sum[:], 0) == nil {
		t.Fatal("accepted a bad hash or size")
	}

	// Progress moves forward only, and a reset starts over.
	for _, p := range []int{10, 40, 30} {
		if err := r.SetProgress(ctx, f.tenant.ID, a.ID, p); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := r.GetAsset(ctx, f.tenant.ID, a.ID); got.Progress != 40 {
		t.Fatalf("progress = %d, want 40 (never backwards)", got.Progress)
	}
	if err := r.ResetProgress(ctx, f.tenant.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.GetAsset(ctx, f.tenant.ID, a.ID); got.Progress != 0 {
		t.Fatalf("progress after reset = %d", got.Progress)
	}
	if r.SetProgress(ctx, f.tenant.ID, a.ID, 101) == nil || r.SetProgress(ctx, f.tenant.ID, a.ID, -1) == nil {
		t.Fatal("accepted an out-of-range progress")
	}
	// Writes to an asset that is not processing are ignored, not errors.
	if err := r.SetProgress(ctx, f.tenant.ID, fresh.ID, 50); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.GetAsset(ctx, f.tenant.ID, fresh.ID); got.Progress != 0 {
		t.Fatalf("progress of a created asset = %d", got.Progress)
	}
}

func artifact(a db.Asset, kind db.ArtifactKind, rendition, key string) db.Artifact {
	sum := sha256.Sum256([]byte(key))
	return db.Artifact{AssetID: a.ID, Kind: kind, Rendition: rendition, Bucket: "delivery", ObjectKey: key, SizeBytes: 10, SHA256: sum[:]}
}

func TestCompleteProcessingAndArtifacts(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := processingAsset(t, r, f)

	for _, art := range []db.Artifact{
		artifact(a, db.ArtifactMaster, "", "hls/master.m3u8"),
		artifact(a, db.ArtifactPlaylist, "720p", "hls/720p/playlist.m3u8"),
		artifact(a, db.ArtifactInit, "720p", "hls/720p/init.mp4"),
		artifact(a, db.ArtifactSegment, "720p", "hls/720p/seg-0.m4s"),
		artifact(a, db.ArtifactPoster, "", "poster.jpg"),
	} {
		if err := r.RecordArtifact(ctx, art); err != nil {
			t.Fatalf("%s: %v", art.ObjectKey, err)
		}
	}
	// Registering again replaces; it does not duplicate.
	again := artifact(a, db.ArtifactSegment, "720p", "hls/720p/seg-0.m4s")
	again.SizeBytes = 99
	if err := r.RecordArtifact(ctx, again); err != nil {
		t.Fatal(err)
	}
	list, err := r.ListArtifacts(ctx, a.ID)
	if err != nil || len(list) != 5 {
		t.Fatalf("ListArtifacts = %d, %v", len(list), err)
	}
	for _, x := range list {
		if x.ObjectKey == "hls/720p/seg-0.m4s" && (x.SizeBytes != 99 || x.Kind != db.ArtifactSegment || x.Rendition != "720p" || x.Bucket != "delivery") {
			t.Errorf("re-registered artifact: %+v", x)
		}
		if x.ObjectKey == "hls/master.m3u8" && x.Rendition != "" {
			t.Errorf("master has a rendition: %+v", x)
		}
	}

	// An object key that belongs to another asset is never taken over.
	other := processingAsset(t, r, f)
	steal := artifact(other, db.ArtifactSegment, "720p", "hls/720p/seg-0.m4s")
	if err := r.RecordArtifact(ctx, steal); err != nil {
		t.Fatal(err)
	}
	if list, _ := r.ListArtifacts(ctx, other.ID); len(list) != 0 {
		t.Fatalf("another asset took over an object: %+v", list)
	}
	// Invalid artifacts are refused before the database.
	bad := artifact(a, "video", "720p", "k")
	if r.RecordArtifact(ctx, bad) == nil {
		t.Error("accepted an unknown kind")
	}
	bad = artifact(a, db.ArtifactSegment, "720p", "k")
	bad.Bucket = "elsewhere"
	if r.RecordArtifact(ctx, bad) == nil {
		t.Error("accepted an unknown bucket")
	}
	bad = artifact(a, db.ArtifactSegment, "720p", "k")
	bad.SHA256 = bad.SHA256[:3]
	if r.RecordArtifact(ctx, bad) == nil {
		t.Error("accepted a short hash")
	}

	// Deleting the HLS artifacts keeps the poster.
	n, err := r.DeleteHLSArtifacts(ctx, a.ID)
	if err != nil || n != 4 {
		t.Fatalf("DeleteHLSArtifacts = %d, %v", n, err)
	}
	if list, _ := r.ListArtifacts(ctx, a.ID); len(list) != 1 || list[0].Kind != db.ArtifactPoster {
		t.Fatalf("after DeleteHLSArtifacts: %+v", list)
	}

	// Completion is a compare-and-set processing -> ready.
	summary, _ := json.Marshal([]map[string]any{{"name": "720p"}})
	done, err := r.CompleteProcessing(ctx, f.tenant.ID, a.ID, db.Completion{Duration: 20 * time.Second, Renditions: summary})
	if err != nil || done.State != db.AssetReady || done.DurationMS != 20000 || done.Progress != 100 || done.ReadyAt == nil {
		t.Fatalf("CompleteProcessing = %+v, %v", done, err)
	}
	var back []map[string]any
	if err := json.Unmarshal(done.Renditions, &back); err != nil || back[0]["name"] != "720p" {
		t.Fatalf("renditions = %s, %v", done.Renditions, err)
	}
	if _, err := r.CompleteProcessing(ctx, f.tenant.ID, a.ID, db.Completion{Duration: time.Second, Renditions: summary}); !errors.Is(err, db.ErrStateChanged) {
		t.Fatalf("second CompleteProcessing: %v", err)
	}
	if _, err := r.CompleteProcessing(ctx, f.tenant.ID, other.ID, db.Completion{Duration: 0, Renditions: summary}); err == nil {
		t.Fatal("accepted a zero duration")
	}
	// A different tenant cannot complete it.
	o := newFixture(t, r, "o2")
	if _, err := r.CompleteProcessing(ctx, o.tenant.ID, other.ID, db.Completion{Duration: time.Second, Renditions: summary}); !errors.Is(err, db.ErrStateChanged) {
		t.Fatalf("cross-tenant CompleteProcessing: %v", err)
	}
}

func TestArtifactsReferenceAnAsset(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := processingAsset(t, r, f)
	ghost := artifact(a, db.ArtifactSegment, "720p", "k")
	ghost.AssetID = id.New[id.AssetKind]()
	err := r.RecordArtifact(ctx, ghost)
	if err == nil {
		t.Fatal("registered an artifact for an asset that does not exist")
	}
	var e *errs.Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not an *errs.Error", err)
	}
}
