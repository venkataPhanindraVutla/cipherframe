//go:build integration

package purge_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// The drop-source tests (H-3) use the purge rig: a real database and object store, the real
// repository and the real asset.drop_source handler, and no FFmpeg.

// dropper is the processor that runs asset.drop_source, over a repository that queues it.
func (r *rig) dropper() (*pipeline.Processor, *pipeline.DBRepo) {
	r.t.Helper()
	repo := pipeline.NewDBRepo(r.pool).WithQueue(r.queue)
	p, err := pipeline.NewProcessor(pipeline.Deps{
		Repo: repo, Source: r.buckets.Source, Delivery: r.buckets.Delivery,
		Keys: pipeline.ContentKeys{Pool: r.pool, Manager: r.mgr}, Tools: media.Tools{}, Signer: r.signer,
		WorkDir: r.t.TempDir(), TranscodeTimeout: time.Minute, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return p, repo
}

// processing makes an asset that is being processed, with its original and tus's .info object in the
// source bucket. drop is the tenant's setting as it was at creation.
func (r *rig) processing(drop, maskFaces bool) (db.Asset, []string) {
	r.t.Helper()
	ctx := context.Background()
	aid := id.New[id.AssetKind]()
	src := keys.NewSource(r.tenant.ID, aid)
	if _, err := r.repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: aid, TenantID: r.tenant.ID, ClientID: r.client.ID, SizeBytes: 9, ContentType: "video/mp4",
		Method: db.UploadTus, SourceKey: src, ExpiresAt: time.Now().Add(time.Hour), MaskFaces: maskFaces, DropSource: drop,
	}); err != nil {
		r.t.Fatal(err)
	}
	var a db.Asset
	for _, step := range [][2]db.AssetState{{db.AssetCreated, db.AssetUploading}, {db.AssetUploading, db.AssetCommitted}, {db.AssetCommitted, db.AssetProcessing}} {
		var err error
		if a, err = r.repos.TransitionAsset(ctx, r.tenant.ID, aid, db.Transition{From: step[0], To: step[1]}); err != nil {
			r.t.Fatal(err)
		}
	}
	r.put(keys.Source, src, "source-bytes")
	r.put(keys.Source, src+".info", "{}")
	return a, []string{src, src + ".info"}
}

func (r *rig) complete(repo *pipeline.DBRepo, a db.Asset) db.Asset {
	r.t.Helper()
	out, err := repo.Complete(context.Background(), a.TenantID, a.ID, nil, db.Completion{Duration: time.Second, Renditions: []byte("[]")})
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *rig) dropJobs(a db.Asset) int {
	r.t.Helper()
	return r.count(`SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'asset_id' = $2`, pipeline.DropSourceKind, a.ID.String())
}

func (r *rig) runDrop(p *pipeline.Processor, a db.Asset) {
	r.t.Helper()
	err := p.HandleDropSource(context.Background(), jobs.Job[pipeline.DropSourceArgs]{
		Args: pipeline.DropSourceArgs{TenantID: a.TenantID, AssetID: a.ID}, Attempt: 1, MaxAttempts: 5,
	})
	if err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) sourceLeft(a db.Asset) []string {
	return r.listAll(keys.Source, keys.SourcePrefix(a.TenantID, a.ID))
}

func TestDropSourceDefaultKeepsTheOriginal(t *testing.T) {
	r := newRig(t)
	p, repo := r.dropper()
	a, srcKeys := r.processing(false, false)
	a = r.complete(repo, a)
	if !a.KeepSource || r.dropJobs(a) != 0 {
		t.Fatalf("keep_source=%v, drop jobs=%d", a.KeepSource, r.dropJobs(a))
	}
	r.runDrop(p, a) // even a job that somehow exists does nothing
	if got := r.sourceLeft(a); len(got) != len(srcKeys) {
		t.Fatalf("source objects left: %v", got)
	}
	if r.audits(a, pipeline.AuditSourceDeleted) != 0 {
		t.Fatal("an audit event was written")
	}
}

func TestDropSourceAfterReady(t *testing.T) {
	r := newRig(t)
	p, repo := r.dropper()
	a, _ := r.processing(true, false)
	if r.dropJobs(a) != 0 {
		t.Fatal("a job was queued before the asset was ready")
	}
	a = r.complete(repo, a)
	if a.KeepSource || r.dropJobs(a) != 1 {
		t.Fatalf("keep_source=%v, drop jobs=%d", a.KeepSource, r.dropJobs(a))
	}
	ctx := context.Background()
	before, err := r.repos.StorageBytes(ctx, a.TenantID, id.ClientID{}, id.AssetID{})
	if err != nil || before != 9 { // the declared size of the original
		t.Fatalf("storage before the drop = %d, err=%v", before, err)
	}
	for range 2 { // a retry is harmless and audits once
		r.runDrop(p, a)
	}
	if after, err := r.repos.StorageBytes(ctx, a.TenantID, id.ClientID{}, id.AssetID{}); err != nil || after != 0 {
		t.Fatalf("storage after the drop = %d, err=%v: the original no longer counts", after, err)
	}
	if got := r.sourceLeft(a); len(got) != 0 {
		t.Fatalf("source objects left: %v", got)
	}
	cur, err := r.repos.GetAsset(ctx, a.TenantID, a.ID)
	if err != nil || cur.SourceDeletedAt == nil || cur.State != db.AssetReady {
		t.Fatalf("asset after the drop: %v, source_deleted_at=%v, err=%v", cur, cur.SourceDeletedAt, err)
	}
	if n := r.audits(a, pipeline.AuditSourceDeleted); n != 1 {
		t.Fatalf("%d asset.source_deleted events, want 1", n)
	}
}

func TestDropSourceWaitsForMasking(t *testing.T) {
	ctx := context.Background()

	// The masked variant finishes after the original: the job is queued when it does.
	r := newRig(t)
	p, repo := r.dropper()
	a, _ := r.processing(true, true)
	a = r.complete(repo, a)
	if a.MaskingState != db.MaskingPending || r.dropJobs(a) != 0 {
		t.Fatalf("masking=%q, drop jobs=%d: the original must stay while the masker may read it", a.MaskingState, r.dropJobs(a))
	}
	r.runDrop(p, a) // a stray job still keeps it
	if got := r.sourceLeft(a); len(got) != 2 {
		t.Fatalf("source objects left while masking is pending: %v", got)
	}
	if err := r.repos.InsertManifest(ctx, db.AssetManifest{
		AssetID: a.ID, TenantID: a.TenantID, KeyID: "sk_test", PayloadSHA256: []byte("01234567890123456789012345678901"),
		TopRoot: []byte("01234567890123456789012345678901"), Envelope: []byte(`{"payloadType":"x","payload":"e30=","signatures":[]}`),
	}); err != nil {
		t.Fatal(err)
	}
	m, err := r.repos.GetManifest(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteMasking(ctx, a.TenantID, a.ID, nil, m, m.PayloadSHA256, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if r.dropJobs(a) != 1 {
		t.Fatalf("drop jobs after the masked variant was published: %d", r.dropJobs(a))
	}
	r.runDrop(p, a)
	if got := r.sourceLeft(a); len(got) != 0 {
		t.Fatalf("source objects left: %v", got)
	}

	// The masker fails after the original is ready: that settles masking too.
	b, _ := r.processing(true, true)
	b = r.complete(repo, b)
	if err := repo.SetMasking(ctx, b.TenantID, b.ID, db.MaskingFailed, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if r.dropJobs(b) != 1 {
		t.Fatalf("drop jobs after the masker failed: %d", r.dropJobs(b))
	}

	// The masker fails before the original is ready: the job is queued when the original is.
	c, _ := r.processing(true, true)
	if err := repo.SetMasking(ctx, c.TenantID, c.ID, db.MaskingFailed, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if r.dropJobs(c) != 0 {
		t.Fatal("a job was queued before the asset was ready")
	}
	r.complete(repo, c)
	if r.dropJobs(c) != 1 {
		t.Fatalf("drop jobs after the original was ready: %d", r.dropJobs(c))
	}
}

func TestDropSourceNeverRunsForFailedOrDeletingAssets(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	p, _ := r.dropper()

	failed, _ := r.processing(true, false)
	if _, err := r.repos.TransitionAsset(ctx, failed.TenantID, failed.ID, db.Transition{From: db.AssetProcessing, To: db.AssetFailed, FailureCode: "transcode_failed"}); err != nil {
		t.Fatal(err)
	}
	deleting, _ := r.processing(true, false)
	if _, err := r.repos.RequestAssetDeletion(ctx, deleting.TenantID, deleting.ID, db.DeletionRequested, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, a := range []db.Asset{failed, deleting} {
		r.runDrop(p, a)
		if got := r.sourceLeft(a); len(got) != 2 {
			t.Errorf("%s: source objects left: %v", a.ID, got)
		}
	}
}

// A purge enumerates storage, so it succeeds when the original is already gone, and the asset is
// then deleted with nothing left behind.
func TestPurgeAfterTheSourceWasDropped(t *testing.T) {
	r := newRig(t)
	p, _ := r.dropper()
	s := r.seed(false)
	if _, err := r.pool.Exec(context.Background(), `UPDATE assets SET keep_source = false WHERE id = $1::uuid`, s.asset.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	r.runDrop(p, s.asset)
	if got := r.sourceLeft(s.asset); len(got) != 0 {
		t.Fatalf("source objects left: %v", got)
	}
	if err := r.run(r.purger, s.asset, db.DeletionRequested); err != nil {
		t.Fatal(err)
	}
	r.assertNothingStored(s.asset)
	got := mustAsset(r, s.asset)
	if got.State != db.AssetDeleted {
		t.Fatalf("state after the purge = %s", got.State)
	}
}
