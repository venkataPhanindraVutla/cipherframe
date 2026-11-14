//go:build integration

package purge_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/rivertype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/deletion"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/purge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/retention"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

func TestMain(m *testing.M) {
	code := dbtest.Run(m)
	storagetest.Terminate()
	os.Exit(code)
}

// rig is a purger over a fresh database and the shared object store.
type rig struct {
	t       *testing.T
	pool    *pgxpool.Pool
	repos   *db.Repos
	buckets *storage.Buckets
	mgr     *contentkey.Manager
	queue   *jobs.Queue
	signer  *signing.Manager
	purger  *purge.Purger
	tenant  db.Tenant
	client  db.Client
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pool := dbtest.NewMigrated(t)
	buckets, err := storage.New(context.Background(), storagetest.Shared(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	p, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	kreg, err := kms.NewRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, pool: pool, repos: db.New(pool), buckets: buckets}
	r.mgr = contentkey.NewManager(pool, kreg, slog.New(slog.DiscardHandler))
	r.signer = signing.NewManager(pool, kreg, slog.New(slog.DiscardHandler))
	t.Cleanup(r.signer.Close)
	if err := r.signer.EnsureCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	reg := jobs.NewRegistry()
	if err := pipeline.Declare(reg); err != nil {
		t.Fatal(err)
	}
	if err := purge.Declare(reg); err != nil {
		t.Fatal(err)
	}
	if r.queue, err = jobs.NewQueue(pool, reg, jobs.Config{}); err != nil {
		t.Fatal(err)
	}
	r.purger = r.newPurger(buckets.Delivery)
	ctx := context.Background()
	if r.tenant, err = r.repos.CreateTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if r.client, err = r.repos.CreateClient(ctx, r.tenant.ID, "acme-client"); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) newPurger(delivery storage.Store) *purge.Purger {
	p, err := purge.New(purge.Deps{
		Pool: r.pool, Source: r.buckets.Source, Delivery: delivery, Keys: r.mgr, Signer: r.signer,
		Log: slog.New(slog.DiscardHandler), InFlightWait: time.Hour,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}

func (r *rig) put(bucket keys.Bucket, key string, data string) {
	r.t.Helper()
	var store storage.Store = r.buckets.Delivery
	if bucket == keys.Source {
		store = r.buckets.Source
	}
	if err := store.Put(context.Background(), key, bytes.NewReader([]byte(data)), int64(len(data)), "application/octet-stream"); err != nil {
		r.t.Fatal(err)
	}
}

// seeded is a ready asset with everything the pipeline and the upload path can leave behind.
type seeded struct {
	asset db.Asset
	// objects maps every key written to its bucket.
	objects map[string]keys.Bucket
}

// seed makes a ready asset: the source and tusd's .info object, an original and a masked HLS tree,
// a poster, registry rows, a manifest, both content keys and one active playback session.
func (r *rig) seed(maskFaces bool) seeded {
	r.t.Helper()
	ctx := context.Background()
	aid := id.New[id.AssetKind]()
	src := keys.NewSource(r.tenant.ID, aid)
	_, err := r.repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: aid, TenantID: r.tenant.ID, ClientID: r.client.ID, SizeBytes: 9, ContentType: "video/mp4",
		Method: db.UploadTus, SourceKey: src, ExpiresAt: time.Now().Add(time.Hour), MaskFaces: maskFaces,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	for _, step := range [][2]db.AssetState{{db.AssetCreated, db.AssetUploading}, {db.AssetUploading, db.AssetCommitted}, {db.AssetCommitted, db.AssetProcessing}} {
		if _, err = r.repos.TransitionAsset(ctx, r.tenant.ID, aid, db.Transition{From: step[0], To: step[1]}); err != nil {
			r.t.Fatal(err)
		}
	}
	a, err := r.repos.CompleteProcessing(ctx, r.tenant.ID, aid, db.Completion{Duration: time.Second, Renditions: []byte("[]")})
	if err != nil {
		r.t.Fatal(err)
	}
	s := seeded{objects: map[string]keys.Bucket{}}
	add := func(b keys.Bucket, key string) {
		r.put(b, key, "data-"+key)
		s.objects[key] = b
	}
	add(keys.Source, src)
	add(keys.Source, src+".info")
	r720, _ := keys.ParseRendition("720p")
	variants := []keys.Variant{keys.Original}
	if maskFaces {
		variants = append(variants, keys.Masked)
	}
	for _, v := range variants {
		add(keys.Delivery, keys.VariantMaster(r.tenant.ID, aid, v))
		add(keys.Delivery, keys.VariantPlaylist(r.tenant.ID, aid, v, r720))
		add(keys.Delivery, keys.VariantInitSegment(r.tenant.ID, aid, v, r720))
		for n := range 3 {
			key := keys.VariantSegment(r.tenant.ID, aid, v, r720, n)
			add(keys.Delivery, key)
			sum := bytes.Repeat([]byte{byte(n + 1)}, 32)
			if err := r.repos.RecordArtifact(ctx, db.Artifact{
				AssetID: aid, Kind: db.ArtifactSegment, Rendition: "720p", Bucket: "delivery", ObjectKey: key,
				SizeBytes: 10, SHA256: sum, Variant: v.String(),
			}); err != nil {
				r.t.Fatal(err)
			}
		}
		err := db.Tx(ctx, r.pool, func(tx *db.Repos) error {
			k, err := r.mgr.Create(ctx, tx, r.tenant.ID, aid, v)
			k.Zero()
			return err
		})
		if err != nil {
			r.t.Fatal(err)
		}
	}
	add(keys.Delivery, keys.Poster(r.tenant.ID, aid))
	if maskFaces {
		if _, err := r.repos.SetAssetMasking(ctx, r.tenant.ID, aid, db.MaskingReady, new(int), time.Now()); err != nil {
			r.t.Fatal(err)
		}
	}
	if err := r.repos.InsertManifest(ctx, db.AssetManifest{
		AssetID: aid, TenantID: r.tenant.ID, KeyID: "sk_test", PayloadSHA256: bytes.Repeat([]byte{7}, 32),
		TopRoot: bytes.Repeat([]byte{8}, 32), Envelope: []byte(`{"payloadType":"x","payload":"e30=","signatures":[]}`),
	}); err != nil {
		r.t.Fatal(err)
	}
	now := time.Now().UTC()
	sid, err := id.NewSession()
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.repos.InsertPlaybackSession(ctx, db.NewPlaybackSession{
		ID: sid, TenantID: r.tenant.ID, ClientID: r.client.ID, AssetID: aid,
		ViewerID: "viewer-1", Now: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		r.t.Fatal(err)
	}
	s.asset = a
	return s
}

func (r *rig) listAll(bucket keys.Bucket, prefix string) []string {
	r.t.Helper()
	var store storage.Store = r.buckets.Delivery
	if bucket == keys.Source {
		store = r.buckets.Source
	}
	var out []string
	for o, err := range storage.ListAll(context.Background(), store, prefix) {
		if err != nil {
			r.t.Fatal(err)
		}
		out = append(out, o.Key)
	}
	return out
}

func (r *rig) assertNothingStored(a db.Asset) {
	r.t.Helper()
	for _, p := range keys.AssetPrefixes(a.TenantID, a.ID) {
		if left := r.listAll(p.Bucket, p.Prefix); len(left) != 0 {
			r.t.Errorf("%d objects left under the %s prefix: %v", len(left), p.Bucket, left)
		}
	}
}

func (r *rig) run(p *purge.Purger, a db.Asset, reason string) error {
	return p.Handle(context.Background(), jobs.Job[purge.DeleteArgs]{
		Args: purge.DeleteArgs{TenantID: a.TenantID, AssetID: a.ID, Reason: reason}, Attempt: 1, MaxAttempts: 8,
	})
}

func (r *rig) count(query string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func wantCode(t *testing.T, err error, code errs.Code) {
	t.Helper()
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

func TestPurgeDeletesEverythingOfAReadyAssetWithAMaskedVariant(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s := r.seed(true)
	a := s.asset
	other := r.seed(false) // another asset must be left alone
	var wantKeys []string
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		k, err := r.repos.GetContentKey(ctx, a.TenantID, a.ID, v)
		if err != nil {
			t.Fatal(err)
		}
		wantKeys = append(wantKeys, k.ID.String()+"/"+v.String())
	}
	stray := keys.DeliveryPrefix(a.TenantID, a.ID) + "thumbs/stray.jpg"
	r.put(keys.Delivery, stray, "x")
	s.objects[stray] = keys.Delivery

	if err := r.run(r.purger, a, db.DeletionRequested); err != nil {
		t.Fatal(err)
	}
	r.assertNothingStored(a)
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		if _, err := r.repos.GetContentKey(ctx, a.TenantID, a.ID, v); err == nil {
			t.Errorf("the %s content key survived", v)
		}
	}
	if n := r.count(`SELECT count(*) FROM content_keys WHERE asset_id = $1`, a.ID.UUID()); n != 0 {
		t.Errorf("%d content key rows left", n)
	}
	if n := r.count(`SELECT count(*) FROM asset_artifacts WHERE asset_id = $1`, a.ID.UUID()); n != 0 {
		t.Errorf("%d registry rows left", n)
	}
	if n := r.count(`SELECT count(*) FROM asset_manifests WHERE asset_id = $1`, a.ID.UUID()); n != 0 {
		t.Errorf("%d manifests left", n)
	}
	if n := r.count(`SELECT count(*) FROM playback_sessions WHERE asset_id = $1 AND state = 'active'`, a.ID.UUID()); n != 0 {
		t.Errorf("%d active sessions left", n)
	}
	if n := r.count(`SELECT count(*) FROM playback_access_log WHERE asset_id = $1 AND event = 'revoked'`, a.ID.UUID()); n != 1 {
		t.Errorf("%d revoked rows in the access trail, want 1", n)
	}
	got, err := r.repos.GetAsset(ctx, a.TenantID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != db.AssetDeleted || got.DeletedAt == nil || got.DeletionRequestedAt == nil || got.DeletionReason != db.DeletionRequested || got.SourceKey != "" {
		t.Errorf("tombstone = %+v", got)
	}
	// Playback is refused for a deleted asset.
	now := time.Now().UTC()
	sid, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.repos.InsertPlaybackSession(ctx, db.NewPlaybackSession{
		ID: sid, TenantID: a.TenantID, ClientID: r.client.ID, AssetID: a.ID, ViewerID: "v", Now: now, ExpiresAt: now.Add(time.Hour),
	})
	if !errors.Is(err, db.ErrStateChanged) {
		t.Errorf("a session for a deleted asset: %v", err)
	}
	// The other asset is untouched.
	for key, b := range other.objects {
		if !slices.Contains(r.listAll(b, key), key) {
			t.Errorf("another asset's object %q is gone", key)
		}
	}
	if _, err := r.repos.GetContentKey(ctx, other.asset.TenantID, other.asset.ID, keys.Original); err != nil {
		t.Errorf("another asset's key: %v", err)
	}

	r.checkRecord(a, s, db.DeletionRequested, wantKeys)

	// A second run, and a second job, change nothing and succeed, and keep the one record.
	if err := r.run(r.purger, a, db.DeletionRequested); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if n := r.count(`SELECT count(*) FROM asset_deletion_records WHERE asset_id = $1`, a.ID.UUID()); n != 1 {
		t.Errorf("%d deletion records, want 1", n)
	}
}

// checkRecord fetches the stored record the way the API serves it, verifies it with public keys
// only and compares its counts with what the test wrote.
func (r *rig) checkRecord(a db.Asset, s seeded, reason string, wantKeys []string) {
	r.t.Helper()
	ctx := context.Background()
	row, err := r.repos.GetDeletionRecord(ctx, a.TenantID, a.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	pub, err := r.signer.PublicKeys(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	keySet := offline.KeySet{}
	for _, k := range pub {
		keySet[k.KeyID] = k.PublicKey
	}
	signed, err := offline.OpenDeletion(row.Envelope, keySet)
	if err != nil {
		r.t.Fatalf("the record does not verify with the published keys: %v", err)
	}
	rec := signed.Record
	if rec.Schema != deletion.Schema || rec.AssetID != a.ID.String() || rec.TenantID != a.TenantID.String() || rec.Reason != reason {
		r.t.Errorf("record = %+v", rec)
	}
	if rec.ManifestRoot != strings.Repeat("08", 32) {
		r.t.Errorf("manifest root = %q", rec.ManifestRoot)
	}
	want := map[string]deletion.ObjectCount{}
	for key, bucket := range s.objects {
		c := purge.Classify(a.TenantID, a.ID, bucket, key)
		k := string(c.Bucket) + "/" + string(c.Kind) + "/" + c.Variant
		o := want[k]
		o.Bucket, o.Kind, o.Variant = string(c.Bucket), string(c.Kind), c.Variant
		o.Count++
		o.Bytes += int64(len("data-" + key))
		want[k] = o
	}
	if len(rec.Objects) != len(want) {
		r.t.Errorf("record lists %d kinds, want %d: %+v", len(rec.Objects), len(want), rec.Objects)
	}
	var total int64
	for _, o := range rec.Objects {
		k := o.Bucket + "/" + o.Kind + "/" + o.Variant
		if w, ok := want[k]; !ok || w.Count != o.Count || (o.Kind != string(purge.KindOther) && w.Bytes != o.Bytes) {
			r.t.Errorf("record entry %+v, want %+v", o, w)
		}
		total += o.Count
	}
	if total != rec.ObjectsDeleted || total != int64(len(s.objects)) {
		r.t.Errorf("record says %d objects deleted, the test wrote %d", total, len(s.objects))
	}
	var gotKeys []string
	for _, k := range rec.ContentKeys.Keys {
		gotKeys = append(gotKeys, k.ID+"/"+k.Variant)
	}
	slices.Sort(gotKeys)
	slices.Sort(wantKeys)
	if !slices.Equal(gotKeys, wantKeys) || rec.ContentKeys.Destroyed != len(wantKeys) {
		r.t.Errorf("record keys %v, want %v", gotKeys, wantKeys)
	}
	if row.Reason != reason || !row.CompletedAt.Equal(*mustAsset(r, a).DeletedAt) {
		r.t.Errorf("record row = %+v", row)
	}
}

func mustAsset(r *rig, a db.Asset) db.Asset {
	got, err := r.repos.GetAsset(context.Background(), a.TenantID, a.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return got
}

// A purge enumerates storage, not the registry: an object nothing registered goes too.
func TestPurgeRemovesObjectsNobodyRegistered(t *testing.T) {
	r := newRig(t)
	s := r.seed(false)
	stray := keys.DeliveryPrefix(s.asset.TenantID, s.asset.ID) + "thumbs/stray.jpg"
	r.put(keys.Delivery, stray, "x")
	if err := r.run(r.purger, s.asset, db.DeletionRetention); err != nil {
		t.Fatal(err)
	}
	r.assertNothingStored(s.asset)
	got, _ := r.repos.GetAsset(context.Background(), s.asset.TenantID, s.asset.ID)
	if got.State != db.AssetDeleted || got.DeletionReason != db.DeletionRetention {
		t.Errorf("asset = %+v", got)
	}
}

// stickyStore pretends to delete one key and keeps it.
type stickyStore struct {
	storage.Store
	stick string
}

func (s stickyStore) DeleteBatch(ctx context.Context, ks []string) error {
	return s.Store.DeleteBatch(ctx, slices.DeleteFunc(slices.Clone(ks), func(k string) bool { return k == s.stick }))
}

// Leftovers are never reported as success: the job fails, the asset stays deleting, the keys stay,
// and a later run (with storage behaving) finishes the job.
func TestPurgeFailsLoudlyWhenObjectsRemain(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s := r.seed(true)
	a := s.asset
	sticky := r.newPurger(stickyStore{Store: r.buckets.Delivery, stick: keys.Poster(a.TenantID, a.ID)})
	err := r.run(sticky, a, db.DeletionRequested)
	if !errors.Is(err, purge.ErrLeftovers) {
		t.Fatalf("error = %v, want ErrLeftovers", err)
	}
	got, _ := r.repos.GetAsset(ctx, a.TenantID, a.ID)
	if got.State != db.AssetDeleting || got.DeletedAt != nil {
		t.Errorf("asset after a failed purge = %+v", got)
	}
	if _, err := r.repos.GetContentKey(ctx, a.TenantID, a.ID, keys.Original); err != nil {
		t.Errorf("the content key was destroyed although storage was not clean: %v", err)
	}
	if err := r.run(r.purger, a, db.DeletionRequested); err != nil {
		t.Fatalf("retry: %v", err)
	}
	r.assertNothingStored(a)
	if got, _ = r.repos.GetAsset(ctx, a.TenantID, a.ID); got.State != db.AssetDeleted {
		t.Errorf("state = %s", got.State)
	}
}

// While a processing or masking job of the asset is active the purge waits for it; once it is gone
// the purge runs.
func TestPurgeWaitsForInFlightJobs(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s := r.seed(false)
	a := s.asset
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.queue.Enqueue(ctx, tx, uploads.ProcessArgs{TenantID: a.TenantID, AssetID: a.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = r.run(r.purger, a, db.DeletionRequested)
	var snooze *rivertype.JobSnoozeError
	if !errors.As(err, &snooze) {
		t.Fatalf("error = %v, want a snooze while the process job is queued", err)
	}
	if got, _ := r.repos.GetAsset(ctx, a.TenantID, a.ID); got.State != db.AssetDeleting {
		t.Errorf("state = %s; the asset must already refuse work", got.State)
	}
	if _, err := r.pool.Exec(ctx, `UPDATE river_job SET state = 'completed', finalized_at = now() WHERE kind = 'asset.process'`); err != nil {
		t.Fatal(err)
	}
	if err := r.run(r.purger, a, db.DeletionRequested); err != nil {
		t.Fatal(err)
	}
	r.assertNothingStored(a)
}

// An in-flight job cannot bring back a deleted asset's content key.
func TestNoContentKeyIsCreatedForADeletingAsset(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s := r.seed(false)
	a := s.asset
	if _, err := r.repos.RequestAssetDeletion(ctx, a.TenantID, a.ID, db.DeletionRequested, time.Now()); err != nil {
		t.Fatal(err)
	}
	keysFor := pipeline.ContentKeys{Pool: r.pool, Manager: r.mgr}
	if _, err := keysFor.Ensure(ctx, a.TenantID, a.ID, keys.Masked); err == nil {
		t.Fatal("a content key was created for a deleting asset")
	} else {
		wantCode(t, err, errs.Conflict)
	}
	if err := r.run(r.purger, a, db.DeletionRequested); err != nil {
		t.Fatal(err)
	}
	if _, err := keysFor.Ensure(ctx, a.TenantID, a.ID, keys.Original); err == nil {
		t.Fatal("a content key was created for a deleted asset")
	}
	if n := r.count(`SELECT count(*) FROM content_keys WHERE asset_id = $1`, a.ID.UUID()); n != 0 {
		t.Errorf("%d content keys exist for a deleted asset", n)
	}
}

func TestRequestDeletionIsIdempotentAndTenantScoped(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s := r.seed(false)
	a := s.asset
	req, err := purge.NewRequester(r.pool, r.queue)
	if err != nil {
		t.Fatal(err)
	}
	first, err := req.Request(ctx, a.TenantID, a.ID, db.DeletionRequested, nil)
	if err != nil || first.State != db.AssetDeleting || first.DeletionReason != db.DeletionRequested {
		t.Fatalf("first request = %+v, %v", first, err)
	}
	second, err := req.Request(ctx, a.TenantID, a.ID, db.DeletionRetention, nil)
	if err != nil || second.State != db.AssetDeleting || second.DeletionReason != db.DeletionRequested {
		t.Fatalf("second request = %+v, %v (the first reason stays)", second, err)
	}
	if n := r.count(`SELECT count(*) FROM river_job WHERE kind = 'asset.delete'`); n != 1 {
		t.Fatalf("%d purge jobs after two requests, want 1", n)
	}
	// A purge job that is gone from the queue (dead-lettered) is queued again by a new request.
	if _, err := r.pool.Exec(ctx, `UPDATE river_job SET state = 'discarded', finalized_at = now() WHERE kind = 'asset.delete'`); err != nil {
		t.Fatal(err)
	}
	if _, err := req.Request(ctx, a.TenantID, a.ID, db.DeletionRequested, nil); err != nil {
		t.Fatal(err)
	}
	if n := r.count(`SELECT count(*) FROM river_job WHERE kind = 'asset.delete' AND state = 'available'`); n != 1 {
		t.Fatalf("%d available purge jobs after a retry request, want 1", n)
	}
	if err := r.run(r.purger, a, db.DeletionRequested); err != nil {
		t.Fatal(err)
	}
	done, err := req.Request(ctx, a.TenantID, a.ID, db.DeletionRequested, nil)
	if err != nil || done.State != db.AssetDeleted {
		t.Fatalf("request after deletion = %+v, %v", done, err)
	}

	// Another tenant cannot delete the asset, and cannot tell it exists.
	t2, err := r.repos.CreateTenant(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	b := r.seed(false).asset
	_, err = req.Request(ctx, t2.ID, b.ID, db.DeletionRequested, nil)
	wantCode(t, err, errs.NotFound)
	if got, _ := r.repos.GetAsset(ctx, b.TenantID, b.ID); got.State != db.AssetReady {
		t.Errorf("another tenant changed the asset: %s", got.State)
	}
}

// An asset whose time-to-live ran out goes through the same verified purge, with reason retention;
// one without a time-to-live is left alone.
func TestRetentionExpiryTriggersVerifiedDeletion(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s := r.seed(true)
	a := s.asset
	kept := r.seed(false).asset
	var wantKeys []string
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		k, err := r.repos.GetContentKey(ctx, a.TenantID, a.ID, v)
		if err != nil {
			t.Fatal(err)
		}
		wantKeys = append(wantKeys, k.ID.String()+"/"+v.String())
	}
	past := time.Now().Add(-time.Hour)
	if _, err := r.repos.SetAssetExpiry(ctx, a.TenantID, a.ID, &past, time.Now()); err != nil {
		t.Fatal(err)
	}
	req, err := purge.NewRequester(r.pool, r.queue)
	if err != nil {
		t.Fatal(err)
	}
	sweeper := &retention.Sweeper{Store: r.repos, Requester: req, AccessLogDays: 90, Log: slog.New(slog.DiscardHandler)}
	res, err := sweeper.Sweep(ctx)
	if err != nil || res.ExpiredAssets != 1 {
		t.Fatalf("sweep = %+v, %v", res, err)
	}
	got := mustAsset(r, a)
	if got.State != db.AssetDeleting || got.DeletionReason != db.DeletionRetention {
		t.Fatalf("expired asset = %+v", got)
	}
	if n := r.count(`SELECT count(*) FROM river_job WHERE kind = 'asset.delete' AND args->>'reason' = 'retention' AND args->>'asset_id' = $1`, a.ID.String()); n != 1 {
		t.Fatalf("%d retention purge jobs, want 1", n)
	}
	if got := mustAsset(r, kept); got.State != db.AssetReady {
		t.Errorf("an asset without a time-to-live is %s", got.State)
	}
	// Running the sweep again queues nothing more; the purge job then does its work.
	if res, err = sweeper.Sweep(ctx); err != nil || res.ExpiredAssets != 0 {
		t.Fatalf("second sweep = %+v, %v", res, err)
	}
	if err := r.run(r.purger, a, db.DeletionRetention); err != nil {
		t.Fatal(err)
	}
	r.assertNothingStored(a)
	r.checkRecord(a, s, db.DeletionRetention, wantKeys)
	if got := mustAsset(r, a); got.State != db.AssetDeleted || got.DeletionReason != db.DeletionRetention {
		t.Errorf("tombstone = %+v", got)
	}
}
