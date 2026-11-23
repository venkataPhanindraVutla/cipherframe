//go:build integration

package rekey_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/rivertype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/anchor"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/purge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/rekey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
)

func TestMain(m *testing.M) {
	code := dbtest.Run(m)
	storagetest.Terminate()
	os.Exit(code)
}

// flaky is the delivery bucket with a switch that makes every write fail: the crash of a worker
// part-way through a re-key.
type flaky struct {
	storage.Store
	failAfter atomic.Int64 // puts that still succeed; negative means never fail
}

func (f *flaky) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	if n := f.failAfter.Add(-1); n < 0 && n > -1_000_000 {
		return errors.New("injected storage failure")
	}
	return f.Store.Put(ctx, key, body, size, contentType)
}

func (f *flaky) heal() { f.failAfter.Store(1 << 40) }

type rig struct {
	t        *testing.T
	pool     *pgxpool.Pool
	repos    *db.Repos
	buckets  *storage.Buckets
	delivery *flaky
	mgr      *contentkey.Manager
	signer   *signing.Manager
	queue    *jobs.Queue
	req      *rekey.Requester
	proc     *rekey.Processor
	tenant   db.Tenant
	client   db.Client
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
	r := &rig{t: t, pool: pool, repos: db.New(pool), buckets: buckets, delivery: &flaky{Store: buckets.Delivery}}
	r.delivery.heal()
	r.mgr = contentkey.NewManager(pool, kreg, slog.New(slog.DiscardHandler))
	r.signer = signing.NewManager(pool, kreg, slog.New(slog.DiscardHandler))
	t.Cleanup(r.signer.Close)
	ctx := context.Background()
	if err := r.signer.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	reg := jobs.NewRegistry()
	for _, declare := range []func(*jobs.Registry) error{rekey.Declare, purge.DeclareCDN, anchor.Declare} {
		if err := declare(reg); err != nil {
			t.Fatal(err)
		}
	}
	if r.queue, err = jobs.NewQueue(pool, reg, jobs.Config{}); err != nil {
		t.Fatal(err)
	}
	if r.req, err = rekey.NewRequester(pool, r.queue); err != nil {
		t.Fatal(err)
	}
	if r.proc, err = rekey.New(rekey.Deps{
		Pool: pool, Delivery: r.delivery, Keys: r.mgr, Signer: r.signer, Queue: r.queue, Anchor: true, CDN: true,
		Log: slog.New(slog.DiscardHandler),
	}); err != nil {
		t.Fatal(err)
	}
	if r.tenant, err = r.repos.CreateTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if r.client, err = r.repos.CreateClient(ctx, r.tenant.ID, "acme-client"); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) actor() auth.Actor { return auth.Actor{ClientID: r.client.ID, RequestID: "req-1"} }

// seeded is a ready asset with real ciphertext in the delivery bucket.
type seeded struct {
	asset db.Asset
	// plain is each segment's plaintext, by variant and path relative to the variant's HLS prefix.
	plain map[string][]byte
	// oldKey is each variant's plaintext content key before the re-key.
	oldKey      map[keys.Variant][]byte
	oldKeyID    map[keys.Variant]id.ContentKeyID
	oldManifest []byte
}

// renditionNames are an asset's renditions: two H.264 rungs and one of each extra codec, whose names
// carry the codec (ADR 0064). A re-key must treat all of them alike.
var renditionNames = []string{"720p", "480p", "720p_hevc", "720p_av1"}

const segmentsPerRendition = 3

func (r *rig) put(key string, body []byte) {
	r.t.Helper()
	if err := r.buckets.Delivery.Put(context.Background(), key, bytes.NewReader(body), int64(len(body)), "application/octet-stream"); err != nil {
		r.t.Fatal(err)
	}
}

// variantTree encrypts, stores and registers one variant the way the pipeline does, and returns its
// manifest input.
func (r *rig) variantTree(aid id.AssetID, v keys.Variant, s *seeded) ([]manifest.RenditionInput, manifest.StoredObject) {
	r.t.Helper()
	ctx := context.Background()
	var ck contentkey.ContentKey
	err := db.Tx(ctx, r.pool, func(tx *db.Repos) error {
		var err error
		ck, err = r.mgr.Create(ctx, tx, r.tenant.ID, aid, v)
		return err
	})
	if err != nil {
		r.t.Fatal(err)
	}
	key := ck.Bytes()
	s.oldKey[v], s.oldKeyID[v] = key, ck.ID()
	ck.Zero()

	prefix := keys.VariantHLSPrefix(r.tenant.ID, aid, v)
	record := func(kind db.ArtifactKind, rendition, objKey string, body []byte) manifest.StoredObject {
		sum := sha256.Sum256(body)
		if err := r.repos.RecordArtifact(ctx, db.Artifact{
			AssetID: aid, Kind: kind, Rendition: rendition, Bucket: "delivery", ObjectKey: objKey,
			SizeBytes: int64(len(body)), SHA256: sum[:], Variant: v.String(),
		}); err != nil {
			r.t.Fatal(err)
		}
		return manifest.StoredObject{Path: strings.TrimPrefix(objKey, prefix), SHA256: sum, Size: int64(len(body))}
	}
	var renditions []manifest.RenditionInput
	for _, name := range renditionNames {
		rend, _ := keys.ParseRendition(name)
		initKey := keys.VariantInitSegment(r.tenant.ID, aid, v, rend)
		initBody := []byte("init-" + v.String() + name)
		r.put(initKey, initBody)
		in := manifest.RenditionInput{Name: name, Width: 1280, Height: 720, Bandwidth: 1000, Init: record(db.ArtifactInit, name, initKey, initBody)}
		pl := hls.MediaPlaylist{InitURI: "init.mp4"}
		for n := range segmentsPerRendition {
			plain := bytes.Repeat([]byte(fmt.Sprintf("%s-%s-%d;", v, name, n)), 100+n*7)
			iv, err := hls.NewIV()
			if err != nil {
				r.t.Fatal(err)
			}
			ct, err := hls.EncryptSegment(key, iv, plain)
			if err != nil {
				r.t.Fatal(err)
			}
			segKey := keys.VariantSegment(r.tenant.ID, aid, v, rend, n)
			r.put(segKey, ct)
			in.Segments = append(in.Segments, record(db.ArtifactSegment, name, segKey, ct))
			s.plain[v.String()+"|"+strings.TrimPrefix(segKey, prefix)] = plain
			pl.Segments = append(pl.Segments, hls.Segment{URI: fmt.Sprintf("seg-%d.m4s", n), Duration: 6 * time.Second, IV: iv})
		}
		text, err := hls.RenderMedia(pl)
		if err != nil {
			r.t.Fatal(err)
		}
		plKey := keys.VariantPlaylist(r.tenant.ID, aid, v, rend)
		body := []byte(text)
		r.put(plKey, body)
		in.Playlist = record(db.ArtifactPlaylist, name, plKey, body)
		renditions = append(renditions, in)
	}
	masterKey := keys.VariantMaster(r.tenant.ID, aid, v)
	masterBody := []byte("#EXTM3U\n")
	r.put(masterKey, masterBody)
	return renditions, record(db.ArtifactMaster, "", masterKey, masterBody)
}

func (r *rig) seed(maskFaces bool) seeded {
	r.t.Helper()
	ctx := context.Background()
	aid := id.New[id.AssetKind]()
	if _, err := r.repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: aid, TenantID: r.tenant.ID, ClientID: r.client.ID, SizeBytes: 9, ContentType: "video/mp4",
		Method: db.UploadTus, SourceKey: keys.NewSource(r.tenant.ID, aid), ExpiresAt: time.Now().Add(time.Hour), MaskFaces: maskFaces,
	}); err != nil {
		r.t.Fatal(err)
	}
	for _, step := range [][2]db.AssetState{{db.AssetCreated, db.AssetUploading}, {db.AssetUploading, db.AssetCommitted}, {db.AssetCommitted, db.AssetProcessing}} {
		if _, err := r.repos.TransitionAsset(ctx, r.tenant.ID, aid, db.Transition{From: step[0], To: step[1]}); err != nil {
			r.t.Fatal(err)
		}
	}
	s := seeded{plain: map[string][]byte{}, oldKey: map[keys.Variant][]byte{}, oldKeyID: map[keys.Variant]id.ContentKeyID{}}
	now := time.Now().UTC()
	renditions, master := r.variantTree(aid, keys.Original, &s)
	built, err := manifest.Build(manifest.Input{
		AssetID: aid.String(), TenantID: r.tenant.ID.String(), CreatedAt: now, PipelineVersion: "test",
		Encoder:    manifest.Encoder{FFmpeg: "test", VideoCodec: "libx264", Preset: "medium", FrameRate: "30/1", SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128"},
		Renditions: renditions, Master: master, SourceSize: 9,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	row, err := pipeline.SignManifest(ctx, r.signer, r.tenant.ID, aid, built, now)
	if err != nil {
		r.t.Fatal(err)
	}
	if s.asset, err = r.repos.CompleteProcessing(ctx, r.tenant.ID, aid, db.Completion{Duration: time.Second, Renditions: []byte("[]"), Manifest: row, At: now}); err != nil {
		r.t.Fatal(err)
	}
	if maskFaces {
		mr, mm := r.variantTree(aid, keys.Masked, &s)
		withMasked, err := manifest.WithMasked(built.Manifest, manifest.MaskedInput{CreatedAt: now, FacesDetected: 1, Frames: 10, Renditions: mr, Master: mm})
		if err != nil {
			r.t.Fatal(err)
		}
		signed, err := pipeline.SignManifest(ctx, r.signer, r.tenant.ID, aid, withMasked, now)
		if err != nil {
			r.t.Fatal(err)
		}
		if err := r.repos.ReplaceManifest(ctx, *signed, row.PayloadSHA256); err != nil {
			r.t.Fatal(err)
		}
		if _, err := r.repos.SetAssetMasking(ctx, r.tenant.ID, aid, db.MaskingReady, new(int), now); err != nil {
			r.t.Fatal(err)
		}
		row = signed
	}
	s.oldManifest = row.Envelope
	return s
}

func (r *rig) run(s seeded, attempt, maxAttempts int) error {
	return r.proc.Handle(context.Background(), jobs.Job[rekey.Args]{
		Args:    rekey.Args{TenantID: r.tenant.ID, AssetID: s.asset.ID, FromGeneration: 0},
		Attempt: attempt, MaxAttempts: maxAttempts,
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

func (r *rig) audit(action string, asset id.AssetID) int {
	return r.count(`SELECT count(*) FROM audit_events WHERE action = $1 AND target = $2`, action, asset.String())
}

func (r *rig) get(key string) []byte {
	r.t.Helper()
	rc, _, err := r.buckets.Delivery.Get(context.Background(), key, nil)
	if err != nil {
		r.t.Fatalf("get %s: %v", key, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

func (r *rig) exists(key string) bool {
	_, err := r.buckets.Delivery.Head(context.Background(), key)
	return err == nil
}

// playable reports whether every segment of the variant, read at the given generation, decrypts
// under key to the original plaintext, using the IVs of that generation's playlists.
func (r *rig) playable(s seeded, v keys.Variant, gen int, key []byte) error {
	for _, name := range renditionNames {
		rend, _ := keys.ParseRendition(name)
		pl, err := hls.ParseMedia(string(r.get(keys.VariantPlaylistGen(r.tenant.ID, s.asset.ID, v, rend, gen))))
		if err != nil {
			return fmt.Errorf("%s playlist: %w", name, err)
		}
		if len(pl.Segments) != segmentsPerRendition {
			return fmt.Errorf("%s playlist has %d segments", name, len(pl.Segments))
		}
		for n, seg := range pl.Segments {
			ct := r.get(keys.VariantSegmentGen(r.tenant.ID, s.asset.ID, v, rend, n, gen))
			got, err := hls.DecryptSegment(key, seg.IV, ct)
			if err != nil {
				return fmt.Errorf("%s segment %d: %w", name, n, err)
			}
			rel := strings.TrimPrefix(keys.VariantSegment(r.tenant.ID, s.asset.ID, v, rend, n), keys.VariantHLSPrefix(r.tenant.ID, s.asset.ID, v))
			if !bytes.Equal(got, s.plain[v.String()+"|"+rel]) {
				return fmt.Errorf("%s segment %d decrypts to other bytes", name, n)
			}
		}
	}
	return nil
}

func (r *rig) keyBytes(s seeded, v keys.Variant) []byte {
	r.t.Helper()
	ck, err := r.mgr.Get(context.Background(), r.tenant.ID, s.asset.ID, v)
	if err != nil {
		r.t.Fatal(err)
	}
	defer ck.Zero()
	return ck.Bytes()
}

func (r *rig) keySet() offline.KeySet {
	r.t.Helper()
	pubs, err := signing.NewKeySet(r.repos, 0, nil).Get(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	ks := offline.KeySet{}
	for _, p := range pubs {
		ks[p.KeyID] = p.PublicKey
	}
	return ks
}

func TestRekeyReplacesTheKeyOfEveryVariantAndKeepsTheAssetVerifiable(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s := r.seed(true)
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		if err := r.playable(s, v, 0, s.oldKey[v]); err != nil {
			t.Fatalf("the seed is not playable: %v", err)
		}
	}

	jobID, err := r.req.Request(ctx, r.tenant.ID, s.asset.ID, r.actor())
	if err != nil || jobID == 0 {
		t.Fatalf("request: %d, %v", jobID, err)
	}
	// At most one re-key per asset in flight.
	_, err = r.req.Request(ctx, r.tenant.ID, s.asset.ID, r.actor())
	wantCode(t, err, errs.Conflict)

	if err := r.run(s, 1, 5); err != nil {
		t.Fatal(err)
	}

	cur, err := r.repos.GetAsset(ctx, r.tenant.ID, s.asset.ID)
	if err != nil || cur.KeyGeneration != 1 || cur.State != db.AssetReady {
		t.Fatalf("asset: generation %d, state %s, %v", cur.KeyGeneration, cur.State, err)
	}
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		newKey := r.keyBytes(s, v)
		if bytes.Equal(newKey, s.oldKey[v]) {
			t.Fatalf("%s: the key did not change", v)
		}
		// Every segment decrypts under the new key, and not under the old one.
		if err := r.playable(s, v, 1, newKey); err != nil {
			t.Fatalf("%s under the new key: %v", v, err)
		}
		if err := r.playable(s, v, 1, s.oldKey[v]); err == nil {
			t.Fatalf("%s: the old key still decrypts the new segments", v)
		}
		// The old key record is destroyed; one key per variant remains (I7).
		if n := r.count(`SELECT count(*) FROM content_keys WHERE id = $1`, s.oldKeyID[v].UUID()); n != 0 {
			t.Fatalf("%s: the old key record is still there", v)
		}
	}
	if n := r.count(`SELECT count(*) FROM content_keys WHERE asset_id = $1`, s.asset.ID.UUID()); n != 2 {
		t.Fatalf("%d key records, want one per variant", n)
	}

	// The old encrypted objects are gone; init segments and the master playlist are shared and stay.
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		for _, name := range renditionNames {
			rend, _ := keys.ParseRendition(name)
			if r.exists(keys.VariantPlaylist(r.tenant.ID, s.asset.ID, v, rend)) || r.exists(keys.VariantSegment(r.tenant.ID, s.asset.ID, v, rend, 0)) {
				t.Fatalf("%s %s: old encrypted objects are still stored", v, name)
			}
			if !r.exists(keys.VariantInitSegment(r.tenant.ID, s.asset.ID, v, rend)) {
				t.Fatalf("%s %s: the init segment was removed", v, name)
			}
		}
		if !r.exists(keys.VariantMaster(r.tenant.ID, s.asset.ID, v)) {
			t.Fatalf("%s: the master playlist was removed", v)
		}
	}
	// The registry follows the objects: every row names an object that exists.
	arts, err := r.repos.ListArtifacts(ctx, s.asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range arts {
		if !r.exists(a.ObjectKey) {
			t.Errorf("a registered %s of the %s variant is not stored", a.Kind, a.Variant)
		}
	}
	if n := r.count(`SELECT count(*) FROM asset_artifacts WHERE asset_id = $1 AND kind = 'segment'`, s.asset.ID.UUID()); n != 2*len(renditionNames)*segmentsPerRendition {
		t.Errorf("%d segment rows, want %d", n, 2*len(renditionNames)*segmentsPerRendition)
	}

	// The new manifest verifies with the public keys alone, for every object of both variants; the
	// old one does not match the new bytes.
	keysets := r.keySet()
	newManifest, err := r.repos.GetManifest(ctx, s.asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(newManifest.Envelope, s.oldManifest) {
		t.Fatal("the manifest was not signed again")
	}
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		prefix := keys.VariantHLSPrefix(r.tenant.ID, s.asset.ID, v)
		for _, name := range renditionNames {
			rend, _ := keys.ParseRendition(name)
			for n := range segmentsPerRendition {
				newKey := keys.VariantSegmentGen(r.tenant.ID, s.asset.ID, v, rend, n, 1)
				sum := sha256.Sum256(r.get(newKey))
				if res := offline.VerifyArtifact(newManifest.Envelope, keysets, strings.TrimPrefix(newKey, prefix), sum, v.String()); res.Outcome != offline.Ours {
					t.Fatalf("%s %s segment %d under the new manifest: %+v", v, name, n, res)
				}
				oldPath := strings.TrimPrefix(keys.VariantSegment(r.tenant.ID, s.asset.ID, v, rend, n), prefix)
				if res := offline.VerifyArtifact(s.oldManifest, keysets, oldPath, sum, v.String()); res.Outcome != offline.Modified {
					t.Fatalf("%s %s segment %d: the old manifest accepts the new bytes: %+v", v, name, n, res)
				}
			}
			plKey := keys.VariantPlaylistGen(r.tenant.ID, s.asset.ID, v, rend, 1)
			sum := sha256.Sum256(r.get(plKey))
			if res := offline.VerifyArtifact(newManifest.Envelope, keysets, strings.TrimPrefix(plKey, prefix), sum, v.String()); res.Outcome != offline.Ours {
				t.Fatalf("%s %s playlist: %+v", v, name, res)
			}
		}
	}

	// Audited, anchored and purged from the CDN: one of each.
	if r.audit(rekey.AuditRequested, s.asset.ID) != 1 || r.audit(rekey.AuditCompleted, s.asset.ID) != 1 || r.audit(rekey.AuditFailed, s.asset.ID) != 0 {
		t.Error("the audit log does not hold exactly a requested and a completed event")
	}
	if n := r.count(`SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'asset_id' = $2`, purge.CDNJobKind, s.asset.ID.String()); n != 1 {
		t.Errorf("%d CDN purge jobs, want 1", n)
	}
	if n := r.count(`SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'asset_id' = $2`, anchor.Kind, s.asset.ID.String()); n != 1 {
		t.Errorf("%d anchor jobs, want 1", n)
	}

	// Running the job again changes nothing: the switch was made, nothing is left to remove.
	if err := r.run(s, 2, 5); err != nil {
		t.Fatal(err)
	}
	if cur, _ := r.repos.GetAsset(ctx, r.tenant.ID, s.asset.ID); cur.KeyGeneration != 1 {
		t.Fatal("a repeated job re-keyed again")
	}
}

func TestACrashBeforeTheSwitchLeavesTheAssetPlayableAndTheRetryCompletes(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s := r.seed(false)
	before, err := r.repos.GetManifest(ctx, s.asset.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Four objects are written, then the store fails: the first attempt dies in the middle.
	r.delivery.failAfter.Store(4)
	err = r.run(s, 1, 5)
	if err == nil {
		t.Fatal("the job succeeded although storage failed")
	}
	if strings.Contains(err.Error(), "k1/") || strings.Contains(err.Error(), s.asset.ID.String()) {
		t.Errorf("the error names an object key: %v", err)
	}
	cur, _ := r.repos.GetAsset(ctx, r.tenant.ID, s.asset.ID)
	if cur.KeyGeneration != 0 || cur.State != db.AssetReady {
		t.Fatalf("asset moved: generation %d, state %s", cur.KeyGeneration, cur.State)
	}
	if got := r.keyBytes(s, keys.Original); !bytes.Equal(got, s.oldKey[keys.Original]) {
		t.Fatal("the key changed")
	}
	if err := r.playable(s, keys.Original, 0, s.oldKey[keys.Original]); err != nil {
		t.Fatalf("the asset is not playable under the old key after the crash: %v", err)
	}
	if m, _ := r.repos.GetManifest(ctx, s.asset.ID); !bytes.Equal(m.PayloadSHA256, before.PayloadSHA256) {
		t.Fatal("the manifest changed")
	}
	if r.audit(rekey.AuditFailed, s.asset.ID) != 0 {
		t.Fatal("a failed event was written for an attempt that will be retried")
	}

	// The retry cleans up and completes.
	r.delivery.heal()
	if err := r.run(s, 2, 5); err != nil {
		t.Fatal(err)
	}
	if err := r.playable(s, keys.Original, 1, r.keyBytes(s, keys.Original)); err != nil {
		t.Fatalf("after the retry: %v", err)
	}
	if r.audit(rekey.AuditCompleted, s.asset.ID) != 1 {
		t.Fatal("no completed event")
	}
}

func TestTheLastFailedAttemptIsAuditedAndLeavesNothingStaged(t *testing.T) {
	r := newRig(t)
	s := r.seed(false)
	r.delivery.failAfter.Store(3)
	if err := r.run(s, 5, 5); err == nil {
		t.Fatal("the job succeeded although storage failed")
	}
	if r.audit(rekey.AuditFailed, s.asset.ID) != 1 {
		t.Fatal("the failure was not audited")
	}
	prefix := keys.VariantGenPrefix(r.tenant.ID, s.asset.ID, keys.Original, 1)
	for obj, err := range storage.ListAll(context.Background(), r.buckets.Delivery, prefix) {
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("a staged object is left: %s", obj.Key)
	}
	if err := r.playable(s, keys.Original, 0, s.oldKey[keys.Original]); err != nil {
		t.Fatalf("the asset is not playable: %v", err)
	}
}

func TestAStoredSegmentThatDoesNotMatchTheManifestFailsTheJobForGood(t *testing.T) {
	r := newRig(t)
	s := r.seed(false)
	rend, _ := keys.ParseRendition("720p")
	r.put(keys.VariantSegment(r.tenant.ID, s.asset.ID, keys.Original, rend, 1), []byte("not what was signed"))
	err := r.run(s, 1, 5)
	var cancelled *rivertype.JobCancelError
	if !errors.As(err, &cancelled) {
		t.Fatalf("err = %v, want the job cancelled", err)
	}
	if r.audit(rekey.AuditFailed, s.asset.ID) != 1 {
		t.Fatal("the failure was not audited")
	}
	if cur, _ := r.repos.GetAsset(context.Background(), r.tenant.ID, s.asset.ID); cur.KeyGeneration != 0 {
		t.Fatal("the asset was switched")
	}
}

func TestRequestRefusesWhatCannotBeRekeyed(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	// Not ready.
	aid := id.New[id.AssetKind]()
	if _, err := r.repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: aid, TenantID: r.tenant.ID, ClientID: r.client.ID, SizeBytes: 9, Method: db.UploadTus,
		SourceKey: keys.NewSource(r.tenant.ID, aid), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := r.req.Request(ctx, r.tenant.ID, aid, r.actor())
	wantCode(t, err, errs.AssetNotReady)

	// Another tenant's asset and an unknown one are not found.
	s := r.seed(false)
	other, err := r.repos.CreateTenant(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.req.Request(ctx, other.ID, s.asset.ID, r.actor())
	wantCode(t, err, errs.NotFound)
	_, err = r.req.Request(ctx, r.tenant.ID, id.New[id.AssetKind](), r.actor())
	wantCode(t, err, errs.NotFound)

	// Masking still running.
	m := r.seed(true)
	if _, err := r.pool.Exec(ctx, `UPDATE assets SET masking_state = 'pending' WHERE id = $1`, m.asset.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	_, err = r.req.Request(ctx, r.tenant.ID, m.asset.ID, r.actor())
	wantCode(t, err, errs.Conflict)

	// A job that was dead-lettered no longer blocks a new request; one that is waiting does.
	if _, err := r.req.Request(ctx, r.tenant.ID, s.asset.ID, r.actor()); err != nil {
		t.Fatal(err)
	}
	_, err = r.req.Request(ctx, r.tenant.ID, s.asset.ID, r.actor())
	wantCode(t, err, errs.Conflict)
	if _, err := r.pool.Exec(ctx, `UPDATE river_job SET state = 'discarded', finalized_at = now() WHERE kind = $1`, rekey.JobKind); err != nil {
		t.Fatal(err)
	}
	if _, err := r.req.Request(ctx, r.tenant.ID, s.asset.ID, r.actor()); err != nil {
		t.Fatalf("a request after a dead-lettered job: %v", err)
	}

	// A deleting asset.
	if _, err := r.repos.RequestAssetDeletion(ctx, r.tenant.ID, m.asset.ID, db.DeletionRequested, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	_, err = r.req.Request(ctx, r.tenant.ID, m.asset.ID, r.actor())
	wantCode(t, err, errs.Conflict)
}

func TestAJobForAnAssetThatIsBeingDeletedStopsWithoutTouchingIt(t *testing.T) {
	r := newRig(t)
	s := r.seed(false)
	if _, err := r.repos.RequestAssetDeletion(context.Background(), r.tenant.ID, s.asset.ID, db.DeletionRequested, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := r.run(s, 1, 5); err != nil {
		t.Fatal(err)
	}
	if err := r.playable(s, keys.Original, 0, s.oldKey[keys.Original]); err != nil {
		t.Fatal(err)
	}
	if r.audit(rekey.AuditFailed, s.asset.ID) != 0 || r.audit(rekey.AuditCompleted, s.asset.ID) != 0 {
		t.Fatal("an event was written for a job that did nothing")
	}
}

func wantCode(t *testing.T, err error, code errs.Code) {
	t.Helper()
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}
