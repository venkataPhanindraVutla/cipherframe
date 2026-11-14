//go:build integration

package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/anchor"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp/tsatest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
)

// startAnchoring runs a worker for manifest.anchor against the test authority and returns the
// repository the pipeline completes assets with: it enqueues the job with every manifest.
func (h *harness) startAnchoring(tsa *tsatest.TSA) *pipeline.DBRepo {
	h.t.Helper()
	reg := jobs.NewRegistry()
	err := anchor.Register(reg, anchor.Deps{
		Repo: h.repos, Stamper: anchor.NewClient(tsa.URL, "", 2*time.Second), TSAURL: tsa.URL, Timeout: 2 * time.Second,
		Backoff: func(int) time.Duration { return 50 * time.Millisecond },
	})
	if err != nil {
		h.t.Fatal(err)
	}
	q, err := jobs.NewQueue(h.pool, reg, jobs.Config{Workers: 2})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = q.Stop(ctx)
	})
	return pipeline.NewDBRepo(h.pool).WithAnchor(q)
}

// processingAsset creates an asset and walks it to processing, as the worker would find it.
func (h *harness) processingAsset(res auth.BootstrapResult, mask bool) db.Asset {
	h.t.Helper()
	ctx := context.Background()
	if err := h.signing.EnsureCurrent(ctx); err != nil {
		h.t.Fatal(err)
	}
	a, err := h.repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: res.Tenant.ID, ClientID: res.Client.ID, SizeBytes: 1000, Method: db.UploadTus,
		SourceKey: "test-fixture-source-" + id.New[id.AssetKind]().String(), ExpiresAt: time.Now().Add(time.Hour).UTC(), MaskFaces: mask,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	for _, next := range []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing} {
		if a, err = h.repos.TransitionAsset(ctx, res.Tenant.ID, a.ID, db.Transition{From: a.State, To: next}); err != nil {
			h.t.Fatal(err)
		}
	}
	return a
}

// sealed signs a canonical manifest the way the pipeline does and returns the row to store.
func (h *harness) sealed(res auth.BootstrapResult, asset db.Asset, built *manifest.Built) db.AssetManifest {
	h.t.Helper()
	keyID, sig, err := h.signing.Sign(context.Background(), dsse.PAE(manifest.PayloadType, built.Canonical))
	if err != nil {
		h.t.Fatal(err)
	}
	enc, err := (&dsse.Envelope{
		PayloadType: manifest.PayloadType, Payload: built.Canonical, Signatures: []dsse.Signature{{KeyID: keyID, Sig: sig}},
	}).Encode()
	if err != nil {
		h.t.Fatal(err)
	}
	sum := sha256.Sum256(built.Canonical)
	return db.AssetManifest{AssetID: asset.ID, TenantID: res.Tenant.ID, KeyID: keyID, PayloadSHA256: sum[:], TopRoot: built.TopRoot[:], Envelope: enc}
}

func (h *harness) waitForToken(key, aid string) resp {
	h.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		r := h.do(key, "GET", "/v1/assets/"+aid+"/manifest/timestamp", nil)
		if r.status == 200 || time.Now().After(deadline) {
			return h.mustOK(r, 200)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// checkToken verifies the API's token the way an auditor would: offline, with the authority's CA.
func (h *harness) checkToken(key, aid string, tsa *tsatest.TSA, payload []byte) (offline.TimestampDoc, time.Time) {
	h.t.Helper()
	env := h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/manifest", nil), 200).raw
	doc, err := offline.ParseTimestamp(h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/manifest/timestamp", nil), 200).raw)
	if err != nil {
		h.t.Fatal(err)
	}
	gen, err := offline.VerifyTimestamp(env, *doc, tsa.Roots)
	if err != nil {
		h.t.Fatalf("the token does not verify offline: %v", err)
	}
	sum := sha256.Sum256(payload)
	if doc.ImprintSHA256 != hex.EncodeToString(sum[:]) || doc.TSAURL != tsa.URL || !gen.Equal(doc.GenTime) {
		h.t.Fatalf("document does not describe the token: %+v", doc)
	}
	return *doc, gen
}

func TestAnchoringRoundTrip(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	tsa := tsatest.New(t)
	repo := h.startAnchoring(tsa)
	ctx := context.Background()

	asset := h.processingAsset(res, true)
	aid := asset.ID.String()
	renditions, master := ladder("")
	built, err := manifest.Build(manifest.Input{
		AssetID: aid, TenantID: res.Tenant.ID.String(), CreatedAt: time.Now(), PipelineVersion: "v0",
		Encoder:    manifest.Encoder{FFmpeg: "ffmpeg", VideoCodec: "libx264", Preset: "medium", FrameRate: "25/1", SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128"},
		Renditions: renditions, Master: master, SourceSHA256: sha256.Sum256([]byte("src")), SourceSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	row := h.sealed(res, asset, built)
	if _, err := repo.Complete(ctx, res.Tenant.ID, asset.ID, nil, db.Completion{
		Duration: time.Second, Renditions: []byte(`[{"name":"360p"}]`), Manifest: &row, At: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// The job stamps the payload; the manifest endpoint is untouched by it.
	h.waitForToken(key, aid)
	first, _ := h.checkToken(key, aid, tsa, built.Canonical)
	stored, err := h.repos.GetManifest(ctx, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env := h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/manifest", nil), 200).raw; !bytes.Equal(env, stored.Envelope) {
		t.Fatal("the manifest endpoint no longer returns the stored envelope byte for byte")
	}

	// Masking re-signs: the old token goes with the old row, and the new payload is anchored. The
	// authority is down for the first attempt, so the unanchored state is observable.
	tsa.SetMode(tsatest.ServerError)
	mb, err := manifest.WithMasked(built.Manifest, manifest.MaskedInput{
		CreatedAt: time.Now(), FacesDetected: 2, Frames: 10, Rungs: []manifest.Rung{{Name: "360p"}, {Name: "720p"}},
		Renditions: renditions, Master: master,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteMasking(ctx, res.Tenant.ID, asset.ID, nil, h.sealed(res, asset, mb), 2, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+aid+"/manifest/timestamp", nil), 404, "not_anchored")
	tsa.SetMode(tsatest.Grant)
	h.waitForToken(key, aid)
	second, _ := h.checkToken(key, aid, tsa, mb.Canonical)
	if second.Token == first.Token || second.ImprintSHA256 == first.ImprintSHA256 {
		t.Fatal("the masked manifest kept the old token")
	}
}

func TestAnchoringAuthorityDownLeavesAssetReady(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	tsa := tsatest.New(t)
	tsa.SetMode(tsatest.ServerError)
	repo := h.startAnchoring(tsa)

	asset := h.processingAsset(res, false)
	aid := asset.ID.String()
	renditions, master := ladder("")
	built, err := manifest.Build(manifest.Input{
		AssetID: aid, TenantID: res.Tenant.ID.String(), CreatedAt: time.Now(), PipelineVersion: "v0",
		Encoder:    manifest.Encoder{FFmpeg: "ffmpeg", VideoCodec: "libx264", Preset: "medium", FrameRate: "25/1", SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128"},
		Renditions: renditions, Master: master, SourceSHA256: sha256.Sum256([]byte("src")), SourceSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	row := h.sealed(res, asset, built)
	if _, err := repo.Complete(context.Background(), res.Tenant.ID, asset.ID, nil, db.Completion{
		Duration: time.Second, Renditions: []byte(`[{"name":"360p"}]`), Manifest: &row, At: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// The job keeps retrying, and the asset and its manifest are served meanwhile.
	deadline := time.Now().Add(30 * time.Second)
	for tsa.Calls() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the job retried %d times, want at least 3", tsa.Calls())
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+aid+"/manifest/timestamp", nil), 404, "not_anchored")
	h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/manifest", nil), 200)
	if got, err := h.repos.GetAsset(context.Background(), res.Tenant.ID, asset.ID); err != nil || got.State != db.AssetReady {
		t.Fatalf("the asset is %q (%v), want ready", got.State, err)
	}

	// Once the authority is back, a retry anchors the manifest.
	tsa.SetMode(tsatest.Grant)
	h.waitForToken(key, aid)
	h.checkToken(key, aid, tsa, built.Canonical)
}

func TestAnchoringNotConfiguredIsNotAnchored(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset, _ := h.readyAssetWithManifest(res, false)
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+asset.ID.String()+"/manifest/timestamp", nil), 404, "not_anchored")
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+id.New[id.AssetKind]().String()+"/manifest/timestamp", nil), 404, "not_found")
}
