//go:build integration

package contract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
)

// TestIntegrityOperationsMatchSpec exercises the manifest, proof and verify operations against a
// real database and validates every request and response against the spec.
func TestIntegrityOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	ctx := context.Background()
	pool := dbtest.NewMigrated(t)
	repos := db.New(pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lp, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := kms.NewRegistry(lp)
	if err != nil {
		t.Fatal(err)
	}
	signer := signing.NewManager(pool, reg, log)
	t.Cleanup(signer.Close)
	if err := signer.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	am := auth.NewManager(pool, onePepper{}, nil)
	res, err := am.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.New(api.Deps{
		Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: am, Signing: signer,
		KeySet: signing.NewKeySet(repos, 1, nil), Repos: repos,
	}).Handler())
	t.Cleanup(srv.Close)

	// A ready asset with a one-rendition manifest, signed by the real current key.
	a, err := repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: res.Tenant.ID, ClientID: res.Client.ID, SizeBytes: 1, Method: db.UploadTus,
		SourceKey: "test-fixture-source", ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing, db.AssetReady} {
		if a, err = repos.TransitionAsset(ctx, res.Tenant.ID, a.ID, db.Transition{From: a.State, To: next}); err != nil {
			t.Fatal(err)
		}
	}
	obj := func(path, seed string) manifest.StoredObject {
		return manifest.StoredObject{Path: path, SHA256: sha256.Sum256([]byte(seed)), Size: int64(len(seed))}
	}
	seg := obj("720p/seg-0.m4s", "seg0")
	built, err := manifest.Build(manifest.Input{
		AssetID: a.ID.String(), TenantID: res.Tenant.ID.String(), CreatedAt: time.Now(), PipelineVersion: "v0",
		Encoder: manifest.Encoder{FFmpeg: "ffmpeg", VideoCodec: "libx264", Preset: "medium", FrameRate: "25/1", SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128"},
		Renditions: []manifest.RenditionInput{{
			Name: "720p", Width: 1280, Height: 720, Bandwidth: 1000, Init: obj("720p/init.mp4", "init"),
			Segments: []manifest.StoredObject{seg, obj("720p/seg-1.m4s", "seg1")}, Playlist: obj("720p/playlist.m3u8", "pl"),
		}},
		Master: obj("master.m3u8", "master"), SourceSHA256: sha256.Sum256([]byte("src")), SourceSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyID, sig, err := signer.Sign(ctx, dsse.PAE(manifest.PayloadType, built.Canonical))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := (&dsse.Envelope{PayloadType: manifest.PayloadType, Payload: built.Canonical, Signatures: []dsse.Signature{{KeyID: keyID, Sig: sig}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(built.Canonical)
	if err := repos.InsertManifest(ctx, db.AssetManifest{
		AssetID: a.ID, TenantID: res.Tenant.ID, KeyID: keyID, PayloadSHA256: sum[:], TopRoot: built.TopRoot[:], Envelope: enc,
	}); err != nil {
		t.Fatal(err)
	}

	hdr := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	covered := map[string]bool{}
	call := func(method, path string, body any, wantStatus int) []byte {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		ex := doBody(t, srv.URL, method, path, hdr, raw)
		if ex.resp.StatusCode != wantStatus {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, ex.resp.StatusCode, wantStatus, ex.body)
		}
		if op := validate(t, doc, ex); op != "" {
			covered[op] = true
		}
		return ex.body
	}

	aid := a.ID.String()
	call("GET", "/v1/assets/"+aid+"/manifest", nil, 200)
	call("GET", "/v1/assets/"+aid+"/manifest", nil, 200)
	call("GET", "/v1/assets/ast_00000000000000000000000001/manifest", nil, 404)
	call("GET", "/v1/assets/"+aid+"/proof?path=720p/seg-1.m4s", nil, 200)
	call("GET", "/v1/assets/"+aid+"/proof?path=master.m3u8&variant=original", nil, 200)
	call("GET", "/v1/assets/"+aid+"/proof?path=nope", nil, 404)
	call("GET", "/v1/assets/"+aid+"/proof?path=master.m3u8&variant=masked", nil, 409)

	hash := hex.EncodeToString(seg.SHA256[:])
	var v struct{ Outcome string }
	for want, body := range map[string]map[string]any{
		"ours":     {"asset_id": aid, "path": seg.Path, "sha256": hash},
		"modified": {"asset_id": aid, "path": seg.Path, "sha256": hex.EncodeToString(make([]byte, 32))},
		"cannot_say": {
			"sha256": hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		},
	} {
		if err := json.Unmarshal(call("POST", "/v1/verify", body, 200), &v); err != nil || v.Outcome != want {
			t.Fatalf("outcome = %q, want %q (%v)", v.Outcome, want, err)
		}
	}
	call("POST", "/v1/verify", map[string]any{"sha256": hash}, 200)
	call("POST", "/v1/verify", map[string]any{"sha256": hash, "asset_id": aid}, 400)

	for _, op := range []string{"getAssetManifest", "getAssetProof", "verifyArtifact"} {
		if !covered[op] {
			t.Errorf("operation %s was not exercised", op)
		}
	}
}
