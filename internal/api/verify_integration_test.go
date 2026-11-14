//go:build integration

package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/proof"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

func fobj(path, seed string) manifest.StoredObject {
	return manifest.StoredObject{Path: path, SHA256: sha256.Sum256([]byte(seed)), Size: int64(len(seed))}
}

// ladder is a two-rendition ladder with three and four segments, so both levels have real paths.
func ladder(tag string) ([]manifest.RenditionInput, manifest.StoredObject) {
	var out []manifest.RenditionInput
	for i, name := range []string{"360p", "720p"} {
		r := manifest.RenditionInput{
			Name: name, Width: 640 * (i + 1), Height: 360 * (i + 1), Bandwidth: 1000,
			Init: fobj(name+"/init.mp4", tag+name+"init"), Playlist: fobj(name+"/playlist.m3u8", tag+name+"pl"),
		}
		for j := range 3 + i {
			r.Segments = append(r.Segments, fobj(fmt.Sprintf("%s/seg-%d.m4s", name, j), fmt.Sprintf("%s%sseg%d", tag, name, j)))
		}
		out = append(out, r)
	}
	return out, fobj("master.m3u8", tag+"master")
}

// register records the HLS objects of one variant in the artifact registry, as the pipeline does.
func (h *harness) register(res auth.BootstrapResult, asset db.Asset, variant keys.Variant, renditions []manifest.RenditionInput, master manifest.StoredObject) {
	h.t.Helper()
	prefix := keys.VariantHLSPrefix(res.Tenant.ID, asset.ID, variant)
	rec := func(kind db.ArtifactKind, rendition string, o manifest.StoredObject) {
		err := h.repos.RecordArtifact(context.Background(), db.Artifact{
			AssetID: asset.ID, Kind: kind, Rendition: rendition, Bucket: "delivery", ObjectKey: prefix + o.Path,
			SizeBytes: o.Size, SHA256: o.SHA256[:], Variant: variant.String(),
		})
		if err != nil {
			h.t.Fatal(err)
		}
	}
	rec(db.ArtifactMaster, "", master)
	for _, r := range renditions {
		rec(db.ArtifactPlaylist, r.Name, r.Playlist)
		rec(db.ArtifactInit, r.Name, r.Init)
		for _, s := range r.Segments {
			rec(db.ArtifactSegment, r.Name, s)
		}
	}
}

// sign wraps a canonical manifest in an envelope signed by the current key and stores it.
func (h *harness) sign(res auth.BootstrapResult, asset db.Asset, built *manifest.Built, replace bool) db.AssetManifest {
	h.t.Helper()
	ctx := context.Background()
	keyID, sig, err := h.signing.Sign(ctx, dsse.PAE(manifest.PayloadType, built.Canonical))
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
	row := db.AssetManifest{
		AssetID: asset.ID, TenantID: res.Tenant.ID, KeyID: keyID, PayloadSHA256: sum[:], TopRoot: built.TopRoot[:], Envelope: enc,
	}
	if replace {
		if _, err := h.repos.DeleteManifest(ctx, asset.ID); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := h.repos.InsertManifest(ctx, row); err != nil {
		h.t.Fatal(err)
	}
	stored, err := h.repos.GetManifest(ctx, asset.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	return stored
}

// readyAssetWithManifest creates a ready asset with an original variant, its registry rows and its
// signed manifest. With mask the asset was created with mask_faces and has no masked section yet.
func (h *harness) readyAssetWithManifest(res auth.BootstrapResult, mask bool) (db.Asset, *manifest.Built) {
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
	for _, next := range []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing, db.AssetReady} {
		if a, err = h.repos.TransitionAsset(ctx, res.Tenant.ID, a.ID, db.Transition{From: a.State, To: next}); err != nil {
			h.t.Fatal(err)
		}
	}
	renditions, master := ladder("")
	built, err := manifest.Build(manifest.Input{
		AssetID: a.ID.String(), TenantID: res.Tenant.ID.String(), CreatedAt: time.Now(), PipelineVersion: "v0",
		Encoder:    manifest.Encoder{FFmpeg: "ffmpeg", VideoCodec: "libx264", Preset: "medium", FrameRate: "25/1", SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128"},
		Renditions: renditions, Master: master, SourceSHA256: sha256.Sum256([]byte("src")), SourceSize: 3,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.register(res, a, keys.Original, renditions, master)
	h.sign(res, a, built, false)
	return a, built
}

func (h *harness) addMasked(res auth.BootstrapResult, a db.Asset, built *manifest.Built) *manifest.Built {
	h.t.Helper()
	renditions, master := ladder("m-")
	mb, err := manifest.WithMasked(built.Manifest, manifest.MaskedInput{
		CreatedAt: time.Now(), FacesDetected: 2, Frames: 10, Rungs: []manifest.Rung{{Name: "360p"}, {Name: "720p"}},
		Renditions: renditions, Master: master,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.register(res, a, keys.Masked, renditions, master)
	h.sign(res, a, mb, true)
	return mb
}

func hexOf(o manifest.StoredObject) string { return hex.EncodeToString(o.SHA256[:]) }

func proofOf(t *testing.T, r resp) proof.Proof {
	t.Helper()
	var p proof.Proof
	if err := json.Unmarshal(r.raw, &p); err != nil {
		t.Fatalf("proof: %v: %s", err, r.raw)
	}
	return p
}

func TestManifestProofAndVerify(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset, built := h.readyAssetWithManifest(res, false)
	aid := asset.ID.String()
	ctx := context.Background()

	// The manifest is the stored envelope, byte for byte, with the documented content type.
	stored, err := h.repos.GetManifest(ctx, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	mr := h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/manifest", nil), 200)
	if !bytes.Equal(mr.raw, stored.Envelope) {
		t.Fatalf("manifest differs from the stored envelope:\n%s\n%s", mr.raw, stored.Envelope)
	}
	if ct := mr.hdr.Get("Content-Type"); ct != "application/vnd.cipherframe.manifest+json; profile=dsse" {
		t.Fatalf("content type = %q", ct)
	}
	env, err := dsse.Decode(mr.raw)
	if err != nil || !bytes.Equal(env.Payload, built.Canonical) {
		t.Fatalf("envelope does not carry the manifest: %v", err)
	}

	// Proofs: every kind of artifact verifies against the hash, and their roots are the signed one.
	renditions, master := ladder("")
	cases := map[string]manifest.StoredObject{
		"master.m3u8": master, "720p/playlist.m3u8": renditions[1].Playlist,
		"360p/init.mp4": renditions[0].Init, "720p/seg-3.m4s": renditions[1].Segments[3],
	}
	for path, o := range cases {
		r := h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path="+path, nil), 200)
		p := proofOf(t, r)
		if p.Path != path || p.Variant != "original" || p.AssetID != aid || p.SHA256 != hexOf(o) || p.TopLevel.Root != built.Manifest.TopLevel.Root {
			t.Fatalf("%s: proof = %s", path, r.raw)
		}
		if err := proof.Verify(p, o.SHA256); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if isPlaylist := strings.Contains(path, "m3u8"); isPlaylist == (p.RenditionRoot != "") {
			t.Fatalf("%s: rendition level present = %v", path, p.RenditionRoot != "")
		}
	}
	// The explicit default variant works too; bad inputs are refused.
	h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path=master.m3u8&variant=original", nil), 200)
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path=nope.m4s", nil), 404, "artifact_not_found")
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+aid+"/proof", nil), 400, "invalid_request")
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path=master.m3u8&variant=x", nil), 400, "invalid_request")
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path=master.m3u8&variant=masked", nil), 409, "variant_unavailable")
	h.wantStatus(h.do(key, "GET", "/v1/assets/ast_00000000000000000000000001/proof?path=master.m3u8", nil), 404, "not_found")
	h.wantStatus(h.do(key, "GET", "/v1/assets/nope/manifest", nil), 404, "not_found")

	// Verify with asset and path: ours (with the proof), modified, and cannot_say.
	seg := renditions[0].Segments[1]
	body := func(m map[string]any) resp { return h.mustOK(h.do(key, "POST", "/v1/verify", m), 200) }
	ours := body(map[string]any{"asset_id": aid, "path": "360p/seg-1.m4s", "sha256": hexOf(seg)})
	if ours.m["outcome"] != "ours" || ours.m["asset_id"] != aid || ours.m["variant"] != "original" || ours.m["path"] != "360p/seg-1.m4s" || ours.m["proof"] == nil {
		t.Fatalf("ours = %s", ours.raw)
	}
	var vr struct {
		Proof proof.Proof `json:"proof"`
	}
	if err := json.Unmarshal(ours.raw, &vr); err != nil || proof.Verify(vr.Proof, seg.SHA256) != nil {
		t.Fatalf("the proof in the verdict does not verify: %v", err)
	}
	other := hexOf(fobj("x", "something else"))
	mod := body(map[string]any{"asset_id": aid, "path": "360p/seg-1.m4s", "sha256": other})
	if mod.m["outcome"] != "modified" || mod.m["proof"] != nil || mod.m["path"] != "360p/seg-1.m4s" {
		t.Fatalf("modified = %s", mod.raw)
	}
	for name, m := range map[string]map[string]any{
		"unknown path":    {"asset_id": aid, "path": "360p/seg-9.m4s", "sha256": other},
		"unknown asset":   {"asset_id": "ast_00000000000000000000000001", "path": "master.m3u8", "sha256": other},
		"malformed asset": {"asset_id": "nope", "path": "master.m3u8", "sha256": other},
		"masked, absent":  {"asset_id": aid, "path": "master.m3u8", "variant": "masked", "sha256": other},
	} {
		r := body(m)
		if r.m["outcome"] != "cannot_say" || r.m["reason"] != "no_match" || r.m["proof"] != nil {
			t.Fatalf("%s: %s", name, r.raw)
		}
	}

	// Hash only: where the hash belongs, as a manifest path (never a storage key), or cannot_say.
	by := body(map[string]any{"sha256": hexOf(renditions[1].Segments[2])})
	if by.m["outcome"] != "ours" || by.m["asset_id"] != aid || by.m["variant"] != "original" || by.m["path"] != "720p/seg-2.m4s" || by.m["proof"] == nil {
		t.Fatalf("by hash = %s", by.raw)
	}
	if strings.Contains(string(by.raw), "t/ten_") || strings.Contains(string(by.raw), "delivery") {
		t.Fatalf("the answer leaks a storage key: %s", by.raw)
	}
	if r := body(map[string]any{"sha256": other}); r.m["outcome"] != "cannot_say" || r.m["reason"] != "no_match" {
		t.Fatalf("unknown hash = %s", r.raw)
	}

	// Validation.
	for name, m := range map[string]map[string]any{
		"upper case":    {"sha256": strings.ToUpper(other)},
		"short":         {"sha256": "abcd"},
		"missing":       {},
		"asset only":    {"sha256": other, "asset_id": aid},
		"path only":     {"sha256": other, "path": "master.m3u8"},
		"variant alone": {"sha256": other, "variant": "masked"},
		"bad variant":   {"sha256": other, "asset_id": aid, "path": "master.m3u8", "variant": "x"},
	} {
		if r := h.do(key, "POST", "/v1/verify", m); r.status != 400 || r.code() != "invalid_request" {
			t.Fatalf("%s: %d %s", name, r.status, r.raw)
		}
	}
	h.wantStatus(h.do(key, "POST", "/v1/verify", nil), 400, "invalid_request")
}

func TestVerifyRefusesAManifestThatDoesNotVerify(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset, _ := h.readyAssetWithManifest(res, false)
	renditions, _ := ladder("")
	hash := hexOf(renditions[0].Init)
	req := map[string]any{"asset_id": asset.ID.String(), "path": "360p/init.mp4", "sha256": hash}
	h.mustOK(h.do(key, "POST", "/v1/verify", req), 200)

	// Corrupt the stored signature: the manifest can no longer be trusted, so the answer is
	// cannot_say (never ours, never modified) and the server logs an error.
	stored, err := h.repos.GetManifest(context.Background(), asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(stored.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	env["signatures"].([]any)[0].(map[string]any)["sig"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
	bad, _ := json.Marshal(env)
	if _, err := h.pool.Exec(context.Background(), "UPDATE asset_manifests SET envelope = $1 WHERE asset_id = $2", bad, asset.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]map[string]any{"by path": req, "by hash": {"sha256": hash}} {
		r := h.mustOK(h.do(key, "POST", "/v1/verify", m), 200)
		if r.m["outcome"] != "cannot_say" || r.m["reason"] != "manifest_unverifiable" || r.m["proof"] != nil {
			t.Fatalf("%s: %s", name, r.raw)
		}
	}
	if !strings.Contains(h.logs.String(), `"level":"ERROR"`) || !strings.Contains(h.logs.String(), "stored manifest failed verification") {
		t.Fatal("the failed verification was not logged as an error")
	}
}

func TestMaskedProofsAndVerify(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset, built := h.readyAssetWithManifest(res, true)
	aid := asset.ID.String()

	// Created with mask_faces but not published yet: variant_not_ready, and verify cannot say.
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path=master.m3u8&variant=masked", nil), 409, "variant_not_ready")
	renditions, master := ladder("m-")
	if r := h.mustOK(h.do(key, "POST", "/v1/verify", map[string]any{"asset_id": aid, "path": "master.m3u8", "variant": "masked", "sha256": hexOf(master)}), 200); r.m["outcome"] != "cannot_say" {
		t.Fatalf("masked before publish = %s", r.raw)
	}

	mb := h.addMasked(res, asset, built)
	seg := renditions[1].Segments[2]
	r := h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path=720p/seg-2.m4s&variant=masked", nil), 200)
	p := proofOf(t, r)
	if p.Variant != "masked" || p.SHA256 != hexOf(seg) || p.TopLevel.Root != mb.Manifest.Masked.TopLevel.Root {
		t.Fatalf("masked proof = %s", r.raw)
	}
	if err := proof.Verify(p, seg.SHA256); err != nil {
		t.Fatal(err)
	}
	// The same path in the original variant has another hash and root.
	po := proofOf(t, h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path=720p/seg-2.m4s", nil), 200))
	if po.SHA256 == p.SHA256 || po.TopLevel.Root == p.TopLevel.Root {
		t.Fatal("the variants share a hash or a root")
	}
	// Verify: the masked hash is ours under masked, modified under original.
	req := map[string]any{"asset_id": aid, "path": "720p/seg-2.m4s", "sha256": hexOf(seg)}
	if r := h.mustOK(h.do(key, "POST", "/v1/verify", req), 200); r.m["outcome"] != "modified" {
		t.Fatalf("masked hash against the original = %s", r.raw)
	}
	req["variant"] = "masked"
	if r := h.mustOK(h.do(key, "POST", "/v1/verify", req), 200); r.m["outcome"] != "ours" || r.m["variant"] != "masked" {
		t.Fatalf("masked hash against masked = %s", r.raw)
	}
	// Hash only finds the masked variant, with the path relative to the masked prefix.
	by := h.mustOK(h.do(key, "POST", "/v1/verify", map[string]any{"sha256": hexOf(seg)}), 200)
	if by.m["outcome"] != "ours" || by.m["variant"] != "masked" || by.m["path"] != "720p/seg-2.m4s" {
		t.Fatalf("by hash = %s", by.raw)
	}
	// The envelope served now carries the masked section.
	env, err := dsse.Decode(h.mustOK(h.do(key, "GET", "/v1/assets/"+aid+"/manifest", nil), 200).raw)
	if err != nil || !bytes.Contains(env.Payload, []byte(`"masked":{`)) {
		t.Fatalf("manifest without the masked section: %v", err)
	}
}

func TestIntegrityEndpointsAreTenantScoped(t *testing.T) {
	h := newHarness(t)
	_, acme := h.bootstrap("acme")
	other, _ := h.bootstrap("globex")
	asset, _ := h.readyAssetWithManifest(acme, false)
	aid := asset.ID.String()
	renditions, _ := ladder("")
	hash := hexOf(renditions[0].Segments[0])

	h.wantStatus(h.do(other, "GET", "/v1/assets/"+aid+"/manifest", nil), 404, "not_found")
	h.wantStatus(h.do(other, "GET", "/v1/assets/"+aid+"/proof?path=360p/seg-0.m4s", nil), 404, "not_found")
	for _, m := range []map[string]any{
		{"asset_id": aid, "path": "360p/seg-0.m4s", "sha256": hash},
		{"sha256": hash},
	} {
		r := h.mustOK(h.do(other, "POST", "/v1/verify", m), 200)
		if r.m["outcome"] != "cannot_say" || r.m["asset_id"] != nil || r.m["proof"] != nil {
			t.Fatalf("another tenant's answer = %s", r.raw)
		}
	}
}

func TestIntegrityEndpointsNeedAssetsRead(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")
	asset, _ := h.readyAssetWithManifest(res, false)
	aid := asset.ID.String()
	cli := h.newClient(admin, "svc")
	weak := str(h.newKey(admin, cli, "sessions", []string{"sessions:write"}).m, "key")
	sum := hexOf(fobj("x", "x"))
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/assets/" + aid + "/manifest", nil},
		{"GET", "/v1/assets/" + aid + "/proof?path=master.m3u8", nil},
		{"POST", "/v1/verify", map[string]any{"sha256": sum}},
	} {
		h.wantStatus(h.do(weak, c.method, c.path, c.body), http.StatusForbidden, "forbidden")
		h.wantStatus(h.do("", c.method, c.path, c.body), http.StatusUnauthorized, "unauthenticated")
	}
}

func TestManifestIs404UntilTheAssetIsReady(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	processing := h.newAsset(res, db.AssetProcessing)
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+processing.ID.String()+"/manifest", nil), 404, "not_found")
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+processing.ID.String()+"/proof?path=master.m3u8", nil), 404, "not_found")
	ready := h.newAsset(res, db.AssetReady) // ready, but no manifest row
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+ready.ID.String()+"/manifest", nil), 404, "not_found")
}
