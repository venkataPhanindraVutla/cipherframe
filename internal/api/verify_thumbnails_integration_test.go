//go:build integration

package api_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
)

// A thumbnail object is signed by hash, per variant, and in no Merkle tree: verify answers ours or
// modified with no proof, the proof endpoint has nothing for it, and the original's poster never
// verifies as the masked variant's (ADR 0046).
func TestThumbnailsVerifyByPath(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset, _ := h.readyAssetWithManifest(res, true)
	aid := asset.ID.String()

	thumbs := func(tag string) []manifest.Thumbnail {
		return []manifest.Thumbnail{
			{Kind: manifest.KindPoster, Object: fobj("poster.jpg", tag+"poster")},
			{Kind: manifest.KindSprite, Object: fobj("sprite.jpg", tag+"sprite")},
			{Kind: manifest.KindThumbnails, Object: fobj("thumbnails.vtt", tag+"track")},
		}
	}
	renditions, master := ladder("")
	built, err := manifest.Build(manifest.Input{
		AssetID: aid, TenantID: res.Tenant.ID.String(), CreatedAt: time.Now(), PipelineVersion: "v0",
		Encoder:    manifest.Encoder{FFmpeg: "ffmpeg", VideoCodec: "libx264", Preset: "medium", FrameRate: "25/1", SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128"},
		Renditions: renditions, Master: master, Thumbnails: thumbs("o-"), SourceSHA256: sha256.Sum256([]byte("src")), SourceSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	mRenditions, mMaster := ladder("m-")
	withMasked, err := manifest.WithMasked(built.Manifest, manifest.MaskedInput{
		CreatedAt: time.Now(), FacesDetected: 2, Frames: 10, Rungs: []manifest.Rung{{Name: "360p"}, {Name: "720p"}},
		Renditions: mRenditions, Master: mMaster, Thumbnails: thumbs("m-"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.sign(res, asset, withMasked, true)

	orig, masked := fobj("poster.jpg", "o-poster"), fobj("poster.jpg", "m-poster")
	for _, c := range []struct {
		variant string
		sum     string
		outcome string
	}{
		{"original", hexOf(orig), "ours"},
		{"masked", hexOf(masked), "ours"},
		{"masked", hexOf(orig), "modified"}, // the original's image is not the masked variant's
		{"original", hexOf(masked), "modified"},
	} {
		r := h.mustOK(h.do(key, "POST", "/v1/verify", map[string]any{"asset_id": aid, "path": "poster.jpg", "variant": c.variant, "sha256": c.sum}), 200)
		if r.m["outcome"] != c.outcome || r.m["proof"] != nil {
			t.Errorf("%s %s: %s", c.variant, c.sum[:8], r.raw)
		}
	}
	track := hexOf(fobj("thumbnails.vtt", "o-track"))
	if r := h.mustOK(h.do(key, "POST", "/v1/verify", map[string]any{"asset_id": aid, "path": "thumbnails.vtt", "sha256": track}), 200); r.m["outcome"] != "ours" {
		t.Errorf("track: %s", r.raw)
	}
	// There is no tree to prove it in.
	h.wantStatus(h.do(key, "GET", "/v1/assets/"+aid+"/proof?path=poster.jpg", nil), 404, "artifact_not_found")
}
