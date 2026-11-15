//go:build integration && media

package pipeline_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/color"
	_ "image/jpeg"
	"image/png"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/branding"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// The brand logo end to end (M7-4, ADR 0049): uploaded through the branding service, pinned by the
// worker, drawn by the real FFmpeg, recorded in the signed manifest. The tests read pixels back out
// of the stored, encrypted segments.

var (
	magenta = color.NRGBA{R: 255, B: 255, A: 255}
	yellow  = color.NRGBA{R: 255, G: 255, A: 255}
)

func (r *rig) brand() *branding.Service {
	r.t.Helper()
	svc, err := branding.New(branding.Deps{Pool: r.pool, Delivery: r.buckets.Delivery})
	if err != nil {
		r.t.Fatal(err)
	}
	return svc
}

func logoPNG(t *testing.T, c color.NRGBA) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 96, 48))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func (r *rig) putLogo(svc *branding.Service, c color.NRGBA, corner string, opacity int) db.TenantLogo {
	r.t.Helper()
	l, err := svc.Put(context.Background(), r.tenant.ID, auth.Actor{}, logoPNG(r.t, c), branding.Placement{Corner: &corner, Opacity: &opacity})
	if err != nil {
		r.t.Fatal(err)
	}
	return l
}

// frame decodes the first frame of a stored rendition of one variant.
func (r *rig) frame(a db.Asset, variant keys.Variant, rendition string) image.Image {
	r.t.Helper()
	name, _ := keys.ParseRendition(rendition)
	key := r.key(a)
	if variant == keys.Masked {
		key = r.maskedKey(a)
	}
	pl := parsePlaylist(r.t, string(r.get(r.buckets.Delivery, keys.VariantPlaylist(a.TenantID, a.ID, variant, name))))
	body, err := hls.DecryptSegment(key, pl.ivs[0], r.get(r.buckets.Delivery, keys.VariantSegment(a.TenantID, a.ID, variant, name, 0)))
	if err != nil {
		r.t.Fatal(err)
	}
	dir := r.t.TempDir()
	frag := filepath.Join(dir, "frag.mp4")
	if err := os.WriteFile(frag, append(r.get(r.buckets.Delivery, keys.VariantInitSegment(a.TenantID, a.ID, variant, name)), body...), 0o600); err != nil {
		r.t.Fatal(err)
	}
	jpg := filepath.Join(dir, "f.jpg")
	cmd := exec.CommandContext(context.Background(), r.tools.FFmpeg, "-hide_banner", "-nostdin", "-v", "error", "-i", "file:"+frag, //nolint:gosec // test: argument array
		"-vf", "format=yuvj420p", "-frames:v", "1", "-q:v", "1", "-update", "1", "-f", "image2", "-c:v", "mjpeg", "file:"+jpg)
	cmd.Env = []string{"LC_ALL=C"}
	if out, err := cmd.CombinedOutput(); err != nil {
		r.t.Fatalf("ffmpeg: %v\n%s", err, out)
	}
	b, err := os.ReadFile(jpg) //nolint:gosec // test reads its own temp dir
	if err != nil {
		r.t.Fatal(err)
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		r.t.Fatal(err)
	}
	return img
}

// at is the mean colour of the 6 x 6 pixels at the centre of the logo's rectangle for a corner.
func at(img image.Image, w, h int, corner string, logo *media.LogoSpec) [3]float64 {
	l := *logo
	l.Corner = corner
	p := l.Place(w, h)
	cx, cy := p.X+p.Width/2, p.Y+p.Height/2
	var sum [3]float64
	for y := cy - 3; y < cy+3; y++ {
		for x := cx - 3; x < cx+3; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			sum[0] += float64(r >> 8)
			sum[1] += float64(g >> 8)
			sum[2] += float64(b >> 8)
		}
	}
	return [3]float64{sum[0] / 36, sum[1] / 36, sum[2] / 36}
}

func near(a, b [3]float64, tol float64) bool {
	for i := range a {
		if math.Abs(a[i]-b[i]) > tol {
			return false
		}
	}
	return true
}

// the logo spec the pipeline hands FFmpeg for the test logo, for Place.
var testLogoSpec = &media.LogoSpec{Width: 96, Height: 48}

func decodedManifest(t *testing.T, r *rig, a db.Asset) manifest.Manifest {
	t.Helper()
	row, err := r.repos.GetManifest(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	m, err := pipeline.DecodeManifest(row.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func snapshotOf(r *rig, a db.Asset) map[string]string {
	return r.snapshot(keys.DeliveryPrefix(a.TenantID, a.ID))
}

var source720 = testmedia.Spec{Name: "source.mp4", Width: 1280, Height: 720, Duration: 4 * time.Second, FPS: 30}

func TestLogoEndToEnd(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	svc := r.brand()
	logo := r.putLogo(svc, magenta, db.CornerTopRight, 100)

	a, sum := r.commit(generate(t, source720))
	if err := r.process(a); err != nil {
		t.Fatalf("process: %v\n%s", err, r.logs.String())
	}
	a, err := r.repos.GetAsset(ctx, a.TenantID, a.ID)
	if err != nil || a.State != db.AssetReady {
		t.Fatalf("asset = %+v, %v", a, err)
	}

	// The manifest records the logo, and still passes every check a manifest without one passes.
	m := decodedManifest(t, r, a)
	want := manifest.Logo{SHA256: hex.EncodeToString(logo.SHA256), Version: logo.ID.String(), Corner: "top_right", OpacityPercent: 100, WidthPercent: 15}
	if m.Encoder.Logo == nil || *m.Encoder.Logo != want {
		t.Fatalf("manifest logo = %+v, want %+v", m.Encoder.Logo, want)
	}
	if m.Source.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("the manifest does not carry the source hash")
	}
	// The stored envelope verifies against the published keys, logo and all.
	row, err := r.repos.GetManifest(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := r.signer.PublicKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ks := offline.KeySet{}
	for _, k := range pub {
		ks[k.KeyID] = k.PublicKey
	}
	if signed, err := offline.Open(row.Envelope, ks); err != nil || signed.Manifest.Encoder.Logo == nil {
		t.Fatalf("the manifest does not verify offline: %v", err)
	}

	// The pin names what the worker used, and the stored logo is the one that was hashed.
	pin, ok, err := r.repos.GetAssetLogoPin(ctx, a.TenantID, a.ID)
	if err != nil || !ok || pin.VersionID != logo.ID || !bytes.Equal(pin.SHA256, logo.SHA256) {
		t.Fatalf("pin = %+v %v %v", pin, ok, err)
	}
	if got := sha256.Sum256(r.get(r.buckets.Delivery, keys.BrandLogo(a.TenantID, logo.ID))); !bytes.Equal(got[:], logo.SHA256) {
		t.Error("the stored logo is not the one the manifest names")
	}

	// Every rung shows the logo in the top right corner, and not in the others.
	for _, rs := range summaryOf(t, a) {
		img := r.frame(a, keys.Original, rs.Name)
		if have := at(img, rs.Width, rs.Height, media.CornerTopRight, testLogoSpec); !near(have, [3]float64{255, 0, 255}, 40) {
			t.Errorf("%s: top right is %v, want magenta", rs.Name, have)
		}
		if have := at(img, rs.Width, rs.Height, media.CornerBottomLeft, testLogoSpec); near(have, [3]float64{255, 0, 255}, 100) {
			t.Errorf("%s: bottom left is %v, the logo is in the wrong corner", rs.Name, have)
		}
	}
	// The poster is cut from the same frames.
	poster, _, err := image.Decode(bytes.NewReader(r.get(r.buckets.Delivery, keys.VariantPoster(a.TenantID, a.ID, keys.Original))))
	if err != nil {
		t.Fatal(err)
	}
	if b := poster.Bounds(); !near(at(poster, b.Dx(), b.Dy(), media.CornerTopRight, testLogoSpec), [3]float64{255, 0, 255}, 40) {
		t.Error("the poster does not show the logo")
	}
	if strings.Contains(r.logs.String(), "branding/") {
		t.Error("a storage key reached the log")
	}
}

// A new, changed or removed logo applies to assets processed afterwards; an earlier asset keeps its
// segments, its manifest and its pin.
func TestChangedLogoDoesNotTouchEarlierAssets(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	svc := r.brand()
	first := r.putLogo(svc, magenta, db.CornerTopRight, 100)

	a1, _ := r.commit(generate(t, source720))
	if err := r.process(a1); err != nil {
		t.Fatalf("process 1: %v\n%s", err, r.logs.String())
	}
	before := snapshotOf(r, a1)
	manifestBefore, err := r.repos.GetManifest(ctx, a1.ID)
	if err != nil {
		t.Fatal(err)
	}

	second := r.putLogo(svc, yellow, db.CornerBottomLeft, 100)
	a2, _ := r.commit(generate(t, source720))
	if err := r.process(a2); err != nil {
		t.Fatalf("process 2: %v\n%s", err, r.logs.String())
	}
	if _, err := svc.Update(ctx, r.tenant.ID, auth.Actor{}, branding.Placement{Enabled: new(false)}); err != nil {
		t.Fatal(err)
	}
	a3, _ := r.commit(generate(t, source720))
	if err := r.process(a3); err != nil {
		t.Fatalf("process 3: %v\n%s", err, r.logs.String())
	}

	// Asset 1: nothing about it moved.
	after := snapshotOf(r, a1)
	if len(after) != len(before) {
		t.Fatalf("asset 1 has %d objects, had %d", len(after), len(before))
	}
	for k, h := range before {
		if after[k] != h {
			t.Errorf("asset 1: %s changed", k)
		}
	}
	manifestAfter, err := r.repos.GetManifest(ctx, a1.ID)
	if err != nil || !bytes.Equal(manifestAfter.Envelope, manifestBefore.Envelope) {
		t.Errorf("asset 1's manifest changed: %v", err)
	}
	if m := decodedManifest(t, r, a1); m.Encoder.Logo == nil || m.Encoder.Logo.Version != first.ID.String() || m.Encoder.Logo.Corner != "top_right" {
		t.Errorf("asset 1 manifest logo = %+v", m.Encoder.Logo)
	}
	p1, ok, err := r.repos.GetAssetLogoPin(ctx, r.tenant.ID, a1.ID)
	if err != nil || !ok || p1.VersionID != first.ID {
		t.Errorf("asset 1 pin = %+v %v %v", p1, ok, err)
	}

	// Asset 2 has the new logo, in the new corner, and the old version is gone from storage.
	if m := decodedManifest(t, r, a2); m.Encoder.Logo == nil || m.Encoder.Logo.Version != second.ID.String() || m.Encoder.Logo.Corner != "bottom_left" {
		t.Errorf("asset 2 manifest logo = %+v", m.Encoder.Logo)
	}
	a2, err = r.repos.GetAsset(ctx, a2.TenantID, a2.ID)
	if err != nil {
		t.Fatal(err)
	}
	rs := summaryOf(t, a2)[0]
	img2 := r.frame(a2, keys.Original, rs.Name)
	if have := at(img2, rs.Width, rs.Height, media.CornerBottomLeft, testLogoSpec); !near(have, [3]float64{255, 255, 0}, 40) {
		t.Errorf("asset 2 bottom left is %v, want yellow", have)
	}
	if _, _, err := r.buckets.Delivery.Get(ctx, keys.BrandLogo(r.tenant.ID, first.ID), nil); err == nil {
		t.Error("the first logo version is still stored although no asset needs it")
	}

	// Asset 3 was made while the logo was disabled: none in the manifest, none in the picture.
	m3 := decodedManifest(t, r, a3)
	if m3.Encoder.Logo != nil {
		t.Errorf("asset 3 manifest logo = %+v", m3.Encoder.Logo)
	}
	row3, _ := r.repos.GetManifest(ctx, a3.ID)
	if strings.Contains(string(row3.Envelope), "logo") {
		t.Error("the envelope of an asset without a logo mentions one")
	}
	img3 := r.frame(a3, keys.Original, rs.Name)
	for _, c := range []string{media.CornerTopRight, media.CornerBottomLeft} {
		have := at(img3, rs.Width, rs.Height, c, testLogoSpec)
		if near(have, [3]float64{255, 255, 0}, 60) || near(have, [3]float64{255, 0, 255}, 60) {
			t.Errorf("asset 3 shows a logo colour in %s: %v", c, have)
		}
	}
}

// An asset pinned when its first attempt started keeps that logo for the retry, although the tenant
// uploaded another one meanwhile and the old version would otherwise have been removed.
func TestRetryOfAPinnedAssetUsesTheSameLogoVersion(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	svc := r.brand()
	first := r.putLogo(svc, magenta, db.CornerTopRight, 100)

	a, _ := r.commit(generate(t, source720))
	// The first attempt got as far as pinning (the real repository call) and then died.
	if _, err := pipeline.NewDBRepo(r.pool).PinLogo(ctx, a.TenantID, a.ID); err != nil {
		t.Fatal(err)
	}
	second := r.putLogo(svc, yellow, db.CornerBottomLeft, 100)
	if _, _, err := r.buckets.Delivery.Get(ctx, keys.BrandLogo(r.tenant.ID, first.ID), nil); err != nil {
		t.Fatalf("the pinned version was removed while its asset is still to be processed: %v", err)
	}

	if err := r.process(a); err != nil {
		t.Fatalf("process: %v\n%s", err, r.logs.String())
	}
	m := decodedManifest(t, r, a)
	if m.Encoder.Logo == nil || m.Encoder.Logo.Version != first.ID.String() || m.Encoder.Logo.Version == second.ID.String() {
		t.Fatalf("the retry used %+v, want version %s", m.Encoder.Logo, first.ID)
	}
	a, err := r.repos.GetAsset(ctx, a.TenantID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	rs := summaryOf(t, a)[0]
	if have := at(r.frame(a, keys.Original, rs.Name), rs.Width, rs.Height, media.CornerTopRight, testLogoSpec); !near(have, [3]float64{255, 0, 255}, 40) {
		t.Errorf("top right is %v, want the first logo's magenta", have)
	}
}

// The masked variant is drawn on by its own transcode of the masked file, with the logo the asset was
// pinned to, whatever the tenant did to its logo in between.
func TestMaskedVariantCarriesTheSameLogo(t *testing.T) {
	r := newMaskRig(t)
	ctx := context.Background()
	svc := r.brand()
	logo := r.putLogo(svc, magenta, db.CornerBottomRight, 100)

	src := generate(t, source720)
	replacement := generate(t, testmedia.Spec{Name: "masked.mp4", Width: 640, Height: 360, Duration: 4 * time.Second, FPS: 30})
	asset, _ := r.commitAs(src, true)
	if err := r.process(asset); err != nil {
		t.Fatalf("asset.process: %v\n%s", err, r.logs.String())
	}
	// The tenant removes the logo before the masked variant is made.
	if err := svc.Delete(ctx, r.tenant.ID, auth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.buckets.Delivery.Get(ctx, keys.BrandLogo(r.tenant.ID, logo.ID), nil); err != nil {
		t.Fatalf("the version was removed while the masked variant still needs it: %v", err)
	}
	r.startMaskerWith(`{"faces_detected":2,"frames":120}`, false, replacement)
	if err := r.mask(asset); err != nil {
		t.Fatalf("asset.mask: %v\n%s", err, r.logs.String())
	}
	a, err := r.repos.GetAsset(ctx, asset.TenantID, asset.ID)
	if err != nil || a.MaskingState != db.MaskingReady {
		t.Fatalf("asset = %+v, %v", a, err)
	}

	m := decodedManifest(t, r, a)
	if m.Encoder.Logo == nil || m.Masked == nil || m.Masked.Logo == nil || *m.Masked.Logo != *m.Encoder.Logo || m.Masked.Logo.Version != logo.ID.String() {
		t.Fatalf("encoder logo %+v, masked logo %+v", m.Encoder.Logo, m.Masked)
	}
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		for _, rs := range summaryOfVariant(t, r, a, v) {
			if have := at(r.frame(a, v, rs.Name), rs.Width, rs.Height, media.CornerBottomRight, testLogoSpec); !near(have, [3]float64{255, 0, 255}, 40) {
				t.Errorf("%s %s: bottom right is %v, want magenta", v, rs.Name, have)
			}
		}
	}
	// The masked poster shows it too: it is cut from the masked output.
	poster, _, err := image.Decode(bytes.NewReader(r.get(r.buckets.Delivery, keys.VariantPoster(a.TenantID, a.ID, keys.Masked))))
	if err != nil {
		t.Fatal(err)
	}
	if b := poster.Bounds(); !near(at(poster, b.Dx(), b.Dy(), media.CornerBottomRight, testLogoSpec), [3]float64{255, 0, 255}, 40) {
		t.Error("the masked poster does not show the logo")
	}
	// With the masked variant done and nothing in flight, the next change removes the version.
	if _, err := svc.Put(ctx, r.tenant.ID, auth.Actor{}, logoPNG(t, yellow), branding.Placement{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.buckets.Delivery.Get(ctx, keys.BrandLogo(r.tenant.ID, logo.ID), nil); err == nil {
		t.Error("an unneeded logo version was kept")
	}
}

// summaryOfVariant lists the renditions of one variant from its manifest section.
func summaryOfVariant(t *testing.T, r *rig, a db.Asset, v keys.Variant) []renditionInfo {
	t.Helper()
	if v == keys.Original {
		return summaryOf(t, a)
	}
	m := decodedManifest(t, r, a)
	out := make([]renditionInfo, len(m.Masked.Renditions))
	for i, x := range m.Masked.Renditions {
		out[i] = renditionInfo{Name: x.Name, Width: x.Width, Height: x.Height}
	}
	return out
}

// Pinning takes the tenant's brand lock, so it cannot interleave with a change that removes old
// versions: every logo an asset was pinned to is still stored afterwards. The pool has four
// connections, so a lock taken the wrong way round would deadlock here.
func TestPinningAndLogoChangesNeverLoseAVersionAnAssetNeeds(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	svc := r.brand()
	r.putLogo(svc, magenta, db.CornerTopRight, 100)
	repo := pipeline.NewDBRepo(r.pool)

	const assets = 24
	var committed []db.Asset
	for range assets {
		a, err := r.repos.CreateAsset(ctx, r.tenant.ID, r.client.ID, db.AssetCommitted)
		if err != nil {
			t.Fatal(err)
		}
		committed = append(committed, a)
	}
	pins := make([]db.LogoPin, assets)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 12 {
			c := color.NRGBA{R: uint8(10 * i), G: 200, B: 1, A: 255} //nolint:gosec // small
			if _, err := svc.Put(ctx, r.tenant.ID, auth.Actor{}, logoPNG(t, c), branding.Placement{}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; i < assets; i += 4 {
				p, err := repo.PinLogo(ctx, r.tenant.ID, committed[i].ID)
				if err != nil {
					t.Error(err)
					return
				}
				pins[i] = p
			}
		}()
	}
	wg.Wait()
	for i, p := range pins {
		if !p.HasLogo() {
			t.Errorf("asset %d got no logo although the tenant always had one", i)
			continue
		}
		rc, _, err := r.buckets.Delivery.Get(ctx, keys.BrandLogo(r.tenant.ID, p.VersionID), nil)
		if err != nil {
			t.Errorf("asset %d is pinned to a version that is gone: %v", i, err)
			continue
		}
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(rc)
		_ = rc.Close()
		if sum := sha256.Sum256(b.Bytes()); !bytes.Equal(sum[:], p.SHA256) {
			t.Errorf("asset %d: the stored version is not the one pinned", i)
		}
	}
	// Pinning again returns the same thing.
	again, err := repo.PinLogo(ctx, r.tenant.ID, committed[0].ID)
	if err != nil || again.VersionID != pins[0].VersionID {
		t.Errorf("second pin = %+v %v, first %+v", again, err, pins[0])
	}
}
