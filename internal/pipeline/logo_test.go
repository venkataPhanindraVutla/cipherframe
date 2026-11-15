package pipeline

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/branding"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// storeLogo puts a solid w x h logo in the delivery bucket as the stored version and returns the pin
// the tenant's settings would give an asset.
func (h *harness) storeLogo(w, hgt int, c color.NRGBA, corner string, opacity int) db.LogoPin {
	h.t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, hgt))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		h.t.Fatal(err)
	}
	norm, err := branding.Normalize(buf.Bytes())
	if err != nil {
		h.t.Fatal(err)
	}
	v := id.New[id.LogoVersionKind]()
	h.delivery.objects[keys.BrandLogo(h.args.TenantID, v)] = norm.PNG
	return db.LogoPin{VersionID: v, SHA256: norm.SHA256[:], Corner: corner, OpacityPercent: opacity}
}

func (h *harness) storedManifest() manifest.Manifest {
	h.t.Helper()
	env, err := dsse.Decode(h.repo.manifest.Envelope)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := dsse.Verify(env, manifest.PayloadType, map[string]ed25519.PublicKey{fakeKeyID: h.signer.priv.Public().(ed25519.PublicKey)}); err != nil {
		h.t.Fatalf("the manifest does not verify: %v", err)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		h.t.Fatal(err)
	}
	return m
}

func TestProcessBurnsInThePinnedLogoAndRecordsItInTheManifest(t *testing.T) {
	h := newHarness(t)
	h.repo.logo = h.storeLogo(64, 32, color.NRGBA{R: 255, G: 255, B: 255, A: 255}, db.CornerTopLeft, 40)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	l := h.tools.lastSpec.Logo
	if l == nil || l.Width != 64 || l.Height != 32 || l.Corner != media.CornerTopLeft || l.OpacityPercent != 40 {
		t.Fatalf("logo given to the transcode = %+v", l)
	}
	if len(h.tools.logoRaw) != 64*32*4 || h.tools.logoRaw[0] != 255 || h.tools.logoRaw[3] != 255 {
		t.Errorf("FFmpeg was not given the logo's raw pixels (%d bytes)", len(h.tools.logoRaw))
	}
	if got := h.workDirEntries(); len(got) != 0 {
		t.Errorf("the logo file outlived the job: %v", got)
	}
	m := h.storedManifest()
	want := &manifest.Logo{
		SHA256: hex.EncodeToString(h.repo.logo.SHA256), Version: h.repo.logo.VersionID.String(), Corner: "top_left",
		OpacityPercent: 40, WidthPercent: media.LogoWidthPercent,
	}
	if m.Encoder.Logo == nil || *m.Encoder.Logo != *want {
		t.Fatalf("manifest logo = %+v, want %+v", m.Encoder.Logo, want)
	}
}

func TestProcessWithoutALogoLeavesTheManifestAsItWas(t *testing.T) {
	h := newHarness(t)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	if h.tools.lastSpec.Logo != nil {
		t.Error("a logo was drawn although the tenant has none")
	}
	env, err := dsse.Decode(h.repo.manifest.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(env.Payload), `"logo"`) {
		t.Errorf("a manifest without a logo mentions one: %s", env.Payload)
	}
}

// A retried job uses the version its asset was pinned to, not the tenant's newer one.
func TestRetryUsesThePinnedLogoVersion(t *testing.T) {
	h := newHarness(t)
	first := h.storeLogo(64, 32, color.NRGBA{R: 255, A: 255}, db.CornerBottomRight, 100)
	h.repo.logo = first
	h.tools.transcodeErr = errors.New("ffmpeg crashed")
	if err := h.run(1, 5); err == nil {
		t.Fatal("expected a retryable error")
	}
	// The tenant uploads another logo while the job waits for its retry.
	h.repo.logo = h.storeLogo(32, 64, color.NRGBA{G: 255, A: 255}, db.CornerTopRight, 50)
	h.tools.transcodeErr = nil
	if err := h.run(2, 5); err != nil {
		t.Fatal(err)
	}
	if l := h.tools.lastSpec.Logo; l == nil || l.Width != 64 || l.Corner != media.CornerBottomRight || l.OpacityPercent != 100 {
		t.Fatalf("the retry used %+v", l)
	}
	if got := h.storedManifest().Encoder.Logo; got == nil || got.Version != first.VersionID.String() {
		t.Fatalf("manifest logo = %+v, want version %s", got, first.VersionID)
	}
}

func TestMissingOrSwappedLogoFailsTheAssetForGood(t *testing.T) {
	t.Run("object gone", func(t *testing.T) {
		h := newHarness(t)
		h.repo.logo = h.storeLogo(64, 32, color.NRGBA{A: 255}, db.CornerTopLeft, 100)
		delete(h.delivery.objects, keys.BrandLogo(h.args.TenantID, h.repo.logo.VersionID))
		if err := h.run(1, 5); !isCancel(err) {
			t.Fatalf("error = %v, want a permanent failure", err)
		}
		if a := h.repo.snapshot(); a.State != db.AssetFailed || a.FailureCode != FailureLogoUnavailable {
			t.Fatalf("asset = %s/%s", a.State, a.FailureCode)
		}
		if h.tools.transcodes != 0 {
			t.Error("the asset was transcoded without its logo")
		}
	})
	t.Run("hash differs from the pin", func(t *testing.T) {
		h := newHarness(t)
		h.repo.logo = h.storeLogo(64, 32, color.NRGBA{A: 255}, db.CornerTopLeft, 100)
		h.repo.logo.SHA256 = bytes.Repeat([]byte{1}, 32)
		if err := h.run(1, 5); !isCancel(err) {
			t.Fatalf("error = %v, want a permanent failure", err)
		}
		if a := h.repo.snapshot(); a.State != db.AssetFailed || a.FailureCode != FailureLogoUnavailable {
			t.Fatalf("asset = %s/%s", a.State, a.FailureCode)
		}
	})
}

// The masked variant gets the same logo, drawn by its own transcode of the masked file, and the
// manifest's masked section records it.
func TestMaskedVariantGetsTheSameLogo(t *testing.T) {
	h := newHarness(t)
	h.repo.logo = h.storeLogo(64, 32, color.NRGBA{R: 255, G: 255, B: 255, A: 255}, db.CornerBottomLeft, 70)
	h.repo.asset.MaskFaces = true
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	h.repo.asset.MaskingState = db.MaskingPending
	// The tenant removes its logo before the masked job starts: the asset keeps the pinned one.
	h.repo.logo = db.LogoPin{}
	m := &maskHarness{harness: h, tasks: &fakeTasks{}, original: map[string][]byte{}}
	proc, err := NewProcessor(Deps{
		Repo: h.repo, Source: h.source, Delivery: h.delivery, Keys: h.keys, Tools: h.tools, Signer: h.signer,
		Limits:  media.Limits{MaxDuration: 3600e9, MaxWidth: 3840, MaxHeight: 2160},
		WorkDir: h.workDir, TranscodeTimeout: 60e9, Tasks: m.tasks, MaskTimeout: 2e9, MaskPoll: 1e6,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.proc = proc
	m.tasks.get = func(env jobs.Envelope, _ int) jobs.Task {
		return succeededTask(env.TaskID, `{"faces_detected":1,"frames":10}`)
	}
	if err := m.runMask(1, 3); err != nil {
		t.Fatal(err)
	}
	if l := h.tools.lastSpec.Logo; l == nil || l.Corner != media.CornerBottomLeft || l.OpacityPercent != 70 {
		t.Fatalf("the masked transcode drew %+v", l)
	}
	got := h.storedManifest()
	if got.Masked == nil || got.Encoder.Logo == nil || got.Masked.Logo == nil || *got.Masked.Logo != *got.Encoder.Logo {
		t.Fatalf("original logo %+v, masked logo %+v", got.Encoder.Logo, got.Masked)
	}
}
