package pipeline

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

func TestCompleteReceivesASignedManifest(t *testing.T) {
	h := newHarness(t)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	if a := h.repo.snapshot(); a.State != db.AssetReady {
		t.Fatalf("state = %s", a.State)
	}
	m := h.repo.manifest
	if m == nil {
		t.Fatal("Complete received no manifest")
	}
	if m.KeyID != fakeKeyID || m.AssetID != h.args.AssetID || m.TenantID != h.args.TenantID {
		t.Errorf("manifest row = %+v", m)
	}

	env, err := dsse.Decode(m.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	res, err := dsse.Verify(env, manifest.PayloadType, map[string]ed25519.PublicKey{
		fakeKeyID: h.signer.priv.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.RequireAny(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(env.Payload)
	if !bytes.Equal(m.PayloadSHA256, sum[:]) {
		t.Error("payload_sha256 does not match the payload")
	}

	var doc manifest.Manifest
	if err := json.Unmarshal(env.Payload, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != manifest.Schema || doc.AssetID != h.args.AssetID.String() || doc.TenantID != h.args.TenantID.String() {
		t.Errorf("manifest header = %s %s %s", doc.Schema, doc.AssetID, doc.TenantID)
	}
	if hex.EncodeToString(m.TopRoot) != doc.TopLevel.Root {
		t.Error("top_root differs from the manifest")
	}
	if doc.Encoder.FFmpeg != "ffmpeg version test-fixture" || doc.Encoder.Encryption != "AES-128" ||
		doc.Encoder.SegmentSeconds != media.SegmentSeconds {
		t.Errorf("encoder = %+v", doc.Encoder)
	}
	if want := sha256.Sum256(h.sourceB); doc.Source.SHA256 != hex.EncodeToString(want[:]) || doc.Source.Size != int64(len(h.sourceB)) {
		t.Errorf("source = %+v", doc.Source)
	}
	if len(doc.Renditions) != 4 || doc.Renditions[0].Name != "720p" || len(doc.Encoder.Rungs) != 4 {
		t.Fatalf("renditions = %d, rungs = %d", len(doc.Renditions), len(doc.Encoder.Rungs))
	}

	// Every hash and size in the manifest is that of the object in the delivery bucket, found by
	// its path under the HLS prefix.
	prefix := keys.HLSPrefix(h.args.TenantID, h.args.AssetID)
	check := func(o manifest.Object) {
		t.Helper()
		body := h.delivery.object(prefix + o.Path)
		got := sha256.Sum256(body)
		if body == nil || hex.EncodeToString(got[:]) != o.SHA256 || int64(len(body)) != o.Size {
			t.Errorf("%s: manifest and stored object disagree", o.Path)
		}
	}
	segments := 0
	for _, r := range doc.Renditions {
		check(r.Init)
		for _, s := range r.Segments {
			check(s)
			segments++
		}
		if r.SegmentCount != len(r.Segments) || r.SegmentCount != 3 {
			t.Errorf("rendition %s: segment_count %d", r.Name, r.SegmentCount)
		}
	}
	for _, a := range doc.Artifacts {
		check(manifest.Object{Path: a.Path, SHA256: a.SHA256, Size: a.Size})
	}
	if segments != 12 || len(doc.Artifacts) != 5 {
		t.Errorf("%d segments, %d artifacts", segments, len(doc.Artifacts))
	}

	// The envelope is nowhere in the logs, and the source key is nowhere in the manifest.
	logs := h.logs.String()
	for _, secret := range []string{base64.StdEncoding.EncodeToString(env.Signatures[0].Sig), string(m.Envelope)} {
		if strings.Contains(logs, secret) {
			t.Error("the logs contain the signature or the envelope")
		}
	}
	if strings.Contains(string(env.Payload), h.repo.snapshot().SourceKey) {
		t.Error("the manifest names the source object")
	}
}

func TestSignerFailureIsTransientAndLeavesTheAssetUncompleted(t *testing.T) {
	h := newHarness(t)
	h.signer.err = errors.New("signer unavailable")
	err := h.run(1, 5)
	if err == nil || isCancel(err) {
		t.Fatalf("error = %v; want a retryable error", err)
	}
	if a := h.repo.snapshot(); a.State != db.AssetProcessing {
		t.Fatalf("state = %s, want processing", a.State)
	}
	if h.repo.manifest != nil {
		t.Error("a manifest was stored")
	}
	if h.signer.calls != 1 {
		t.Errorf("signer calls = %d", h.signer.calls)
	}

	// The retry succeeds once the signer is back.
	h.signer.err = nil
	if err := h.run(2, 5); err != nil {
		t.Fatal(err)
	}
	if h.repo.manifest == nil || h.repo.snapshot().State != db.AssetReady {
		t.Fatal("the retry did not complete the asset with a manifest")
	}
}

func TestSignerFailureOnTheLastAttemptFailsTheAsset(t *testing.T) {
	h := newHarness(t)
	h.signer.err = errors.New("signer unavailable")
	if err := h.run(5, 5); err == nil {
		t.Fatal("expected an error")
	}
	a := h.repo.snapshot()
	if a.State != db.AssetFailed || a.FailureCode != FailureProcessing {
		t.Fatalf("state = %s, code = %q", a.State, a.FailureCode)
	}
	if len(h.delivery.keys()) != 0 {
		t.Error("partial output was left behind")
	}
}

func TestRetryDeletesTheStaleManifest(t *testing.T) {
	h := newHarness(t)
	// A manifest left by an earlier attempt must be gone before the new one is stored; the fake
	// refuses a duplicate, as the table's primary key does.
	h.repo.manifest = &db.AssetManifest{KeyID: "stale"}
	if err := h.run(2, 5); err != nil {
		t.Fatal(err)
	}
	if h.repo.manifestDeletes != 1 {
		t.Errorf("manifest deletes = %d, want 1", h.repo.manifestDeletes)
	}
	if h.repo.manifest == nil || h.repo.manifest.KeyID != fakeKeyID {
		t.Fatalf("manifest after the retry = %+v", h.repo.manifest)
	}
}

func TestFailingAnAssetRemovesItsManifest(t *testing.T) {
	h := newHarness(t)
	h.repo.manifest = &db.AssetManifest{KeyID: "stale"}
	h.tools.probeErr = errors.New("ffprobe not running")
	if err := h.run(5, 5); err == nil {
		t.Fatal("expected an error")
	}
	if h.repo.manifest != nil {
		t.Error("the manifest of a failed asset was kept")
	}
}

func TestFFmpegVersionIsReadOnceAndFailuresAreNotCached(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.tools.versionErr = errors.New("no ffmpeg")
	if _, err := h.proc.ffmpegVersionString(ctx); err == nil {
		t.Fatal("expected an error")
	}
	h.tools.versionErr = nil
	for range 3 {
		v, err := h.proc.ffmpegVersionString(ctx)
		if err != nil || v != "ffmpeg version test-fixture" {
			t.Fatalf("version = %q, %v", v, err)
		}
	}
	if h.tools.versionCalls != 2 {
		t.Errorf("version calls = %d, want 2 (one failure, one success)", h.tools.versionCalls)
	}
}

func TestVersionFailureIsRetried(t *testing.T) {
	h := newHarness(t)
	h.tools.versionErr = errors.New("no ffmpeg")
	if err := h.run(1, 5); err == nil || isCancel(err) {
		t.Fatalf("error = %v; want a retryable error", err)
	}
	if h.repo.snapshot().State != db.AssetProcessing {
		t.Fatal("the asset left processing")
	}
}

func TestNewProcessorRequiresASigner(t *testing.T) {
	h := newHarness(t)
	_, err := NewProcessor(Deps{
		Repo: h.repo, Source: h.source, Delivery: h.delivery, Keys: h.keys, Tools: h.tools,
		WorkDir: t.TempDir(), TranscodeTimeout: time.Minute, Log: slog.Default(),
	})
	if err == nil {
		t.Fatal("a processor without a signer was accepted")
	}
}

func TestRationalFrameRates(t *testing.T) {
	for in, want := range map[string]string{
		"30": "30/1", "30000/1001": "30000/1001", "23.976": "23976/1000", "12.5": "125/10",
	} {
		if got := rational(in); got != want {
			t.Errorf("rational(%q) = %q, want %q", in, got, want)
		}
	}
}
