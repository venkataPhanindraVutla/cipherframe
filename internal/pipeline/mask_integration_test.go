//go:build integration && media

package pipeline_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/riverqueue/river/rivertype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// The masking tests use the real processor, FFmpeg, Postgres and object store, with a fake masker
// standing in for the Python worker: a goroutine that claims the media.mask_faces task through
// jobs.Claim (the same SQL as the hand-off contract) and writes the output file.

// newMaskRig is a rig whose processor enqueues asset.mask and can hand tasks to a masker.
func newMaskRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	q, err := jobs.NewQueue(r.pool, jobs.NewRegistry(), jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	repo := pipeline.NewDBRepo(r.pool)
	repo.Queue = q
	r.proc, err = pipeline.NewProcessor(pipeline.Deps{
		Repo: repo, Source: r.buckets.Source, Delivery: r.buckets.Delivery,
		Keys: pipeline.ContentKeys{Pool: r.pool, Manager: r.mgr}, Tools: r.tools, Signer: r.signer,
		Limits:  media.Limits{MaxDuration: time.Hour, MaxWidth: 3840, MaxHeight: 2160},
		WorkDir: r.workDir, TranscodeTimeout: 10 * time.Minute,
		Tasks: pipeline.DBTasks{Pool: r.pool, Queue: q}, MaskTimeout: time.Minute, MaskPoll: 50 * time.Millisecond,
		Log: slog.New(slog.NewTextHandler(r.logs, nil)), ProgressInterval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) mask(a db.Asset) error {
	return r.proc.HandleMask(context.Background(), jobs.Job[pipeline.MaskArgs]{
		ID: 2, Args: pipeline.MaskArgs{TenantID: a.TenantID, AssetID: a.ID}, Attempt: 1, MaxAttempts: 3,
	})
}

// masker is what the fake masker did.
type masker struct {
	claimed atomic.Int32
	// inputSHA256 is the hash of the input file as the masker found it.
	inputSHA256 atomic.Value
}

// startMasker runs a fake masker until the test ends. It copies the input to the output and
// completes the task with the given output, or fails it (not retryable) when fail is true.
func (r *rig) startMasker(output string, fail bool) *masker {
	m := &masker{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			task, err := jobs.Claim(ctx, r.pool, []string{pipeline.MaskTaskKind}, "test-fixture-masker", time.Minute)
			if err != nil || task == nil {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			m.claimed.Add(1)
			res := jobs.Result{EnvelopeVersion: jobs.EnvelopeVersion, TaskID: task.ID}
			var p struct{ Input, Output string }
			if err := json.Unmarshal(task.Envelope.Payload, &p); err != nil {
				return
			}
			in, err := os.ReadFile(filepath.Join(r.workDir, p.Input)) //nolint:gosec // test: a path inside the test's work directory
			if err != nil {
				return
			}
			sum := sha256.Sum256(in)
			m.inputSHA256.Store(hex.EncodeToString(sum[:]))
			if fail {
				res.Status = jobs.StatusFailed
				res.Error = &jobs.TaskError{Code: "decode_failed", Retryable: false, Message: "test-fixture failure"}
				_ = jobs.Fail(ctx, r.pool, task.ID, "test-fixture-masker", res)
				continue
			}
			if err := os.WriteFile(filepath.Join(r.workDir, p.Output), in, 0o600); err != nil { //nolint:gosec // test: a path inside the test's work directory
				return
			}
			res.Status, res.Output = jobs.StatusSucceeded, json.RawMessage(output)
			_ = jobs.Complete(ctx, r.pool, task.ID, "test-fixture-masker", res)
		}
	}()
	return m
}

// snapshot is the SHA-256 of every object under prefix in the delivery bucket.
func (r *rig) snapshot(prefix string) map[string]string {
	r.t.Helper()
	out := map[string]string{}
	for obj, err := range storage.ListAll(context.Background(), r.buckets.Delivery, prefix) {
		if err != nil {
			r.t.Fatal(err)
		}
		sum := sha256.Sum256(r.get(r.buckets.Delivery, obj.Key))
		out[obj.Key] = hex.EncodeToString(sum[:])
	}
	return out
}

func (r *rig) riverJobs(kind string) int {
	r.t.Helper()
	var n int
	if err := r.pool.QueryRow(context.Background(), `SELECT count(*) FROM river_job WHERE kind = $1`, kind).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func TestMaskEndToEnd(t *testing.T) {
	r := newMaskRig(t)
	ctx := context.Background()
	src := generate(t, testmedia.Spec{Name: "source.mp4", Width: 640, Height: 360, Duration: 8 * time.Second, FPS: 30, Audio: true})
	asset, sourceSum := r.commitAs(src, true)

	// asset.process completes the asset and enqueues asset.mask in the same transaction.
	if err := r.process(asset); err != nil {
		t.Fatalf("asset.process: %v\n%s", err, r.logs.String())
	}
	a, err := r.repos.GetAsset(ctx, asset.TenantID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != db.AssetReady || a.MaskingState != db.MaskingPending {
		t.Fatalf("after asset.process: state %s, masking %q", a.State, a.MaskingState)
	}
	if n := r.riverJobs(pipeline.MaskKind); n != 1 {
		t.Fatalf("%d asset.mask jobs enqueued, want 1", n)
	}
	if _, err := playback.ResolveVariant(a, keys.Masked); !isVariantNotReady(err) {
		t.Fatalf("a masked session before masking: %v", err)
	}
	originalPrefix := keys.HLSPrefix(a.TenantID, a.ID)
	before := r.snapshot(originalPrefix)
	beforeManifest, err := r.repos.GetManifest(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}

	m := r.startMasker(`{"faces_detected":5,"frames":240}`, false)
	if err := r.mask(a); err != nil {
		t.Fatalf("asset.mask: %v\n%s", err, r.logs.String())
	}

	a, err = r.repos.GetAsset(ctx, asset.TenantID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != db.AssetReady || a.MaskingState != db.MaskingReady || a.FacesDetected == nil || *a.FacesDetected != 5 {
		t.Fatalf("after asset.mask: %+v", a)
	}
	if m.claimed.Load() != 1 {
		t.Errorf("the masker claimed %d tasks", m.claimed.Load())
	}
	// The masker saw the very bytes of the uploaded source.
	if got := m.inputSHA256.Load(); got != hex.EncodeToString(sourceSum[:]) {
		t.Errorf("masker input hash = %v", got)
	}
	// The source is still in the source bucket, and nothing is left in the work directory.
	if rc, _, err := r.buckets.Source.Get(ctx, a.SourceKey, nil); err != nil {
		t.Errorf("the source is gone after masking: %v", err)
	} else {
		_ = rc.Close()
	}
	if es, _ := os.ReadDir(r.workDir); len(es) != 0 {
		t.Errorf("work directory not empty: %d entries", len(es))
	}

	// The original variant is byte for byte what it was.
	after := r.snapshot(originalPrefix)
	if len(after) != len(before) {
		t.Fatalf("original objects: %d before, %d after", len(before), len(after))
	}
	for k, h := range before {
		if after[k] != h {
			t.Errorf("original object %s changed", k)
		}
	}

	// The masked variant is under masked/hls with its own content key.
	maskedPrefix := keys.VariantHLSPrefix(a.TenantID, a.ID, keys.Masked)
	masked := r.snapshot(maskedPrefix)
	if len(masked) == 0 || strings.HasPrefix(maskedPrefix, originalPrefix) {
		t.Fatalf("masked objects: %d", len(masked))
	}
	arts, err := r.repos.ListArtifacts(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var nOrig, nMasked int
	for _, art := range arts {
		switch art.Variant {
		case db.VariantOriginal:
			nOrig++
			if !strings.HasPrefix(art.ObjectKey, originalPrefix) {
				t.Errorf("original artifact %s outside the original prefix", art.ObjectKey)
			}
		case db.VariantMasked:
			nMasked++
			if !strings.HasPrefix(art.ObjectKey, maskedPrefix) {
				t.Errorf("masked artifact %s outside the masked prefix", art.ObjectKey)
			}
		}
	}
	if nOrig != len(before) || nMasked != len(masked) {
		t.Errorf("registry has %d original and %d masked artifacts; storage has %d and %d", nOrig, nMasked, len(before), len(masked))
	}
	origKey, maskedKey := r.key(a), r.maskedKey(a)
	if bytes.Equal(origKey, maskedKey) {
		t.Fatal("both variants share a content key")
	}

	// A masked session resolves, and its segments play with the masked key and not the original.
	if v, err := playback.ResolveVariant(a, keys.Masked); err != nil || v != keys.Masked {
		t.Fatalf("a masked session after masking: %v, %v", v, err)
	}
	name, _ := keys.ParseRendition("360p")
	pl := parsePlaylist(t, string(r.get(r.buckets.Delivery, keys.VariantPlaylist(a.TenantID, a.ID, keys.Masked, name))))
	if len(pl.segments) == 0 || pl.initURI != "init.mp4" {
		t.Fatalf("masked playlist = %+v", pl)
	}
	segment := func(key []byte) (string, error) {
		body := r.get(r.buckets.Delivery, keys.VariantSegment(a.TenantID, a.ID, keys.Masked, name, 0))
		plain, err := hls.DecryptSegment(key, pl.ivs[0], body)
		if err != nil {
			return "", err
		}
		f := filepath.Join(t.TempDir(), "masked-0.mp4")
		return f, os.WriteFile(f, append(r.get(r.buckets.Delivery, keys.VariantInitSegment(a.TenantID, a.ID, keys.Masked, name)), plain...), 0o600)
	}
	f, err := segment(maskedKey)
	if err != nil {
		t.Fatal(err)
	}
	if ps, err := probePackets(t, r.tools, f); err != nil || len(ps) == 0 {
		t.Fatalf("a masked segment does not play: %d packets, %v", len(ps), err)
	}
	if f, err := segment(origKey); err == nil {
		if ps, err := probePackets(t, r.tools, f); err == nil && len(ps) > 0 {
			t.Error("the original key plays a masked segment")
		}
	}

	// The manifest lists both variants, is signed again, and the original part is as it was signed.
	row, err := r.repos.GetManifest(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(row.PayloadSHA256, beforeManifest.PayloadSHA256) {
		t.Error("the manifest was not signed again")
	}
	pubs, err := r.signer.PublicKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{}
	for _, k := range pubs {
		trusted[k.KeyID] = k.PublicKey
	}
	env, err := dsse.Decode(row.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	res, err := dsse.Verify(env, manifest.PayloadType, trusted)
	if err != nil || res.RequireAny() != nil {
		t.Fatalf("the new envelope does not verify: %v", err)
	}
	var doc, was manifest.Manifest
	if err := json.Unmarshal(env.Payload, &doc); err != nil {
		t.Fatal(err)
	}
	oldEnv, _ := dsse.Decode(beforeManifest.Envelope)
	if err := json.Unmarshal(oldEnv.Payload, &was); err != nil {
		t.Fatal(err)
	}
	if doc.Masked == nil || doc.Masked.FacesDetected != 5 || doc.Masked.Frames != 240 || len(doc.Masked.Renditions) == 0 {
		t.Fatalf("masked section = %+v", doc.Masked)
	}
	if doc.Masked.TopLevel.Root == doc.TopLevel.Root || doc.TopLevel.Root != was.TopLevel.Root || hex.EncodeToString(row.TopRoot) != doc.TopLevel.Root {
		t.Error("the trees of the two variants are not kept apart")
	}
	check := func(prefix, path, want string) {
		t.Helper()
		got := sha256.Sum256(r.get(r.buckets.Delivery, prefix+path))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("%s%s: the manifest hash is not the hash of the stored object", prefix, path)
		}
	}
	for _, rend := range doc.Masked.Renditions {
		check(maskedPrefix, rend.Init.Path, rend.Init.SHA256)
		for _, s := range rend.Segments {
			check(maskedPrefix, s.Path, s.SHA256)
		}
	}
	for _, art := range doc.Masked.Artifacts {
		check(maskedPrefix, art.Path, art.SHA256)
	}
	for _, rend := range doc.Renditions {
		for _, s := range rend.Segments {
			check(originalPrefix, s.Path, s.SHA256)
		}
	}
	if doc.Source.SHA256 != hex.EncodeToString(sourceSum[:]) {
		t.Error("the re-signed manifest lost the source hash")
	}
}

func TestMaskFailureKeepsTheOriginalPlayable(t *testing.T) {
	r := newMaskRig(t)
	ctx := context.Background()
	src := generate(t, testmedia.Spec{Name: "source.mp4", Width: 640, Height: 360, Duration: 6 * time.Second, FPS: 30, Audio: true})
	asset, _ := r.commitAs(src, true)
	if err := r.process(asset); err != nil {
		t.Fatalf("asset.process: %v\n%s", err, r.logs.String())
	}
	originalPrefix := keys.HLSPrefix(asset.TenantID, asset.ID)
	before := r.snapshot(originalPrefix)
	beforeManifest, err := r.repos.GetManifest(ctx, asset.ID)
	if err != nil {
		t.Fatal(err)
	}

	r.startMasker("", true)
	err = r.mask(asset)
	var cancelled *rivertype.JobCancelError
	if !errors.As(err, &cancelled) {
		t.Fatalf("asset.mask error = %v; want a cancelled job", err)
	}

	a, err := r.repos.GetAsset(ctx, asset.TenantID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != db.AssetReady || a.MaskingState != db.MaskingFailed || a.FacesDetected != nil {
		t.Fatalf("after a failed masking: %+v", a)
	}
	if left := r.snapshot(keys.VariantHLSPrefix(a.TenantID, a.ID, keys.Masked)); len(left) != 0 {
		t.Errorf("%d masked objects left behind", len(left))
	}
	after := r.snapshot(originalPrefix)
	if len(after) != len(before) {
		t.Fatalf("original objects: %d before, %d after", len(before), len(after))
	}
	for k, h := range before {
		if after[k] != h {
			t.Errorf("original object %s changed", k)
		}
	}
	arts, _ := r.repos.ListArtifacts(ctx, a.ID)
	for _, art := range arts {
		if art.Variant != db.VariantOriginal {
			t.Errorf("a %s artifact is registered after a failed masking", art.Variant)
		}
	}
	if row, err := r.repos.GetManifest(ctx, a.ID); err != nil || !bytes.Equal(row.Envelope, beforeManifest.Envelope) {
		t.Errorf("the manifest changed after a failed masking: %v", err)
	}
	// The original session still resolves; the masked one never falls back to it.
	if v, err := playback.ResolveVariant(a, keys.Original); err != nil || v != keys.Original {
		t.Errorf("original session: %v, %v", v, err)
	}
	if _, err := playback.ResolveVariant(a, keys.Masked); !isVariantNotReady(err) {
		t.Errorf("masked session after a failed masking: %v", err)
	}
	// The original still plays: a segment decrypts with its key and parses.
	name, _ := keys.ParseRendition("360p")
	pl := parsePlaylist(t, string(r.get(r.buckets.Delivery, keys.Playlist(a.TenantID, a.ID, name))))
	f := r.segmentFile(a, "360p", 0, r.key(a), pl.ivs[0], false)
	if ps, err := probePackets(t, r.tools, f); err != nil || len(ps) == 0 {
		t.Errorf("the original does not play: %d packets, %v", len(ps), err)
	}
	if es, _ := os.ReadDir(r.workDir); len(es) != 0 {
		t.Errorf("work directory not empty: %d entries", len(es))
	}
}

func TestProcessWithoutMaskFacesEnqueuesNoMaskJob(t *testing.T) {
	r := newMaskRig(t)
	src := generate(t, testmedia.Spec{Name: "source.mp4", Width: 640, Height: 360, Duration: 4 * time.Second, FPS: 30, Audio: true})
	asset, _ := r.commit(src)
	if err := r.process(asset); err != nil {
		t.Fatalf("asset.process: %v\n%s", err, r.logs.String())
	}
	if n := r.riverJobs(pipeline.MaskKind); n != 0 {
		t.Fatalf("%d asset.mask jobs for an asset without mask_faces", n)
	}
}

func (r *rig) maskedKey(a db.Asset) []byte {
	r.t.Helper()
	k, err := r.mgr.Get(context.Background(), a.TenantID, a.ID, keys.Masked)
	if err != nil {
		r.t.Fatal(err)
	}
	defer k.Zero()
	return k.Bytes()
}

func isVariantNotReady(err error) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == errs.VariantNotReady
}
