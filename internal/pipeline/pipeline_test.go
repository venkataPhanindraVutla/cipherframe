package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river/rivertype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// logBuffer is a goroutine-safe buffer for captured log output.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type harness struct {
	t        *testing.T
	proc     *Processor
	repo     *fakeRepo
	source   *memStore
	delivery *memStore
	keys     *fakeKeys
	tools    *fakeTools
	signer   *fakeSigner
	logs     *logBuffer
	args     uploads.ProcessArgs
	workDir  string
	sourceB  []byte
	events   []string
}

const testBitsOfSource = "the source bytes of a test video"

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, source: newMemStore(), delivery: newMemStore(), logs: &logBuffer{}}
	tenant, asset := id.New[id.TenantKind](), id.New[id.AssetKind]()
	h.sourceB = []byte(strings.Repeat(testBitsOfSource, 100))
	srcKey := keys.NewSource(tenant, asset)
	h.source.objects[srcKey] = h.sourceB
	h.repo = newFakeRepo(db.Asset{
		ID: asset, TenantID: tenant, State: db.AssetCommitted, SizeBytes: int64(len(h.sourceB)), SourceKey: srcKey,
	})
	h.keys = &fakeKeys{events: &h.events}
	h.tools = &fakeTools{
		info: landscapeInfo(), segments: []time.Duration{6 * time.Second, 6 * time.Second, 2 * time.Second}, events: &h.events,
	}
	h.signer = newFakeSigner()
	h.workDir = t.TempDir()
	h.args = uploads.ProcessArgs{TenantID: tenant, AssetID: asset}

	proc, err := NewProcessor(Deps{
		Repo: h.repo, Source: h.source, Delivery: h.delivery, Keys: h.keys, Tools: h.tools, Signer: h.signer,
		Limits:  media.Limits{MaxDuration: time.Hour, MaxWidth: 3840, MaxHeight: 2160},
		WorkDir: h.workDir, TranscodeTimeout: time.Minute,
		Log:              slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ProgressInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.proc = proc
	return h
}

func (h *harness) run(attempt, maxAttempts int) error {
	h.t.Helper()
	return h.proc.Handle(context.Background(), jobs.Job[uploads.ProcessArgs]{ID: 1, Args: h.args, Attempt: attempt, MaxAttempts: maxAttempts})
}

func (h *harness) workDirEntries() []string {
	h.t.Helper()
	es, err := os.ReadDir(h.workDir)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func isCancel(err error) bool {
	var c *rivertype.JobCancelError
	return errors.As(err, &c)
}

func TestProcessHappyPath(t *testing.T) {
	h := newHarness(t)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	a := h.repo.snapshot()
	if a.State != db.AssetReady || a.Progress != 100 || a.DurationMS != 14000 {
		t.Fatalf("asset after processing: state=%s progress=%d duration=%d", a.State, a.Progress, a.DurationMS)
	}
	// The source hash was taken from the bytes that were downloaded.
	want := sha256.Sum256(h.sourceB)
	if !bytes.Equal(a.SourceSHA256, want[:]) || a.SourceSizeBytes != int64(len(h.sourceB)) {
		t.Fatalf("source hash/size = %x / %d", a.SourceSHA256, a.SourceSizeBytes)
	}
	// 720p, 480p, 360p, 240p: never 1080p.
	var sum []RenditionSummary
	if err := json.Unmarshal(a.Renditions, &sum); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range sum {
		names = append(names, s.Name)
		if s.Codecs != "avc1.640028,mp4a.40.2" || s.Segments != 3 || s.Bandwidth < s.AverageBandwidth || s.AverageBandwidth <= 0 {
			t.Errorf("summary %+v", s)
		}
	}
	if !slices.Equal(names, []string{"720p", "480p", "360p", "240p"}) {
		t.Fatalf("renditions %v", names)
	}

	// Every delivery object is registered, with the hash of the stored bytes, and the other way round.
	stored := h.delivery.keys()
	if len(stored) != len(h.repo.artifacts) || len(stored) != 4*(1+1+3)+1 {
		t.Fatalf("%d objects, %d artifacts", len(stored), len(h.repo.artifacts))
	}
	for _, k := range stored {
		art, ok := h.repo.artifacts["delivery/"+k]
		if !ok {
			t.Fatalf("object %s is not registered", k)
		}
		got := sha256.Sum256(h.delivery.object(k))
		if !bytes.Equal(art.SHA256, got[:]) || art.SizeBytes != int64(len(h.delivery.object(k))) {
			t.Errorf("artifact %s: wrong hash or size", k)
		}
	}

	// Segments are ciphertext: they decrypt with the key and the IV in the playlist, and not otherwise.
	tenant, asset := h.args.TenantID, h.args.AssetID
	name, _ := keys.ParseRendition("720p")
	playlist := string(h.delivery.object(keys.Playlist(tenant, asset, name)))
	ivs := regexp.MustCompile(`IV=0x([0-9A-F]{32})`).FindAllStringSubmatch(playlist, -1)
	if len(ivs) != 3 {
		t.Fatalf("playlist has %d IVs:\n%s", len(ivs), playlist)
	}
	seen := map[string]bool{}
	for i, m := range ivs {
		if seen[m[1]] {
			t.Fatal("an IV was reused")
		}
		seen[m[1]] = true
		var iv hls.IV
		raw, _ := hex.DecodeString(m[1])
		copy(iv[:], raw)
		ct := h.delivery.object(keys.Segment(tenant, asset, name, i))
		plain := h.tools.plaintext[fmt.Sprintf("720p/%d", i)]
		if bytes.Contains(ct, plain[:64]) {
			t.Fatalf("segment %d contains plaintext", i)
		}
		got, err := hls.DecryptSegment(h.keys.key, iv, ct)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("segment %d does not decrypt to what FFmpeg wrote: %v", i, err)
		}
		bad := slices.Clone(h.keys.key)
		bad[0] ^= 0xff
		if got, err := hls.DecryptSegment(bad, iv, ct); err == nil && bytes.Equal(got, plain) {
			t.Fatal("decrypted with the wrong key")
		}
	}
	if strings.Contains(playlist, "http") || !strings.Contains(playlist, `URI="cipherframe-key"`) ||
		!strings.Contains(playlist, "#EXT-X-MAP:URI=\"init.mp4\"") {
		t.Errorf("unexpected stored playlist:\n%s", playlist)
	}
	master := string(h.delivery.object(keys.Master(tenant, asset)))
	if !strings.Contains(master, `CODECS="avc1.640028,mp4a.40.2"`) || !strings.Contains(master, "RESOLUTION=1280x720") ||
		!strings.Contains(master, "FRAME-RATE=30.000") || strings.Contains(master, "1920x1080") {
		t.Errorf("unexpected master playlist:\n%s", master)
	}

	// The init segment is stored as FFmpeg wrote it (documented), everything else is ciphertext.
	if !bytes.Equal(h.delivery.object(keys.InitSegment(tenant, asset, name)), fakeInit(true)) {
		t.Error("init segment was altered")
	}
	// The work directory is gone, and the key was created once before the transcode.
	if got := h.workDirEntries(); len(got) != 0 {
		t.Errorf("work directory not empty: %v", got)
	}
	if h.keys.creates != 1 || !slices.Equal(h.events, []string{"key", "transcode"}) {
		t.Errorf("key creates=%d, order=%v", h.keys.creates, h.events)
	}
	// Progress only moved forward.
	if !slices.IsSorted(h.repo.progress) {
		t.Errorf("progress went backwards: %v", h.repo.progress)
	}
}

func TestRetryStartsCleanAndReusesTheKey(t *testing.T) {
	h := newHarness(t)
	// The first attempt dies in the middle of the upload (a storage outage).
	h.delivery.putFailAfter = 6
	err := h.run(1, 5)
	if err == nil || isCancel(err) {
		t.Fatalf("first attempt error = %v; want a retryable error", err)
	}
	if a := h.repo.snapshot(); a.State != db.AssetProcessing {
		t.Fatalf("state after a transient failure = %s, want processing", a.State)
	}
	if n := len(h.delivery.keys()); n != 6 {
		t.Fatalf("partial upload left %d objects, want 6", n)
	}
	if got := h.workDirEntries(); len(got) != 0 {
		t.Errorf("plaintext left behind after a failure: %v", got)
	}
	// Something an earlier, crashed attempt registered but never completed.
	h.repo.artifacts["delivery/stale"] = db.Artifact{ObjectKey: "stale"}
	h.delivery.objects[keys.HLSPrefix(h.args.TenantID, h.args.AssetID)+"720p/seg-99.m4s"] = []byte("old")

	if err := h.run(2, 5); err != nil {
		t.Fatal(err)
	}
	if a := h.repo.snapshot(); a.State != db.AssetReady {
		t.Fatalf("state after the retry = %s", a.State)
	}
	// The delivery bucket holds exactly the registered artifacts: nothing stale, nothing missing.
	stored := h.delivery.keys()
	if len(stored) != len(h.repo.artifacts) || len(stored) != 21 {
		t.Fatalf("%d objects vs %d artifacts", len(stored), len(h.repo.artifacts))
	}
	for _, k := range stored {
		if _, ok := h.repo.artifacts["delivery/"+k]; !ok {
			t.Errorf("object %s is not registered", k)
		}
		if strings.Contains(k, "seg-99") {
			t.Error("a stale segment survived the retry")
		}
	}
	if _, ok := h.repo.artifacts["delivery/stale"]; ok {
		t.Error("a stale artifact row survived the retry")
	}
	if h.keys.creates != 1 || h.keys.calls != 2 {
		t.Errorf("content key created %d times in %d attempts; want created once, fetched each attempt", h.keys.creates, h.keys.calls)
	}
}

func TestInvalidMediaFailsTheAssetForGood(t *testing.T) {
	for name, tc := range map[string]struct {
		mod  func(*harness)
		code string
	}{
		"probe rejects": {func(h *harness) { h.tools.probeErr = errs.New(errs.InvalidRequest, "not media") }, FailureInvalidMedia},
		"too long": {func(h *harness) {
			h.tools.info.Duration = 5 * time.Hour
		}, FailureInvalidMedia},
		"no video": {func(h *harness) { h.tools.info.Video = nil }, FailureInvalidMedia},
		"ffmpeg rejects the stream": {func(h *harness) {
			h.tools.transcodeErr = errs.New(errs.InvalidRequest, "could not be transcoded")
		}, FailureTranscode},
		"transcode timeout": {func(h *harness) {
			h.tools.transcodeErr = errs.New(errs.Timeout, "too long")
		}, FailureTranscodeTimeout},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			tc.mod(h)
			err := h.run(1, 5)
			if !isCancel(err) {
				t.Fatalf("error = %v; want a cancelled (non-retryable) job", err)
			}
			a := h.repo.snapshot()
			if a.State != db.AssetFailed || a.FailureCode != tc.code {
				t.Fatalf("asset = %s/%s, want failed/%s", a.State, a.FailureCode, tc.code)
			}
			if len(h.delivery.keys()) != 0 || len(h.repo.artifacts) != 0 {
				t.Error("a failed asset has delivery objects or artifacts")
			}
			if got := h.workDirEntries(); len(got) != 0 {
				t.Errorf("work directory not empty: %v", got)
			}
		})
	}
}

func TestSourceProblems(t *testing.T) {
	t.Run("declared size differs", func(t *testing.T) {
		h := newHarness(t)
		h.repo.asset.SizeBytes++
		if err := h.run(1, 5); !isCancel(err) {
			t.Fatalf("error = %v", err)
		}
		if a := h.repo.snapshot(); a.State != db.AssetFailed || a.FailureCode != FailureSourceMismatch {
			t.Fatalf("asset = %s/%s", a.State, a.FailureCode)
		}
		if h.tools.probes != 0 {
			t.Error("probed a source whose size was wrong")
		}
	})
	t.Run("object is gone", func(t *testing.T) {
		h := newHarness(t)
		h.source.objects = map[string][]byte{}
		if err := h.run(1, 5); !isCancel(err) {
			t.Fatalf("error = %v", err)
		}
		if a := h.repo.snapshot(); a.State != db.AssetFailed || a.FailureCode != FailureSourceMissing {
			t.Fatalf("asset = %s/%s", a.State, a.FailureCode)
		}
	})
}

func TestTransientFailureOnTheLastAttemptFailsTheAsset(t *testing.T) {
	h := newHarness(t)
	h.delivery.putFailAfter = 2
	err := h.run(5, 5)
	if err == nil || isCancel(err) {
		t.Fatalf("error = %v", err)
	}
	if a := h.repo.snapshot(); a.State != db.AssetFailed || a.FailureCode != FailureProcessing {
		t.Fatalf("asset = %s/%s, want failed/%s", a.State, a.FailureCode, FailureProcessing)
	}
	if len(h.delivery.keys()) != 0 {
		t.Error("a failed asset kept its partial output")
	}
}

func TestInterruptionLeavesTheAssetProcessing(t *testing.T) {
	h := newHarness(t)
	h.tools.block, h.tools.started = true, make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-h.tools.started
		cancel()
	}()
	err := h.proc.Handle(ctx, jobs.Job[uploads.ProcessArgs]{ID: 1, Args: h.args, Attempt: 5, MaxAttempts: 5})
	if err == nil || isCancel(err) {
		t.Fatalf("error = %v; want the context error (retried later)", err)
	}
	// Even on the last attempt: shutdown is not a failure of the asset.
	if a := h.repo.snapshot(); a.State != db.AssetProcessing {
		t.Fatalf("state = %s", a.State)
	}
	if got := h.workDirEntries(); len(got) != 0 {
		t.Errorf("work directory not empty after an interruption: %v", got)
	}
}

func TestNothingToDoForFinishedAssets(t *testing.T) {
	for _, st := range []db.AssetState{db.AssetReady, db.AssetFailed, db.AssetDeleted} {
		h := newHarness(t)
		h.repo.asset.State = st
		if err := h.run(1, 5); err != nil {
			t.Errorf("%s: %v", st, err)
		}
		if h.tools.probes != 0 || len(h.delivery.keys()) != 0 || h.repo.snapshot().State != st {
			t.Errorf("%s: the job did work or changed the asset", st)
		}
	}
	// An asset that was never committed is not this job's to process.
	h := newHarness(t)
	h.repo.asset.State = db.AssetUploading
	if err := h.run(1, 5); !isCancel(err) {
		t.Errorf("uploading asset: %v", err)
	}
}

func TestLostRaceForTheClaim(t *testing.T) {
	h := newHarness(t)
	// Another worker already moved the asset to processing between our read and our transition.
	r := &racyRepo{fakeRepo: h.repo}
	h.proc.Repo = r
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	if a := h.repo.snapshot(); a.State != db.AssetReady {
		t.Fatalf("state = %s", a.State)
	}
	if r.conflicts != 1 {
		t.Fatalf("conflicts = %d", r.conflicts)
	}
}

type racyRepo struct {
	*fakeRepo
	conflicts int
}

func (r *racyRepo) TransitionAsset(ctx context.Context, tn id.TenantID, a id.AssetID, t db.Transition) (db.Asset, error) {
	if t.To == db.AssetProcessing && r.conflicts == 0 {
		r.conflicts++
		r.mu.Lock()
		r.asset.State = db.AssetProcessing
		r.mu.Unlock()
		return db.Asset{}, errs.Wrap(errs.Conflict, "state", db.ErrStateChanged)
	}
	return r.fakeRepo.TransitionAsset(ctx, tn, a, t)
}

func TestAssetDeletedWhileProcessingLeavesNoOutput(t *testing.T) {
	h := newHarness(t)
	h.proc.Repo = &deletingRepo{fakeRepo: h.repo}
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	if len(h.delivery.keys()) != 0 {
		t.Errorf("output of a deleted asset was kept: %v", h.delivery.keys())
	}
}

// deletingRepo deletes the asset just before the pipeline tries to complete it.
type deletingRepo struct{ *fakeRepo }

func (r *deletingRepo) Complete(ctx context.Context, tn id.TenantID, a id.AssetID, arts []db.Artifact, c db.Completion) (db.Asset, error) {
	r.mu.Lock()
	r.asset.State = db.AssetDeleted
	r.mu.Unlock()
	return r.fakeRepo.Complete(ctx, tn, a, arts, c)
}

func TestNoUpscalingAndTinySources(t *testing.T) {
	h := newHarness(t)
	h.tools.info.Video.Width, h.tools.info.Video.Height = 320, 180
	h.tools.info.Video.DisplayWidth, h.tools.info.Video.DisplayHeight = 320, 180
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	if got := len(h.tools.lastSpec.Renditions); got != 1 || h.tools.lastSpec.Renditions[0].Height != 180 {
		t.Errorf("renditions for a 180p source: %+v", h.tools.lastSpec.Renditions)
	}
}

func TestSourceWithoutAudio(t *testing.T) {
	h := newHarness(t)
	h.tools.info.Audio = nil
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	master := string(h.delivery.object(keys.Master(h.args.TenantID, h.args.AssetID)))
	if !strings.Contains(master, `CODECS="avc1.640028"`) || strings.Contains(master, "mp4a") {
		t.Errorf("master playlist of a silent video:\n%s", master)
	}
}

// ---- secrets stay out of logs, errors and job arguments ---------------------------------------

func leaks(haystack string, key []byte) []string {
	var found []string
	for name, needle := range map[string]string{
		"raw":    string(key),
		"hex":    hex.EncodeToString(key),
		"HEX":    strings.ToUpper(hex.EncodeToString(key)),
		"base64": base64.StdEncoding.EncodeToString(key),
		"b64url": base64.RawURLEncoding.EncodeToString(key),
		"%v":     fmt.Sprintf("%v", key),
	} {
		if strings.Contains(haystack, needle) {
			found = append(found, name)
		}
	}
	return found
}

func TestKeyBytesNeverReachLogsErrorsOrArgs(t *testing.T) {
	var collected []string
	for name, mod := range map[string]func(*harness){
		"success":         func(*harness) {},
		"upload outage":   func(h *harness) { h.delivery.putFailAfter = 4 },
		"transcode error": func(h *harness) { h.tools.transcodeErr = errs.New(errs.InvalidRequest, "bad") },
		"last attempt":    func(h *harness) { h.delivery.putFailAfter = 3 },
	} {
		h := newHarness(t)
		mod(h)
		attempt := 1
		if name == "last attempt" {
			attempt = 5
		}
		err := h.run(attempt, 5)
		if err != nil {
			collected = append(collected, fmt.Sprintf("%v %+v %#v", err, err, err))
		}
		collected = append(collected, h.logs.String())
		args, _ := json.Marshal(h.args)
		collected = append(collected, string(args))
		a := h.repo.snapshot()
		collected = append(collected, fmt.Sprintf("%+v", a), string(a.Renditions))
		for _, art := range h.repo.artifacts {
			collected = append(collected, fmt.Sprintf("%+v", art))
		}
		// Neither storage nor the registry holds the key, in any encoding.
		for _, k := range h.delivery.keys() {
			collected = append(collected, k)
			if h.keys.key != nil {
				if strings.Contains(string(h.delivery.object(k)), string(h.keys.key)) && !strings.HasSuffix(k, ".m4s") {
					t.Errorf("%s: object %s contains the raw key", name, k)
				}
			}
		}
		if h.keys.key == nil {
			continue // failed before the key existed: nothing to scan for
		}
		if l := leaks(strings.Join(collected, "\n"), h.keys.key); len(l) > 0 {
			t.Errorf("%s: the key appears in %v", name, l)
		}
		collected = collected[:0]
	}
}

func TestLogLinesCarryIDsAndCountsOnly(t *testing.T) {
	h := newHarness(t)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	logs := h.logs.String()
	srcKey := h.repo.snapshot().SourceKey
	if strings.Contains(logs, srcKey) || strings.Contains(logs, path.Base(srcKey)) {
		t.Error("the source object key was logged")
	}
	if strings.Contains(logs, h.workDir) {
		t.Error("a work directory path was logged")
	}
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if rec["asset_id"] != h.args.AssetID.String() {
			t.Errorf("log line without the asset id: %s", line)
		}
	}
}

func TestProcessArgsHoldOnlyIDs(t *testing.T) {
	b, err := json.Marshal(uploads.ProcessArgs{TenantID: id.New[id.TenantKind](), AssetID: id.New[id.AssetKind]()})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["tenant_id"] == nil || m["asset_id"] == nil {
		t.Fatalf("job args: %s", b)
	}
	if uploads.ProcessKind != "asset.process" || (uploads.ProcessArgs{}).Kind() != "asset.process" {
		t.Fatal("the job kind changed")
	}
}

// ---- helpers ----------------------------------------------------------------------------------

func TestBitrateAndPeak(t *testing.T) {
	if got := bitrate(750_000, 6*time.Second); got != 1_000_000 {
		t.Errorf("bitrate = %d", got)
	}
	if bitrate(0, time.Second) != 1 || bitrate(10, 0) != 1 {
		t.Error("bitrate must be at least 1")
	}
}

func TestPeakBandwidthIgnoresATinyFinalSegment(t *testing.T) {
	h := newHarness(t)
	// A last segment of 40 ms: its instantaneous bitrate is huge and meaningless.
	h.tools.segments = []time.Duration{6 * time.Second, 6 * time.Second, 40 * time.Millisecond}
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	var sum []RenditionSummary
	if err := json.Unmarshal(h.repo.snapshot().Renditions, &sum); err != nil {
		t.Fatal(err)
	}
	for _, s := range sum {
		// 6 s segments of ~1-2 kB: the peak is a few kbit/s, not hundreds from the 40 ms segment.
		if s.Bandwidth > 20_000 {
			t.Errorf("%s: bandwidth %d is skewed by the tiny final segment", s.Name, s.Bandwidth)
		}
	}
}

func TestReporterWritesLatestValueAndStops(t *testing.T) {
	var mu sync.Mutex
	var got []int
	rep := startReporter(context.Background(), 2*time.Millisecond, func(_ context.Context, p int) error {
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
		return nil
	})
	rep.transcoded(5*time.Second, 10*time.Second) // 45
	time.Sleep(30 * time.Millisecond)
	rep.transcoded(20*time.Second, 10*time.Second) // clamped to 90
	time.Sleep(30 * time.Millisecond)
	rep.transcoded(0, 0) // ignored
	rep.stop()
	mu.Lock()
	defer mu.Unlock()
	if len(got) < 2 || got[0] != 45 || got[len(got)-1] != 90 || !slices.IsSorted(got) {
		t.Errorf("reported %v", got)
	}
	// Each value is written once.
	if slices.Compact(slices.Clone(got))[0] != 45 || len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Errorf("repeated writes: %v", got)
	}
}

func TestNewProcessorValidatesAndPreparesTheWorkDirectory(t *testing.T) {
	h := newHarness(t)
	d := h.proc.Deps
	d.WorkDir = h.workDir + "/nested/work"
	p, err := NewProcessor(d)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p.WorkDir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("work directory: %v, %v", st, err)
	}
	// A base directory that others can enter is restricted.
	loose := t.TempDir()
	if err := os.Chmod(loose, 0o755); err != nil { //nolint:gosec // the test needs a loose directory
		t.Fatal(err)
	}
	d.WorkDir = loose
	if _, err := NewProcessor(d); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(loose); st.Mode().Perm() != 0o700 {
		t.Errorf("work directory mode = %v", st.Mode().Perm())
	}
	for name, mod := range map[string]func(*Deps){
		"no repo": func(d *Deps) { d.Repo = nil }, "no tools": func(d *Deps) { d.Tools = nil },
		"no timeout": func(d *Deps) { d.TranscodeTimeout = 0 }, "no dir": func(d *Deps) { d.WorkDir = "" },
	} {
		dd := h.proc.Deps
		mod(&dd)
		if _, err := NewProcessor(dd); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestRegisterAddsTheKind(t *testing.T) {
	h := newHarness(t)
	reg := jobs.NewRegistry()
	if err := Register(reg, h.proc.Deps); err != nil {
		t.Fatal(err)
	}
	if got := reg.Kinds(); !slices.Equal(got, []string{"asset.process"}) {
		t.Fatalf("kinds = %v", got)
	}
	if err := Register(reg, h.proc.Deps); err == nil {
		t.Fatal("registered the kind twice")
	}
}

func TestStoreErrorsAreStorageErrors(t *testing.T) {
	// The retry policy depends on storage failures not being classified as invalid_request.
	var e error = &storage.Error{Kind: storage.Unavailable, Op: "put"}
	if !jobs.Retryable(e) {
		t.Fatal("a storage outage must be retried")
	}
}
