package pipeline

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// maskHarness is a harness whose asset was created with mask_faces and whose original variant is
// already ready (asset.process has run), so only asset.mask is left.
type maskHarness struct {
	*harness
	tasks *fakeTasks
	// original is a copy of the delivery bucket after asset.process.
	original map[string][]byte
	// inputSeen records whether the masker's input file existed when the task was looked at.
	inputSeen bool
}

func newMaskHarness(t *testing.T) *maskHarness {
	t.Helper()
	h := newHarness(t)
	h.repo.asset.MaskFaces = true
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	h.repo.asset.MaskingState = db.MaskingPending
	m := &maskHarness{harness: h, tasks: &fakeTasks{}, original: map[string][]byte{}}
	for _, k := range h.delivery.keys() {
		m.original[k] = h.delivery.object(k)
	}
	proc, err := NewProcessor(Deps{
		Repo: h.repo, Source: h.source, Delivery: h.delivery, Keys: h.keys, Tools: h.tools, Signer: h.signer,
		Limits:  media.Limits{MaxDuration: time.Hour, MaxWidth: 3840, MaxHeight: 2160},
		WorkDir: h.workDir, TranscodeTimeout: time.Minute, Tasks: m.tasks, MaskTimeout: 2 * time.Second, MaskPoll: time.Millisecond,
		Log:              slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ProgressInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.proc = proc
	// By default the masker succeeds on the second look, after checking that its input is there.
	m.tasks.get = func(env jobs.Envelope, call int) jobs.Task {
		if call == 1 {
			var p maskPayload
			_ = json.Unmarshal(env.Payload, &p)
			_, err := os.Stat(filepath.Join(h.workDir, p.Input))
			m.inputSeen = err == nil
			return jobs.Task{State: jobs.StateLeased, LeaseOwner: "test-fixture-masker"}
		}
		return succeededTask(env.TaskID, `{"faces_detected":3,"frames":420}`)
	}
	return m
}

func (m *maskHarness) runMask(attempt, maxAttempts int) error {
	m.t.Helper()
	return m.proc.HandleMask(context.Background(), jobs.Job[MaskArgs]{
		ID: 2, Args: MaskArgs{TenantID: m.args.TenantID, AssetID: m.args.AssetID}, Attempt: attempt, MaxAttempts: maxAttempts,
	})
}

// maskedKeys are the delivery objects under the masked prefix.
func (m *maskHarness) maskedKeys() []string {
	prefix := keys.VariantHLSPrefix(m.args.TenantID, m.args.AssetID, keys.Masked)
	var out []string
	for _, k := range m.delivery.keys() {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

// originalUntouched fails the test when any original-variant object changed or went missing.
func (m *maskHarness) originalUntouched() {
	m.t.Helper()
	for k, want := range m.original {
		if !bytes.Equal(m.delivery.object(k), want) {
			m.t.Errorf("original object %s changed or is gone", k)
		}
	}
}

func TestMaskHappyPath(t *testing.T) {
	m := newMaskHarness(t)
	origManifest := *m.repo.manifest
	if err := m.runMask(1, 3); err != nil {
		t.Fatal(err)
	}

	// The task named the job directory's files, relative to the work directory, and carried no key.
	if len(m.tasks.created) != 1 {
		t.Fatalf("%d tasks created", len(m.tasks.created))
	}
	env := m.tasks.created[0]
	var p maskPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		t.Fatal(err)
	}
	dir := strings.TrimSuffix(p.Input, "/source")
	if env.Kind != "media.mask_faces" || !strings.HasPrefix(dir, "job-mask-") || p.Output != dir+"/masked.mp4" || strings.Contains(dir, "/") {
		t.Fatalf("envelope = %+v payload = %+v", env, p)
	}
	if env.AssetID == nil || *env.AssetID != m.args.AssetID || strings.Contains(string(env.Payload), "t/") {
		t.Errorf("envelope identity or payload is wrong: %s", env.Payload)
	}
	if m.tasks.opts[0] == nil || m.tasks.opts[0].MaxAttempts != maskTaskAttempts {
		t.Errorf("task options = %+v", m.tasks.opts[0])
	}
	if !m.inputSeen {
		t.Error("the source was not in the job directory when the masker looked")
	}
	if got := m.workDirEntries(); len(got) != 0 {
		t.Errorf("job directory left behind: %v", got)
	}

	// The masked variant is published under its own prefix with its own key; the original is as it was.
	a := m.repo.snapshot()
	if a.MaskingState != db.MaskingReady || a.FacesDetected == nil || *a.FacesDetected != 3 || a.State != db.AssetReady {
		t.Fatalf("asset after masking: %+v", a)
	}
	masked := m.maskedKeys()
	if len(masked) != 4*(1+1+3)+1 {
		t.Fatalf("%d masked objects", len(masked))
	}
	m.originalUntouched()
	if len(m.delivery.keys()) != len(m.original)+len(masked) {
		t.Error("objects outside both variants' prefixes appeared")
	}
	for _, k := range masked {
		art, ok := m.repo.artifacts["delivery/"+k]
		if !ok || art.Variant != db.VariantMasked {
			t.Errorf("masked object %s is not registered as masked", k)
		}
	}
	for k, art := range m.repo.artifacts {
		if art.Variant == db.VariantMasked && !strings.Contains(k, "/masked/hls/") {
			t.Errorf("masked artifact %s is outside the masked prefix", k)
		}
	}
	if m.keys.key == nil || m.keys.maskedKey == nil || bytes.Equal(m.keys.key, m.keys.maskedKey) {
		t.Fatal("the masked variant did not get its own content key")
	}
	// Masked segments decrypt with the masked key and not the original's.
	name, _ := keys.ParseRendition("720p")
	pl := string(m.delivery.object(keys.VariantPlaylist(m.args.TenantID, m.args.AssetID, keys.Masked, name)))
	if strings.Count(pl, "IV=0x") != 3 {
		t.Fatalf("masked playlist:\n%s", pl)
	}
	ct := m.delivery.object(keys.VariantSegment(m.args.TenantID, m.args.AssetID, keys.Masked, name, 0))
	var iv hls.IV
	ivHex := pl[strings.Index(pl, "IV=0x")+5:][:32]
	for i := range iv {
		iv[i] = unhex(ivHex[2*i])<<4 | unhex(ivHex[2*i+1])
	}
	// The fake FFmpeg's plaintext map now holds what the masked transcode wrote.
	if got, err := hls.DecryptSegment(m.keys.maskedKey, iv, ct); err != nil || !bytes.Equal(got, m.tools.plaintext["720p/0"]) {
		t.Errorf("masked segment does not decrypt with the masked key: %v", err)
	}
	if got, err := hls.DecryptSegment(m.keys.key, iv, ct); err == nil && bytes.Equal(got, m.tools.plaintext["720p/0"]) {
		t.Error("the original key decrypts the masked segment")
	}

	// The manifest was signed again: valid signature, the original members as before, a masked section.
	sealed := *m.repo.manifest
	if bytes.Equal(sealed.Envelope, origManifest.Envelope) {
		t.Fatal("the manifest was not replaced")
	}
	signed, err := dsse.Decode(sealed.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	pub := m.signer.priv.Public().(ed25519.PublicKey)
	if _, err := dsse.Verify(signed, manifest.PayloadType, map[string]ed25519.PublicKey{fakeKeyID: pub}); err != nil {
		t.Fatalf("the new envelope does not verify: %v", err)
	}
	var got, was manifest.Manifest
	if err := json.Unmarshal(signed.Payload, &got); err != nil {
		t.Fatal(err)
	}
	oldEnv, _ := dsse.Decode(origManifest.Envelope)
	if err := json.Unmarshal(oldEnv.Payload, &was); err != nil {
		t.Fatal(err)
	}
	if got.Masked == nil || got.Masked.FacesDetected != 3 || got.Masked.Frames != 420 || len(got.Masked.Renditions) != 4 {
		t.Fatalf("masked section = %+v", got.Masked)
	}
	for _, r := range got.Masked.Renditions {
		for _, s := range append([]manifest.Object{r.Init}, r.Segments...) {
			if _, ok := m.repo.artifacts["delivery/"+keys.VariantHLSPrefix(m.args.TenantID, m.args.AssetID, keys.Masked)+s.Path]; !ok {
				t.Errorf("manifest names %s, which is not a registered masked object", s.Path)
			}
		}
	}
	got.Masked = nil
	if !reflect.DeepEqual(got, was) {
		t.Error("the original variant's manifest members changed")
	}
	if !bytes.Equal(sealed.TopRoot, origManifest.TopRoot) {
		t.Error("top_root is no longer the original variant's")
	}
}

func unhex(c byte) byte {
	if c >= 'A' {
		return c - 'A' + 10
	}
	return c - '0'
}

func TestMaskerFailureKeepsTheOriginalAndLeavesNothing(t *testing.T) {
	m := newMaskHarness(t)
	// Output of an earlier attempt that never got registered.
	m.delivery.objects[keys.VariantHLSPrefix(m.args.TenantID, m.args.AssetID, keys.Masked)+"720p/seg-0.m4s"] = []byte("partial")
	m.tasks.get = func(env jobs.Envelope, _ int) jobs.Task { return failedTask(env.TaskID, "decode_failed", false, 0) }

	err := m.runMask(1, 3)
	if !isCancel(err) {
		t.Fatalf("error = %v; want a cancelled job", err)
	}
	a := m.repo.snapshot()
	if a.State != db.AssetReady || a.MaskingState != db.MaskingFailed || a.FacesDetected != nil {
		t.Fatalf("asset = %+v", a)
	}
	if len(m.maskedKeys()) != 0 {
		t.Errorf("masked objects left: %v", m.maskedKeys())
	}
	m.originalUntouched()
	if m.repo.manifest == nil || m.repo.manifest.Envelope == nil {
		t.Error("the manifest was lost")
	}
	if got := m.workDirEntries(); len(got) != 0 {
		t.Errorf("job directory left behind: %v", got)
	}
}

func TestMaskerRetryableFailureIsWaitedOutWhileAttemptsRemain(t *testing.T) {
	m := newMaskHarness(t)
	m.tasks.get = func(env jobs.Envelope, call int) jobs.Task {
		switch call {
		case 1:
			return failedTask(env.TaskID, "encode_failed", true, 0) // the await job will requeue it
		case 2:
			return jobs.Task{State: jobs.StatePending, Attempts: 1}
		}
		return succeededTask(env.TaskID, `{"faces_detected":0,"frames":10}`)
	}
	if err := m.runMask(1, 3); err != nil {
		t.Fatal(err)
	}
	if a := m.repo.snapshot(); a.MaskingState != db.MaskingReady || a.FacesDetected == nil || *a.FacesDetected != 0 {
		t.Fatalf("asset = %+v; zero faces still publishes the masked variant", a)
	}
}

func TestMaskerRetryableFailureWithNoAttemptLeftIsFinal(t *testing.T) {
	m := newMaskHarness(t)
	m.tasks.get = func(env jobs.Envelope, _ int) jobs.Task { return failedTask(env.TaskID, "encode_failed", true, 1) }
	if err := m.runMask(1, 3); !isCancel(err) {
		t.Fatalf("error = %v", err)
	}
	if a := m.repo.snapshot(); a.MaskingState != db.MaskingFailed {
		t.Fatalf("masking state = %s", a.MaskingState)
	}
}

func TestMaskTimeoutFailsMasking(t *testing.T) {
	m := newMaskHarness(t)
	m.proc.MaskTimeout = 30 * time.Millisecond
	m.tasks.get = func(jobs.Envelope, int) jobs.Task { return jobs.Task{State: jobs.StatePending} }
	err := m.runMask(1, 3)
	if !isCancel(err) {
		t.Fatalf("error = %v; want a cancelled job", err)
	}
	if a := m.repo.snapshot(); a.State != db.AssetReady || a.MaskingState != db.MaskingFailed {
		t.Fatalf("asset = %+v", a)
	}
	m.originalUntouched()
}

func TestMaskerOutputThatBreaksTheContractFailsMasking(t *testing.T) {
	for name, output := range map[string]string{
		"missing frames":   `{"faces_detected":1}`,
		"negative":         `{"faces_detected":-1,"frames":5}`,
		"unknown member":   `{"faces_detected":1,"frames":5,"extra":true}`,
		"no output at all": ``,
	} {
		t.Run(name, func(t *testing.T) {
			m := newMaskHarness(t)
			m.tasks.get = func(env jobs.Envelope, _ int) jobs.Task { return succeededTask(env.TaskID, output) }
			if err := m.runMask(1, 3); !isCancel(err) {
				t.Fatalf("error = %v", err)
			}
			if a := m.repo.snapshot(); a.MaskingState != db.MaskingFailed {
				t.Fatalf("masking state = %s", a.MaskingState)
			}
			if len(m.maskedKeys()) != 0 {
				t.Error("masked objects were published")
			}
		})
	}
}

func TestMaskTranscodeErrorRetriesThenFails(t *testing.T) {
	m := newMaskHarness(t)
	m.tools.transcodeErr = errors.New("ffmpeg not running")
	// A partial upload of an earlier attempt, to prove a retry cleans the masked prefix first.
	stale := keys.VariantHLSPrefix(m.args.TenantID, m.args.AssetID, keys.Masked) + "480p/seg-9.m4s"
	m.delivery.objects[stale] = []byte("partial")

	err := m.runMask(1, 3)
	if err == nil || isCancel(err) {
		t.Fatalf("attempt 1 error = %v; want a retryable error", err)
	}
	if a := m.repo.snapshot(); a.MaskingState != db.MaskingPending {
		t.Fatalf("a retryable failure changed the masking state to %s", a.MaskingState)
	}
	if len(m.maskedKeys()) != 0 {
		t.Errorf("stale masked objects survived: %v", m.maskedKeys())
	}
	m.tasks.get = func(env jobs.Envelope, _ int) jobs.Task {
		return succeededTask(env.TaskID, `{"faces_detected":1,"frames":9}`)
	}
	if err := m.runMask(3, 3); err == nil || isCancel(err) {
		t.Fatalf("last attempt error = %v; want the underlying error", err)
	}
	if a := m.repo.snapshot(); a.MaskingState != db.MaskingFailed || a.State != db.AssetReady {
		t.Fatalf("asset = %+v", a)
	}
	m.originalUntouched()

	// And a clean retry later succeeds, replacing nothing it should not.
	m.tools.transcodeErr = nil
	if err := m.runMask(1, 3); err != nil {
		t.Fatal(err)
	}
	if a := m.repo.snapshot(); a.MaskingState != db.MaskingReady {
		t.Fatalf("masking state = %s", a.MaskingState)
	}
	m.originalUntouched()
}

func TestMaskRefusesASourceThatIsNotTheProcessedOne(t *testing.T) {
	m := newMaskHarness(t)
	m.source.objects[m.repo.asset.SourceKey] = bytes.Repeat([]byte("x"), len(m.sourceB))
	if err := m.runMask(1, 3); !isCancel(err) {
		t.Fatalf("error = %v", err)
	}
	if len(m.tasks.created) != 0 {
		t.Error("a task was created for a source that does not match")
	}
	if a := m.repo.snapshot(); a.MaskingState != db.MaskingFailed {
		t.Fatalf("masking state = %s", a.MaskingState)
	}
}

func TestMaskSourceIsStillThereAfterProcessing(t *testing.T) {
	m := newMaskHarness(t)
	if _, ok := m.source.objects[m.repo.asset.SourceKey]; !ok {
		t.Fatal("asset.process removed the source before masking could run")
	}
}

func TestMaskNothingToDo(t *testing.T) {
	t.Run("not a masking asset", func(t *testing.T) {
		m := newMaskHarness(t)
		m.repo.asset.MaskFaces, m.repo.asset.MaskingState = false, ""
		if err := m.runMask(1, 3); !isCancel(err) || len(m.tasks.created) != 0 {
			t.Fatalf("error = %v, tasks = %d", err, len(m.tasks.created))
		}
	})
	t.Run("already masked", func(t *testing.T) {
		m := newMaskHarness(t)
		m.repo.asset.MaskingState = db.MaskingReady
		if err := m.runMask(1, 3); err != nil || len(m.tasks.created) != 0 {
			t.Fatalf("error = %v, tasks = %d", err, len(m.tasks.created))
		}
	})
	t.Run("asset gone", func(t *testing.T) {
		m := newMaskHarness(t)
		m.repo.asset.State = db.AssetDeleted
		if err := m.runMask(1, 3); err != nil || len(m.tasks.created) != 0 {
			t.Fatalf("error = %v, tasks = %d", err, len(m.tasks.created))
		}
	})
	t.Run("no ids", func(t *testing.T) {
		m := newMaskHarness(t)
		if err := m.proc.HandleMask(context.Background(), jobs.Job[MaskArgs]{}); !isCancel(err) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestMaskAssetDeletedWhileMaskingLeavesNoOutput(t *testing.T) {
	m := newMaskHarness(t)
	m.tasks.get = func(env jobs.Envelope, call int) jobs.Task {
		if call == 1 {
			m.repo.mu.Lock()
			m.repo.asset.State = db.AssetDeleted
			m.repo.mu.Unlock()
			return jobs.Task{State: jobs.StateLeased}
		}
		return succeededTask(env.TaskID, `{"faces_detected":1,"frames":9}`)
	}
	if err := m.runMask(1, 3); err != nil {
		t.Fatal(err)
	}
	if len(m.maskedKeys()) != 0 || m.repo.maskingCompletes != 0 {
		t.Errorf("masked output left for a deleted asset: %v", m.maskedKeys())
	}
}

func TestMaskTaskIDsAreFreshPerAttempt(t *testing.T) {
	m := newMaskHarness(t)
	m.tools.transcodeErr = errors.New("ffmpeg not running")
	_ = m.runMask(1, 3)
	_ = m.runMask(2, 3)
	if len(m.tasks.created) != 2 || m.tasks.created[0].TaskID == (uuid.UUID{}) || m.tasks.created[0].TaskID == m.tasks.created[1].TaskID {
		t.Errorf("tasks = %+v", m.tasks.created)
	}
	if m.tasks.created[0].Payload == nil || bytes.Equal(m.tasks.created[0].Payload, m.tasks.created[1].Payload) {
		t.Error("each attempt must use its own job directory")
	}
}

func TestRegisterAddsAssetMaskOnlyWithTasks(t *testing.T) {
	d := Deps{
		Repo: newFakeRepo(db.Asset{}), Source: newMemStore(), Delivery: newMemStore(), Keys: &fakeKeys{}, Tools: &fakeTools{},
		Signer: newFakeSigner(), WorkDir: t.TempDir(), TranscodeTimeout: time.Minute,
	}
	reg := jobs.NewRegistry()
	if err := Register(reg, d); err != nil {
		t.Fatal(err)
	}
	if got := reg.Kinds(); !slices.Equal(got, []string{"asset.process"}) {
		t.Fatalf("kinds without tasks = %v", got)
	}
	d.Tasks, d.MaskTimeout = &fakeTasks{}, time.Hour
	reg = jobs.NewRegistry()
	if err := Register(reg, d); err != nil {
		t.Fatal(err)
	}
	if got := reg.Kinds(); !slices.Equal(got, []string{"asset.mask", "asset.process"}) {
		t.Fatalf("kinds with tasks = %v", got)
	}
	d.MaskTimeout = 0
	if _, err := NewProcessor(d); err == nil {
		t.Error("tasks without a mask timeout were accepted")
	}
}
