package pipeline

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

// ---- in-memory object store -------------------------------------------------------------------

type memStore struct {
	storage.Store // anything the pipeline does not use panics on the nil interface

	mu      sync.Mutex
	objects map[string][]byte
	// putFailAfter, when >= 0, makes every Put after that many successful ones fail once.
	putFailAfter int
	puts         int
	putFailed    bool
}

func newMemStore() *memStore { return &memStore{objects: map[string][]byte{}, putFailAfter: -1} }

func (m *memStore) Put(_ context.Context, key string, body io.Reader, size int64, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putFailAfter >= 0 && m.puts >= m.putFailAfter && !m.putFailed {
		m.putFailed = true
		return &storage.Error{Kind: storage.Unavailable, Op: "put"}
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(b)) != size {
		return errors.New("memStore: size mismatch")
	}
	m.objects[key] = b
	m.puts++
	return nil
}

func (m *memStore) Get(_ context.Context, key string, _ *storage.Range) (io.ReadCloser, storage.ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	if !ok {
		return nil, storage.ObjectInfo{}, &storage.Error{Kind: storage.NotFound, Op: "get"}
	}
	return io.NopCloser(bytes.NewReader(slices.Clone(b))), storage.ObjectInfo{Key: key, Size: int64(len(b))}, nil
}

func (m *memStore) List(_ context.Context, prefix, cursor string, limit int) (storage.Page, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ks []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) && k > cursor {
			ks = append(ks, k)
		}
	}
	sort.Strings(ks)
	page := storage.Page{}
	for i, k := range ks {
		if i == limit {
			page.NextCursor = ks[i-1]
			break
		}
		page.Objects = append(page.Objects, storage.ObjectInfo{Key: k, Size: int64(len(m.objects[k]))})
	}
	return page, nil
}

func (m *memStore) DeleteBatch(_ context.Context, keys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.objects, k)
	}
	return nil
}

func (m *memStore) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.objects))
	for k := range m.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *memStore) object(key string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.objects[key])
}

// ---- in-memory repository ---------------------------------------------------------------------

type fakeRepo struct {
	mu          sync.Mutex
	asset       db.Asset
	artifacts   map[string]db.Artifact
	transitions []db.Transition
	progress    []int
	// manifest is the stored manifest, nil when there is none; manifestDeletes counts the calls
	// that removed one.
	manifest        *db.AssetManifest
	manifestDeletes int
}

func newFakeRepo(a db.Asset) *fakeRepo {
	return &fakeRepo{asset: a, artifacts: map[string]db.Artifact{}}
}

func (r *fakeRepo) GetAsset(context.Context, id.TenantID, id.AssetID) (db.Asset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.asset, nil
}

func (r *fakeRepo) TransitionAsset(_ context.Context, _ id.TenantID, _ id.AssetID, t db.Transition) (db.Asset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !t.From.CanTransitionTo(t.To) {
		return db.Asset{}, errs.New(errs.InternalError, "bad edge")
	}
	if r.asset.State != t.From {
		return db.Asset{}, errs.Wrap(errs.Conflict, "state", db.ErrStateChanged)
	}
	r.asset.State = t.To
	if t.To == db.AssetFailed {
		r.asset.FailureCode = t.FailureCode
	}
	r.transitions = append(r.transitions, t)
	return r.asset, nil
}

func (r *fakeRepo) RecordSource(_ context.Context, _ id.TenantID, _ id.AssetID, sha []byte, size int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.asset.State != db.AssetProcessing {
		return errs.Wrap(errs.Conflict, "state", db.ErrStateChanged)
	}
	r.asset.SourceSHA256, r.asset.SourceSizeBytes = slices.Clone(sha), size
	return nil
}

func (r *fakeRepo) SetProgress(_ context.Context, _ id.TenantID, _ id.AssetID, p int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p > r.asset.Progress {
		r.asset.Progress = p
		r.progress = append(r.progress, p)
	}
	return nil
}

func (r *fakeRepo) ResetProgress(context.Context, id.TenantID, id.AssetID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asset.Progress = 0
	return nil
}

func (r *fakeRepo) DeleteHLSArtifacts(context.Context, id.AssetID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := int64(len(r.artifacts))
	r.artifacts = map[string]db.Artifact{}
	return n, nil
}

func (r *fakeRepo) DeleteManifest(context.Context, id.AssetID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	had := r.manifest != nil
	if had {
		r.manifestDeletes++
	}
	r.manifest = nil
	return had, nil
}

func (r *fakeRepo) Complete(_ context.Context, _ id.TenantID, _ id.AssetID, arts []db.Artifact, c db.Completion) (db.Asset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.asset.State != db.AssetProcessing {
		return db.Asset{}, errs.Wrap(errs.Conflict, "state", db.ErrStateChanged)
	}
	if r.manifest != nil && c.Manifest != nil {
		return db.Asset{}, errors.New("duplicate manifest")
	}
	for _, a := range arts {
		r.artifacts[a.Bucket+"/"+a.ObjectKey] = a
	}
	if c.Manifest != nil {
		m := *c.Manifest
		r.manifest = &m
	}
	r.asset.State = db.AssetReady
	r.asset.DurationMS = c.Duration.Milliseconds()
	r.asset.Renditions = c.Renditions
	r.asset.Progress = 100
	return r.asset, nil
}

func (r *fakeRepo) snapshot() db.Asset {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.asset
}

// ---- content key source -----------------------------------------------------------------------

type fakeKeys struct {
	mu      sync.Mutex
	key     []byte
	creates int
	calls   int
	events  *[]string
}

func (k *fakeKeys) Ensure(context.Context, id.TenantID, id.AssetID) (Key, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls++
	if k.key == nil {
		k.key = make([]byte, contentkey.KeyBytes)
		if _, err := rand.Read(k.key); err != nil {
			return nil, err
		}
		k.creates++
	}
	if k.events != nil {
		*k.events = append(*k.events, "key")
	}
	return testKey{b: slices.Clone(k.key)}, nil
}

type testKey struct{ b []byte }

func (t testKey) Bytes() []byte { return slices.Clone(t.b) }
func (t testKey) Zero()         { clear(t.b) }

// ---- fake FFmpeg ------------------------------------------------------------------------------

type fakeTools struct {
	info         media.Info
	probeErr     error
	transcodeErr error
	// segments are the durations of the segments every rendition gets.
	segments []time.Duration
	events   *[]string
	// block, when set, makes Transcode wait for ctx to end; started is closed when it begins.
	block   bool
	started chan struct{}

	probes, transcodes int
	versionCalls       int
	versionErr         error
	// plaintext records what the fake wrote per rendition and segment index.
	mu        sync.Mutex
	plaintext map[string][]byte
	lastSpec  media.TranscodeSpec
}

func (f *fakeTools) Version(context.Context) (string, error) {
	f.versionCalls++
	if f.versionErr != nil {
		return "", f.versionErr
	}
	return "ffmpeg version test-fixture", nil
}

func (f *fakeTools) Probe(context.Context, string) (media.Info, error) {
	f.probes++
	return f.info, f.probeErr
}

func (f *fakeTools) Transcode(ctx context.Context, spec media.TranscodeSpec, progress func(time.Duration)) error {
	f.transcodes++
	f.lastSpec = spec
	if f.events != nil {
		*f.events = append(*f.events, "transcode")
	}
	if f.block {
		close(f.started)
		<-ctx.Done()
		return ctx.Err()
	}
	if f.transcodeErr != nil {
		return f.transcodeErr
	}
	if progress != nil {
		progress(f.info.Duration / 2)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.plaintext == nil {
		f.plaintext = map[string][]byte{}
	}
	for _, r := range spec.Renditions {
		dir := spec.RenditionDir(r)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, media.InitFile), fakeInit(f.info.Audio != nil), 0o600); err != nil {
			return err
		}
		var pl strings.Builder
		pl.WriteString("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:6\n#EXT-X-MAP:URI=\"init.mp4\"\n")
		for i, d := range f.segments {
			body := make([]byte, 700+97*i+3*r.Height)
			if _, err := rand.Read(body); err != nil {
				return err
			}
			name := fmt.Sprintf("seg_%d.m4s", media.FirstSegmentNumber+i)
			if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
				return err
			}
			f.plaintext[fmt.Sprintf("%s/%d", r.Name, i)] = body
			fmt.Fprintf(&pl, "#EXTINF:%.6f,\n%s\n", d.Seconds(), name)
		}
		pl.WriteString("#EXT-X-ENDLIST\n")
		if err := os.WriteFile(filepath.Join(dir, media.PlaylistFile), []byte(pl.String()), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func box(typ string, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	out := binary.BigEndian.AppendUint32(nil, uint32(8+len(body))) //nolint:gosec // small test data
	out = append(out, typ...)
	return append(out, body...)
}

func descriptor(tag byte, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	return append([]byte{tag, byte(len(body))}, body...) //nolint:gosec // small test data
}

// fakeInit is a minimal init segment with an avc1 (High, level 4.0) and optionally an mp4a (AAC-LC)
// sample entry, enough for the codec strings.
func fakeInit(audio bool) []byte {
	avc1 := box("avc1", make([]byte, 78), box("avcC", []byte{1, 0x64, 0x00, 0x28, 0xff, 0xe1}))
	parts := [][]byte{box("stsd", []byte{0, 0, 0, 0, 0, 0, 0, 1}, avc1)}
	if audio {
		asc := descriptor(0x05, []byte{2 << 3, 0x10})
		dec := descriptor(0x04, []byte{0x40, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, asc)
		es := descriptor(0x03, []byte{0, 2, 0}, dec)
		mp4a := box("mp4a", make([]byte, 28), box("esds", []byte{0, 0, 0, 0}, es))
		parts = append(parts, box("stsd", []byte{0, 0, 0, 0, 0, 0, 0, 1}, mp4a))
	}
	return box("moov", parts...)
}

func landscapeInfo() media.Info {
	return media.Info{
		Container: media.ContainerMP4, Duration: 14 * time.Second,
		Video: &media.VideoStream{Index: 0, Codec: "h264", Width: 1280, Height: 720, DisplayWidth: 1280, DisplayHeight: 720, FrameRate: 30},
		Audio: &media.AudioStream{Index: 1, Codec: "aac", Channels: 2, SampleRate: 48000},
	}
}

// ---- signer -----------------------------------------------------------------------------------

// fakeSigner signs with an Ed25519 key made from a fixed seed.
type fakeSigner struct {
	mu    sync.Mutex
	priv  ed25519.PrivateKey
	keyID string
	err   error
	calls int
}

const fakeKeyID = "sk_0123456789abcdefghjkmnpqrs"

func newFakeSigner() *fakeSigner {
	seed := sha256.Sum256([]byte("test-fixture-pipeline-signer-seed"))
	return &fakeSigner{priv: ed25519.NewKeyFromSeed(seed[:]), keyID: fakeKeyID}
}

func (s *fakeSigner) Sign(_ context.Context, message []byte) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return "", nil, s.err
	}
	return s.keyID, ed25519.Sign(s.priv, message), nil
}

func (s *fakeSigner) PublicKeys(context.Context) ([]signing.PublicKey, error) {
	return []signing.PublicKey{{KeyID: s.keyID, Algorithm: signing.AlgEd25519, PublicKey: s.priv.Public().(ed25519.PublicKey)}}, nil
}
