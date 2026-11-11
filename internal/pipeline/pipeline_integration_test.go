//go:build integration && media

package pipeline_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// The pipeline test runs the real thing end to end: real FFmpeg and FFprobe (the worker image's
// static binaries), real Postgres and real SeaweedFS (testcontainers). It needs:
//
//	CIPHERFRAME_TEST_FFMPEG           the worker image's ffmpeg
//	CIPHERFRAME_TEST_FFPROBE          the worker image's ffprobe
//	CIPHERFRAME_TEST_FFMPEG_FIXTURES  the test-only generator, which also has the ssim filter
//
// FFmpeg only exists as Linux binaries, so on macOS the whole run happens inside a Linux
// container: see CONTRIBUTING.md, "Media and pipeline tests".

func TestMain(m *testing.M) {
	code := dbtest.Run(m)
	storagetest.Terminate()
	os.Exit(code)
}

func envPath(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set (see the comment at the top of this file)", name)
	}
	return v
}

// rig is one worker with a fresh database, the shared object store and the real tools.
type rig struct {
	t       *testing.T
	pool    *pgxpool.Pool
	repos   *db.Repos
	buckets *storage.Buckets
	mgr     *contentkey.Manager
	proc    *pipeline.Processor
	tenant  db.Tenant
	client  db.Client
	workDir string
	logs    *bytes.Buffer
	tools   media.Tools
}

func newRig(t *testing.T) *rig {
	t.Helper()
	tools := media.Tools{FFmpeg: envPath(t, "CIPHERFRAME_TEST_FFMPEG"), FFprobe: envPath(t, "CIPHERFRAME_TEST_FFPROBE")}
	pool := dbtest.NewMigrated(t)
	sw := storagetest.Shared(t)
	buckets, err := storage.New(context.Background(), sw.Config())
	if err != nil {
		t.Fatal(err)
	}
	p, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := kms.NewRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, pool: pool, repos: db.New(pool), buckets: buckets, workDir: t.TempDir(), logs: &bytes.Buffer{}, tools: tools}
	r.mgr = contentkey.NewManager(pool, reg, slog.New(slog.DiscardHandler))
	ctx := context.Background()
	if r.tenant, err = r.repos.CreateTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if r.client, err = r.repos.CreateClient(ctx, r.tenant.ID, "acme-client"); err != nil {
		t.Fatal(err)
	}
	r.proc, err = pipeline.NewProcessor(pipeline.Deps{
		Repo: pipeline.NewDBRepo(pool), Source: buckets.Source, Delivery: buckets.Delivery,
		Keys: pipeline.ContentKeys{Pool: pool, Manager: r.mgr}, Tools: tools,
		Limits:  media.Limits{MaxDuration: time.Hour, MaxWidth: 3840, MaxHeight: 2160},
		WorkDir: r.workDir, TranscodeTimeout: 10 * time.Minute,
		Log: slog.New(slog.NewTextHandler(r.logs, nil)), ProgressInterval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// generate makes a fixture with the test-only FFmpeg.
func generate(t *testing.T, s testmedia.Spec) string {
	t.Helper()
	g := testmedia.Generator{FFmpeg: envPath(t, "CIPHERFRAME_TEST_FFMPEG_FIXTURES")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	p, err := g.Generate(ctx, t.TempDir(), s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// commit stores the file as an asset's source and walks the asset to committed, the way the
// upload API does. It returns the asset and the SHA-256 of the file, hashed here independently.
func (r *rig) commit(file string) (db.Asset, [sha256.Size]byte) {
	r.t.Helper()
	ctx := context.Background()
	data, err := os.ReadFile(file) //nolint:gosec // a fixture the test just generated
	if err != nil {
		r.t.Fatal(err)
	}
	assetID := id.New[id.AssetKind]()
	srcKey := keys.NewSource(r.tenant.ID, assetID)
	a, err := r.repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: assetID, TenantID: r.tenant.ID, ClientID: r.client.ID, SizeBytes: int64(len(data)), ContentType: "video/mp4",
		Method: db.UploadMultipart, SourceKey: srcKey, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.buckets.Source.Put(ctx, srcKey, bytes.NewReader(data), int64(len(data)), "video/mp4"); err != nil {
		r.t.Fatal(err)
	}
	for _, step := range [][2]db.AssetState{{db.AssetCreated, db.AssetUploading}, {db.AssetUploading, db.AssetCommitted}} {
		if a, err = r.repos.TransitionAsset(ctx, r.tenant.ID, assetID, db.Transition{From: step[0], To: step[1]}); err != nil {
			r.t.Fatal(err)
		}
	}
	return a, sha256.Sum256(data)
}

func (r *rig) process(a db.Asset) error {
	return r.proc.Handle(context.Background(), jobs.Job[uploads.ProcessArgs]{
		ID: 1, Args: uploads.ProcessArgs{TenantID: a.TenantID, AssetID: a.ID}, Attempt: 1, MaxAttempts: 5,
	})
}

func (r *rig) key(a db.Asset) []byte {
	r.t.Helper()
	k, err := r.mgr.Get(context.Background(), a.TenantID, a.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	defer k.Zero()
	return k.Bytes()
}

func (r *rig) get(bucket storage.Store, key string) []byte {
	r.t.Helper()
	rc, _, err := bucket.Get(context.Background(), key, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	var b bytes.Buffer
	if _, err := b.ReadFrom(rc); err != nil {
		r.t.Fatal(err)
	}
	return b.Bytes()
}

// ---- reading what the pipeline stored ---------------------------------------------------------

type storedPlaylist struct {
	initURI  string
	segments []string
	ivs      []hls.IV
	durs     []float64
}

var (
	ivAttr   = regexp.MustCompile(`IV=0x([0-9A-Fa-f]{32})`)
	extinfRe = regexp.MustCompile(`^#EXTINF:([0-9.]+),`)
)

func parsePlaylist(t *testing.T, text string) storedPlaylist {
	t.Helper()
	var p storedPlaylist
	var pendingIV *hls.IV
	var pendingDur float64
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "#EXT-X-MAP:"):
			p.initURI = strings.Trim(strings.TrimPrefix(line, "#EXT-X-MAP:URI="), `"`)
		case strings.HasPrefix(line, "#EXT-X-KEY:"):
			m := ivAttr.FindStringSubmatch(line)
			if m == nil || !strings.Contains(line, `METHOD=AES-128`) || !strings.Contains(line, `URI="cipherframe-key"`) {
				t.Fatalf("bad key line %q", line)
			}
			raw, _ := hex.DecodeString(m[1])
			var iv hls.IV
			copy(iv[:], raw)
			pendingIV = &iv
		case extinfRe.MatchString(line):
			pendingDur, _ = strconv.ParseFloat(extinfRe.FindStringSubmatch(line)[1], 64)
		case line != "" && !strings.HasPrefix(line, "#"):
			if pendingIV == nil {
				t.Fatal("segment without a key tag")
			}
			p.segments, p.ivs, p.durs = append(p.segments, line), append(p.ivs, *pendingIV), append(p.durs, pendingDur)
			pendingIV = nil
		}
	}
	return p
}

type packet struct {
	Type  string
	PTS   float64
	Flags string
}

// probePackets runs the worker's ffprobe over a file and returns its packets. It is the check that
// a file parses as fMP4: a failure to parse is an error.
func probePackets(t *testing.T, tools media.Tools, file string) ([]packet, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tools.FFprobe, "-hide_banner", "-v", "error", "-protocol_whitelist", "file,pipe", //nolint:gosec // test: argument array
		"-print_format", "json", "-show_entries", "packet=codec_type,pts_time,flags", "-show_packets", "-i", "file:"+file)
	cmd.Env = []string{"LC_ALL=C"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ffprobe failed: %w: %s", err, stderr.String())
	}
	var doc struct {
		Packets []struct {
			CodecType string `json:"codec_type"`
			PTSTime   string `json:"pts_time"`
			Flags     string `json:"flags"`
		} `json:"packets"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	var ps []packet
	for _, p := range doc.Packets {
		pts, _ := strconv.ParseFloat(p.PTSTime, 64)
		ps = append(ps, packet{Type: p.CodecType, PTS: pts, Flags: p.Flags})
	}
	return ps, nil
}

// minPTS returns the earliest presentation time of a stream type among packets.
func minPTS(ps []packet, typ string) (float64, bool) {
	best, ok := math.Inf(1), false
	for _, p := range ps {
		if p.Type == typ && p.PTS < best {
			best, ok = p.PTS, true
		}
	}
	return best, ok
}

// segmentFile writes init + segment into a file ffprobe can open. When raw is true the stored
// (encrypted) bytes are used as they are; otherwise the segment is decrypted first.
func (r *rig) segmentFile(a db.Asset, rendition string, n int, key []byte, iv hls.IV, raw bool) string {
	r.t.Helper()
	name, _ := keys.ParseRendition(rendition)
	body := r.get(r.buckets.Delivery, keys.Segment(a.TenantID, a.ID, name, n))
	if !raw {
		var err error
		if body, err = hls.DecryptSegment(key, iv, body); err != nil {
			r.t.Fatalf("%s segment %d: %v", rendition, n, err)
		}
	}
	data := append(r.get(r.buckets.Delivery, keys.InitSegment(a.TenantID, a.ID, name)), body...)
	f := filepath.Join(r.t.TempDir(), fmt.Sprintf("%s-%d.mp4", rendition, n))
	if err := os.WriteFile(f, data, 0o600); err != nil {
		r.t.Fatal(err)
	}
	return f
}

type renditionInfo = pipeline.RenditionSummary

func summaryOf(t *testing.T, a db.Asset) []renditionInfo {
	t.Helper()
	var s []renditionInfo
	if err := json.Unmarshal(a.Renditions, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// ---- the main test: a 20 s 720p source --------------------------------------------------------

func TestPipelineEndToEnd(t *testing.T) {
	start := time.Now()
	r := newRig(t)
	ctx := context.Background()
	src := generate(t, testmedia.Spec{Name: "source.mp4", Width: 1280, Height: 720, Duration: 20 * time.Second, FPS: 30, Audio: true})
	asset, sourceSum := r.commit(src)
	if st, _ := os.Stat(src); st != nil {
		t.Logf("source: %d bytes, 1280x720, 20 s, 30 fps, H.264 + AAC", st.Size())
	}

	t0 := time.Now()
	if err := r.process(asset); err != nil {
		t.Fatalf("asset.process: %v\n%s", err, r.logs.String())
	}
	t.Logf("asset.process took %s", time.Since(t0).Round(time.Millisecond))

	a, err := r.repos.GetAsset(ctx, asset.TenantID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != db.AssetReady || a.Progress != 100 || a.ReadyAt == nil {
		t.Fatalf("asset = %s, progress %d", a.State, a.Progress)
	}
	// The hash taken while streaming equals one computed independently from the file.
	if !bytes.Equal(a.SourceSHA256, sourceSum[:]) || a.SourceSizeBytes != asset.SizeBytes {
		t.Fatalf("source hash/size = %x / %d, want %x / %d", a.SourceSHA256, a.SourceSizeBytes, sourceSum, asset.SizeBytes)
	}
	if d := time.Duration(a.DurationMS) * time.Millisecond; d < 19*time.Second || d > 21*time.Second {
		t.Errorf("duration = %s", d)
	}

	// Renditions: 720p, 480p, 360p, 240p and never an upscale to 1080p.
	sum := summaryOf(t, a)
	var names []string
	for _, s := range sum {
		names = append(names, s.Name)
	}
	if !slices.Equal(names, []string{"720p", "480p", "360p", "240p"}) {
		t.Fatalf("renditions = %v", names)
	}
	for _, s := range sum {
		if s.Segments != 4 {
			t.Errorf("%s has %d segments, want 4 (6+6+6+2 s)", s.Name, s.Segments)
		}
		if !strings.HasPrefix(s.Codecs, "avc1.64") || !strings.HasSuffix(s.Codecs, ",mp4a.40.2") {
			t.Errorf("%s codecs = %q", s.Name, s.Codecs)
		}
	}

	// ---- registry: every delivery object is an artifact and every artifact exists ----
	arts, err := r.repos.ListArtifacts(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]storage.ObjectInfo{}
	for o, err := range storage.ListAll(ctx, r.buckets.Delivery, keys.DeliveryPrefix(a.TenantID, a.ID)) {
		if err != nil {
			t.Fatal(err)
		}
		listed[o.Key] = o
	}
	if len(arts) != len(listed) || len(arts) != 4*(1+1+4)+1 {
		t.Fatalf("%d artifacts, %d delivery objects", len(arts), len(listed))
	}
	for _, art := range arts {
		o, ok := listed[art.ObjectKey]
		if !ok || art.Bucket != "delivery" || o.Size != art.SizeBytes {
			t.Errorf("artifact %s: stored=%v size=%d vs %d", art.ObjectKey, ok, o.Size, art.SizeBytes)
			continue
		}
		stored := sha256.Sum256(r.get(r.buckets.Delivery, art.ObjectKey))
		if !bytes.Equal(art.SHA256, stored[:]) {
			t.Errorf("artifact %s: the registered hash is not the hash of the stored bytes", art.ObjectKey)
		}
	}

	// ---- the work directory is empty ----
	if es, err := os.ReadDir(r.workDir); err != nil || len(es) != 0 {
		t.Errorf("work directory after the job: %v, %v", es, err)
	}

	key := r.key(a)
	defer clear(key)
	t.Run("segments are undecryptable without the key", func(t *testing.T) { checkEncryption(t, r, a, key) })
	t.Run("segment start PTS is identical across renditions", func(t *testing.T) { checkAlignment(t, r, a, key) })
	t.Run("size per rung and quality", func(t *testing.T) { checkSizeAndQuality(t, r, a, key, src, sum) })

	// ---- a retry is idempotent: the output is rebuilt, the key is reused ----
	t.Run("retry rebuilds the same set and reuses the key", func(t *testing.T) {
		before := slices.Clone(key)
		if _, err := r.pool.Exec(ctx, "UPDATE assets SET state = 'processing', progress = 0 WHERE id = $1", pgtype.UUID{Bytes: [16]byte(a.ID.UUID()), Valid: true}); err != nil {
			t.Fatal(err)
		}
		if err := r.process(a); err != nil {
			t.Fatalf("retry: %v\n%s", err, r.logs.String())
		}
		after := r.key(a)
		defer clear(after)
		if !bytes.Equal(before, after) {
			t.Fatal("the content key changed on retry")
		}
		again, err := r.repos.ListArtifacts(ctx, a.ID)
		if err != nil || len(again) != len(arts) {
			t.Fatalf("artifacts after the retry: %d, %v", len(again), err)
		}
		n := 0
		for o, err := range storage.ListAll(ctx, r.buckets.Delivery, keys.DeliveryPrefix(a.TenantID, a.ID)) {
			if err != nil {
				t.Fatal(err)
			}
			n++
			_ = o
		}
		if n != len(arts) {
			t.Fatalf("%d delivery objects after the retry, want %d", n, len(arts))
		}
	})
	t.Logf("total test time %s", time.Since(start).Round(time.Millisecond))
}

// checkEncryption: segments fetched straight from storage are not media; they are media after
// decryption with the key and the IV from the playlist, and the init segment is plain.
func checkEncryption(t *testing.T, r *rig, a db.Asset, key []byte) {
	for _, rendition := range []string{"720p", "240p"} {
		name, _ := keys.ParseRendition(rendition)
		pl := parsePlaylist(t, string(r.get(r.buckets.Delivery, keys.Playlist(a.TenantID, a.ID, name))))
		if pl.initURI != "init.mp4" || len(pl.segments) != 4 {
			t.Fatalf("%s playlist: %+v", rendition, pl)
		}
		for n := range pl.segments {
			stored := r.get(r.buckets.Delivery, keys.Segment(a.TenantID, a.ID, name, n))
			if len(stored)%16 != 0 || len(stored) < 16 {
				t.Fatalf("%s segment %d: %d bytes is not a whole number of AES blocks", rendition, n, len(stored))
			}
			// An fMP4 segment starts with a box header (styp or moof); ciphertext does not.
			if head := string(stored[4:8]); head == "styp" || head == "moof" || head == "ftyp" {
				t.Fatalf("%s segment %d is stored as plain fMP4", rendition, n)
			}
			rawFile := r.segmentFile(a, rendition, n, key, pl.ivs[n], true)
			if ps, err := probePackets(t, r.tools, rawFile); err == nil && len(ps) > 0 {
				t.Fatalf("%s segment %d: ffprobe read %d packets from the stored bytes", rendition, n, len(ps))
			}
			plainFile := r.segmentFile(a, rendition, n, key, pl.ivs[n], false)
			ps, err := probePackets(t, r.tools, plainFile)
			if err != nil || len(ps) == 0 {
				t.Fatalf("%s segment %d does not parse after decrypting: %v", rendition, n, err)
			}
			// The wrong key does not give media either.
			wrong := slices.Clone(key)
			wrong[0] ^= 1
			if got, err := hls.DecryptSegment(wrong, pl.ivs[n], stored); err == nil && len(got) > 8 && string(got[4:8]) == "moof" {
				t.Fatal("decrypted with the wrong key")
			}
		}
		// Every segment has its own IV.
		seen := map[hls.IV]bool{}
		for _, iv := range pl.ivs {
			if seen[iv] {
				t.Fatalf("%s: an IV is used twice", rendition)
			}
			seen[iv] = true
		}
	}
	// The init segment is stored in the clear: it is codec configuration, and it parses.
	name, _ := keys.ParseRendition("720p")
	init := r.get(r.buckets.Delivery, keys.InitSegment(a.TenantID, a.ID, name))
	if len(init) < 8 || string(init[4:8]) != "ftyp" {
		t.Error("the init segment is not a plain fMP4 init segment")
	}
	// Neither the key nor its hex or base64 form appears in any stored object.
	for o, err := range storage.ListAll(context.Background(), r.buckets.Delivery, keys.DeliveryPrefix(a.TenantID, a.ID)) {
		if err != nil {
			t.Fatal(err)
		}
		body := r.get(r.buckets.Delivery, o.Key)
		if bytes.Contains(body, key) || bytes.Contains(body, []byte(hex.EncodeToString(key))) {
			t.Errorf("%s contains the content key", o.Key)
		}
	}
	if strings.Contains(r.logs.String(), hex.EncodeToString(key)) {
		t.Error("the key is in the logs")
	}
}

// checkAlignment is pitfall 4: switching rendition at a segment boundary must land on the same
// timestamp. The earliest video (and audio) presentation time of segment N, read by ffprobe from
// the decrypted segment with its init segment, must be the same in every rendition, and
// each segment must begin with a keyframe.
func checkAlignment(t *testing.T, r *rig, a db.Asset, key []byte) {
	type start struct{ video, audio float64 }
	starts := map[string][]start{}
	var order []string
	for _, s := range summaryOf(t, a) {
		order = append(order, s.Name)
		name, _ := keys.ParseRendition(s.Name)
		pl := parsePlaylist(t, string(r.get(r.buckets.Delivery, keys.Playlist(a.TenantID, a.ID, name))))
		for n := range pl.segments {
			ps, err := probePackets(t, r.tools, r.segmentFile(a, s.Name, n, key, pl.ivs[n], false))
			if err != nil {
				t.Fatal(err)
			}
			v, ok := minPTS(ps, "video")
			if !ok {
				t.Fatalf("%s segment %d has no video", s.Name, n)
			}
			au, _ := minPTS(ps, "audio")
			// The first packet in decode order of a segment is a keyframe.
			for _, p := range ps {
				if p.Type == "video" {
					if !strings.Contains(p.Flags, "K") {
						t.Errorf("%s segment %d does not start with a keyframe", s.Name, n)
					}
					break
				}
			}
			starts[s.Name] = append(starts[s.Name], start{v, au})
		}
	}
	ref := starts[order[0]]
	for n, s := range ref {
		want := float64(n * media.SegmentSeconds)
		if math.Abs(s.video-want) > 0.25 {
			t.Errorf("segment %d starts at %.4f s, expected about %.0f s", n, s.video, want)
		}
	}
	for _, name := range order[1:] {
		for n, s := range starts[name] {
			if s.video != ref[n].video {
				t.Errorf("segment %d: %s starts at %.6f s but %s at %.6f s", n, name, s.video, order[0], ref[n].video)
			}
			if math.Abs(s.audio-ref[n].audio) > 1e-6 {
				t.Errorf("segment %d: %s audio starts at %.6f s but %s at %.6f s", n, name, s.audio, order[0], ref[n].audio)
			}
		}
	}
	t.Logf("segment start PTS (s), identical on %v: %v", order, starts[order[0]])
}

// checkSizeAndQuality reports the size of every rung (pitfall 11) and measures the 720p rung against
// the source with SSIM and PSNR. Only the test-only FFmpeg has those filters.
func checkSizeAndQuality(t *testing.T, r *rig, a db.Asset, key []byte, src string, sum []renditionInfo) {
	dur := time.Duration(a.DurationMS) * time.Millisecond
	caps := map[string]int64{"720p": 2500, "480p": 1200, "360p": 700, "240p": 350}
	for _, s := range sum {
		kbps := float64(s.Bytes) * 8 / dur.Seconds() / 1000
		t.Logf("size %-4s  %8d bytes  avg %7.1f kbit/s  peak %7d kbit/s  (cap %d + 96 audio)", s.Name, s.Bytes, kbps, s.Bandwidth/1000, caps[s.Name])
		// VBV: total video bits stay under maxrate x duration plus one buffer (2 x maxrate bits);
		// add the audio and 10% for container overhead.
		limit := (float64(caps[s.Name]+96)*1000*dur.Seconds() + float64(caps[s.Name])*2*1000) * 1.10
		if float64(s.Bytes)*8 > limit {
			t.Errorf("%s is %.0f kbit/s, over the capped rate", s.Name, kbps)
		}
	}
	for i := 1; i < len(sum); i++ {
		if sum[i].Bytes >= sum[i-1].Bytes {
			t.Errorf("%s (%d bytes) is not smaller than %s (%d bytes)", sum[i].Name, sum[i].Bytes, sum[i-1].Name, sum[i-1].Bytes)
		}
	}

	// Reassemble the 720p rendition from its decrypted segments.
	name, _ := keys.ParseRendition("720p")
	pl := parsePlaylist(t, string(r.get(r.buckets.Delivery, keys.Playlist(a.TenantID, a.ID, name))))
	whole := r.get(r.buckets.Delivery, keys.InitSegment(a.TenantID, a.ID, name))
	for n := range pl.segments {
		plain, err := hls.DecryptSegment(key, pl.ivs[n], r.get(r.buckets.Delivery, keys.Segment(a.TenantID, a.ID, name, n)))
		if err != nil {
			t.Fatal(err)
		}
		whole = append(whole, plain...)
	}
	rendition := filepath.Join(t.TempDir(), "720p.mp4")
	if err := os.WriteFile(rendition, whole, 0o600); err != nil {
		t.Fatal(err)
	}

	gen := envPath(t, "CIPHERFRAME_TEST_FFMPEG_FIXTURES")
	ssim := measure(t, gen, rendition, src, "ssim", `All:([0-9.]+)`)
	psnr := measure(t, gen, rendition, src, "psnr", `average:([0-9.]+)`)
	t.Logf("720p rung vs source: SSIM %.4f, PSNR %.2f dB", ssim, psnr)
	// The floor. Measured on this fixture: SSIM 0.994 and PSNR 43 dB at 2.7 Mbit/s. testsrc2 is
	// synthetic, sharp-edged, high-detail content that stresses a capped encode harder than camera
	// footage, so real talking-head video scores higher. A faithful encode stays far above 0.97
	// whatever the CPU architecture (SIMD paths differ in the last bits only); a wrong scale, colour
	// conversion, frame misalignment or broken rate control gives 0.9 or lower. 0.97 leaves room for
	// platform drift and still catches all of those.
	const ssimFloor = 0.97
	if ssim < ssimFloor {
		t.Errorf("SSIM of the 720p rung against the source = %.4f, floor %.2f", ssim, ssimFloor)
	}
}

// measure runs the test-only FFmpeg's ssim or psnr filter on (rendition, source) and parses the
// summary line it logs.
func measure(t *testing.T, ffmpeg, rendition, source, filter, pattern string) float64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpeg, "-hide_banner", "-nostdin", "-v", "info", "-protocol_whitelist", "file,pipe", //nolint:gosec // test: argument array
		"-i", "file:"+rendition, "-i", "file:"+source,
		"-filter_complex", "[0:v][1:v]"+filter, "-an", "-f", "null", "-")
	cmd.Env = []string{"LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s measurement failed: %v\n%s", filter, err, out)
	}
	ms := regexp.MustCompile(pattern).FindAllSubmatch(out, -1)
	if len(ms) == 0 {
		t.Fatalf("no %s result in the output:\n%s", filter, out)
	}
	v, err := strconv.ParseFloat(string(ms[len(ms)-1][1]), 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ---- a rotated phone video ---------------------------------------------------------------------

func TestPipelineRotatedPortraitSource(t *testing.T) {
	r := newRig(t)
	// A 640x360 stored frame with a 90 degree display matrix: a 360x640 portrait picture.
	src := generate(t, testmedia.Spec{Name: "portrait.mp4", Width: 640, Height: 360, Duration: 8 * time.Second, FPS: 30, Audio: true, Rotation: 90})
	asset, _ := r.commit(src)
	if err := r.process(asset); err != nil {
		t.Fatalf("asset.process: %v\n%s", err, r.logs.String())
	}
	a, err := r.repos.GetAsset(context.Background(), asset.TenantID, asset.ID)
	if err != nil || a.State != db.AssetReady {
		t.Fatalf("asset: %v, %v", a.State, err)
	}
	sum := summaryOf(t, a)
	var names []string
	key := r.key(a)
	defer clear(key)
	for _, s := range sum {
		names = append(names, s.Name)
		if s.Width >= s.Height {
			t.Errorf("%s is %dx%d: a portrait source must give portrait renditions", s.Name, s.Width, s.Height)
		}
		// The encoded frames really are portrait, and carry no rotation for a player to apply.
		name, _ := keys.ParseRendition(s.Name)
		pl := parsePlaylist(t, string(r.get(r.buckets.Delivery, keys.Playlist(a.TenantID, a.ID, name))))
		file := r.segmentFile(a, s.Name, 0, key, pl.ivs[0], false)
		info, err := r.tools.Probe(context.Background(), file)
		if err != nil {
			t.Fatal(err)
		}
		v := info.Video
		if v.Width != s.Width || v.Height != s.Height || v.Rotation != 0 {
			t.Errorf("%s: stored frames %dx%d rotation %d, want %dx%d and none", s.Name, v.Width, v.Height, v.Rotation, s.Width, s.Height)
		}
	}
	if !slices.Equal(names, []string{"480p", "360p", "240p"}) {
		t.Fatalf("renditions of a 360x640 portrait source = %v (display height 640 allows 480p and below)", names)
	}
}

// A file that is not a video fails the asset for good, cleans up after itself and leaves nothing
// behind in the work directory.
func TestPipelineRejectsNonMedia(t *testing.T) {
	r := newRig(t)
	junk := filepath.Join(t.TempDir(), "junk.mp4")
	if err := os.WriteFile(junk, bytes.Repeat([]byte("this is not a video "), 1000), 0o600); err != nil {
		t.Fatal(err)
	}
	asset, _ := r.commit(junk)
	err := r.process(asset)
	if err == nil {
		t.Fatal("a non-media file was processed")
	}
	a, gerr := r.repos.GetAsset(context.Background(), asset.TenantID, asset.ID)
	if gerr != nil || a.State != db.AssetFailed || a.FailureCode != pipeline.FailureInvalidMedia {
		t.Fatalf("asset = %s/%s (%v)", a.State, a.FailureCode, gerr)
	}
	if es, _ := os.ReadDir(r.workDir); len(es) != 0 {
		t.Errorf("work directory not empty: %v", es)
	}
	if _, err := r.mgr.Get(context.Background(), a.TenantID, a.ID); err == nil {
		t.Error("a content key was created for a file that never got that far")
	}
}

// A source shorter than the smallest rung gets one rendition at its own height, and a source
// without an audio track gets video-only renditions: the single-branch split and the missing audio
// map must both work in the minimal FFmpeg build.
func TestPipelineSmallSilentSource(t *testing.T) {
	r := newRig(t)
	src := generate(t, testmedia.Spec{Name: "small.mp4", Width: 320, Height: 180, Duration: 5 * time.Second, FPS: 25})
	asset, _ := r.commit(src)
	if err := r.process(asset); err != nil {
		t.Fatalf("asset.process: %v\n%s", err, r.logs.String())
	}
	a, err := r.repos.GetAsset(context.Background(), asset.TenantID, asset.ID)
	if err != nil || a.State != db.AssetReady {
		t.Fatalf("asset: %v, %v", a.State, err)
	}
	sum := summaryOf(t, a)
	if len(sum) != 1 || sum[0].Name != "180p" || sum[0].Width != 320 || sum[0].Height != 180 || sum[0].Segments != 1 || sum[0].FrameRate != 25 {
		t.Fatalf("renditions = %+v", sum)
	}
	if strings.Contains(sum[0].Codecs, "mp4a") {
		t.Errorf("codecs %q for a silent source", sum[0].Codecs)
	}
	master := string(r.get(r.buckets.Delivery, keys.Master(a.TenantID, a.ID)))
	if !strings.Contains(master, "RESOLUTION=320x180") || !strings.Contains(master, "FRAME-RATE=25.000") {
		t.Errorf("master playlist:\n%s", master)
	}
}
