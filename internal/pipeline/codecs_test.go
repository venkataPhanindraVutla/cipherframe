package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// extraHarness is a harness whose asset asked for codecs and whose worker can encode have.
func extraHarness(t *testing.T, asked []string, have ...media.Codec) *harness {
	t.Helper()
	h := newHarness(t)
	h.repo.asset.ExtraCodecs = asked
	h.proc.Codecs = have
	return h
}

func renditionNames(t *testing.T, a db.Asset) []string {
	t.Helper()
	var sum []RenditionSummary
	if err := json.Unmarshal(a.Renditions, &sum); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range sum {
		names = append(names, s.Name)
	}
	return names
}

// With the setting empty nothing changes: one transcode, the H.264 renditions and nothing else.
func TestNoExtraCodecsLeavesTheOutputUnchanged(t *testing.T) {
	h := extraHarness(t, nil, media.CodecHEVC, media.CodecAV1)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	a := h.repo.snapshot()
	if a.State != db.AssetReady || h.tools.transcodes != 1 || len(a.ExtraCodecFailures) != 0 {
		t.Fatalf("state %s, transcodes %d, failures %v", a.State, h.tools.transcodes, a.ExtraCodecFailures)
	}
	if got := renditionNames(t, a); !slices.Equal(got, []string{"720p", "480p", "360p", "240p"}) {
		t.Fatalf("renditions %v", got)
	}
	m, err := DecodeManifest(h.repo.manifest.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Encoder.Rungs {
		if r.Codec != "" || r.VideoCodec != "" || r.Preset != "" {
			t.Errorf("an H.264 rung carries extra-codec members: %+v", r)
		}
	}
	if raw := string(h.repo.manifest.Envelope); strings.Contains(raw, "hvc1") {
		t.Error("the stored envelope mentions HEVC")
	}
}

// An asset that asked for both gets a full ladder per codec, each with its own codec string, in the
// master playlist H.264 first, and every one in the manifest and the registry.
func TestExtraCodecsMakeAFullLadderEach(t *testing.T) {
	h := extraHarness(t, []string{"hevc", "av1"}, media.CodecHEVC, media.CodecAV1)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	a := h.repo.snapshot()
	if a.State != db.AssetReady || h.tools.transcodes != 3 || len(a.ExtraCodecFailures) != 0 {
		t.Fatalf("state %s, transcodes %d, failures %v", a.State, h.tools.transcodes, a.ExtraCodecFailures)
	}
	want := []string{
		"720p", "480p", "360p", "240p",
		"720p_hevc", "480p_hevc", "360p_hevc", "240p_hevc", "720p_av1", "480p_av1", "360p_av1", "240p_av1",
	}
	if got := renditionNames(t, a); !slices.Equal(got, want) {
		t.Fatalf("renditions %v", got)
	}
	var sum []RenditionSummary
	if err := json.Unmarshal(a.Renditions, &sum); err != nil {
		t.Fatal(err)
	}
	for _, s := range sum {
		prefix := map[bool]string{true: "avc1.", false: ""}[!strings.Contains(s.Name, "_")]
		if strings.HasSuffix(s.Name, "_hevc") {
			prefix = "hvc1.1.6.L120.90,"
		} else if strings.HasSuffix(s.Name, "_av1") {
			prefix = "av01.0.08M.08,"
		}
		if !strings.HasPrefix(s.Codecs, prefix) || !strings.HasSuffix(s.Codecs, ",mp4a.40.2") || s.Segments != 3 {
			t.Errorf("%s: %+v", s.Name, s)
		}
	}

	// The master lists all twelve, H.264 first, and the registry holds every rendition's objects.
	master := string(h.delivery.object(keys.Master(h.args.TenantID, h.args.AssetID)))
	var variants []string
	for l := range strings.SplitSeq(master, "\n") {
		if strings.HasSuffix(l, "/playlist.m3u8") {
			variants = append(variants, strings.TrimSuffix(l, "/playlist.m3u8"))
		}
	}
	if len(variants) != 12 || slices.Index(variants, "240p_hevc") < slices.Index(variants, "720p") || slices.Index(variants, "240p_av1") < slices.Index(variants, "720p_hevc") {
		t.Fatalf("master variants %v", variants)
	}
	if !strings.Contains(master, `CODECS="avc1.640028,mp4a.40.2"`) || !strings.Contains(master, `CODECS="av01.0.08M.08,mp4a.40.2"`) {
		t.Errorf("master:\n%s", master)
	}
	if n := len(h.delivery.keys()); n != len(h.repo.artifacts) || n != 12*(1+1+3)+1+3 {
		t.Fatalf("%d delivery objects, %d artifacts", n, len(h.repo.artifacts))
	}

	// The signed manifest covers every rendition and records each extra codec's encoder.
	m, err := DecodeManifest(h.repo.manifest.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Renditions) != 12 || len(m.Encoder.Rungs) != 12 {
		t.Fatalf("manifest has %d renditions and %d rungs", len(m.Renditions), len(m.Encoder.Rungs))
	}
	for _, r := range m.Encoder.Rungs {
		switch {
		case strings.HasSuffix(r.Name, "_hevc"):
			if r.Codec != "hevc" || r.VideoCodec != "libx265" || r.Preset != media.X265Preset || r.CRF != media.CRFHEVC {
				t.Errorf("%+v", r)
			}
		case strings.HasSuffix(r.Name, "_av1"):
			if r.Codec != "av1" || r.VideoCodec != "libsvtav1" || r.Preset != media.SVTAV1Preset || r.CRF != media.CRFAV1 {
				t.Errorf("%+v", r)
			}
		}
	}
}

// A worker without an encoder for a requested codec records encoder_unavailable for it; the codec it
// has is made, and the asset is ready.
func TestExtraCodecWithoutAnEncoderIsRecorded(t *testing.T) {
	h := extraHarness(t, []string{"hevc", "av1"}, media.CodecHEVC)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	a := h.repo.snapshot()
	if a.State != db.AssetReady || h.tools.transcodes != 2 {
		t.Fatalf("state %s, transcodes %d", a.State, h.tools.transcodes)
	}
	if want := []db.CodecFailure{{Codec: "av1", Reason: db.CodecEncoderUnavailable}}; !slices.Equal(a.ExtraCodecFailures, want) {
		t.Fatalf("failures %v", a.ExtraCodecFailures)
	}
	if got := renditionNames(t, a); len(got) != 8 || got[4] != "720p_hevc" {
		t.Fatalf("renditions %v", got)
	}
	if !strings.Contains(h.logs.String(), "has no encoder") {
		t.Error("the skipped codec is not logged")
	}
}

// codecTools fails the transcode of one codec the way FFmpeg does, and runs every other through the fake.
type codecTools struct {
	*fakeTools
	fail media.Codec
	err  error
	// after runs once the fake has written the codec's files, to damage them.
	after func(spec media.TranscodeSpec)
}

func (c *codecTools) Transcode(ctx context.Context, spec media.TranscodeSpec, progress func(time.Duration)) error {
	if spec.Codec == c.fail && c.err != nil {
		c.transcodes++
		return c.err
	}
	err := c.fakeTools.Transcode(ctx, spec, progress)
	if err == nil && spec.Codec == c.fail && c.after != nil {
		c.after(spec)
	}
	return err
}

// A codec whose transcode fails, times out or writes unusable files costs only itself.
func TestExtraCodecFailuresDoNotFailTheAsset(t *testing.T) {
	ffmpegFailed := errors.New("ffmpeg exited with code 1")
	for name, tc := range map[string]struct {
		tools  func(*fakeTools) *codecTools
		reason string
	}{
		"ffmpeg fails": {func(f *fakeTools) *codecTools {
			return &codecTools{fakeTools: f, fail: media.CodecAV1, err: errs.Wrap(errs.InvalidRequest, "The media file could not be transcoded.", ffmpegFailed)}
		}, db.CodecTranscodeFailed},
		"times out": {func(f *fakeTools) *codecTools {
			return &codecTools{fakeTools: f, fail: media.CodecAV1, err: errs.Wrap(errs.Timeout, "Transcoding took too long.", ffmpegFailed)}
		}, db.CodecTranscodeTimeout},
		"misaligned output": {func(f *fakeTools) *codecTools {
			return &codecTools{fakeTools: f, fail: media.CodecAV1, after: func(spec media.TranscodeSpec) {
				// The first segment is a second shorter than the H.264 ladder's.
				pl := filepath.Join(spec.RenditionDir(spec.Renditions[0]), media.PlaylistFile)
				b, err := os.ReadFile(pl) //nolint:gosec // a file the fake wrote under t.TempDir
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(pl, bytes.Replace(b, []byte("#EXTINF:6.000000"), []byte("#EXTINF:5.000000"), 1), 0o600); err != nil { //nolint:gosec // as above
					t.Fatal(err)
				}
			}}
		}, db.CodecOutputInvalid},
		"unreadable codec configuration": {func(f *fakeTools) *codecTools {
			return &codecTools{fakeTools: f, fail: media.CodecAV1, after: func(spec media.TranscodeSpec) {
				init := filepath.Join(spec.RenditionDir(spec.Renditions[1]), media.InitFile)
				if err := os.WriteFile(init, []byte("not an init segment"), 0o600); err != nil {
					t.Fatal(err)
				}
			}}
		}, db.CodecOutputInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			h := extraHarness(t, []string{"hevc", "av1"}, media.CodecHEVC, media.CodecAV1)
			h.proc.Tools = tc.tools(h.tools)
			if err := h.run(1, 5); err != nil {
				t.Fatal(err)
			}
			a := h.repo.snapshot()
			if a.State != db.AssetReady {
				t.Fatalf("state %s, want ready", a.State)
			}
			if want := []db.CodecFailure{{Codec: "av1", Reason: tc.reason}}; !slices.Equal(a.ExtraCodecFailures, want) {
				t.Fatalf("failures %v, want %v", a.ExtraCodecFailures, want)
			}
			// H.264 and HEVC were published whole; nothing of AV1 is in the registry.
			if got := renditionNames(t, a); len(got) != 8 {
				t.Fatalf("renditions %v", got)
			}
			for _, k := range h.delivery.keys() {
				if strings.Contains(k, "_av1") {
					t.Fatalf("an AV1 object was stored: %s", k)
				}
			}
		})
	}
}

// A shutdown during an extra codec's transcode is not a codec failure: the job is retried whole.
func TestExtraCodecInterruptedIsRetried(t *testing.T) {
	h := extraHarness(t, []string{"hevc"}, media.CodecHEVC)
	ctx, cancel := context.WithCancel(context.Background())
	h.proc.Tools = &cancelOnCodec{fakeTools: h.tools, codec: media.CodecHEVC, cancel: cancel}
	err := h.proc.Handle(ctx, jobs.Job[uploads.ProcessArgs]{ID: 1, Args: h.args, Attempt: 1, MaxAttempts: 5})
	if err == nil {
		t.Fatal("an interrupted job reported success")
	}
	if got := h.repo.snapshot(); got.State != db.AssetProcessing || len(got.ExtraCodecFailures) != 0 {
		t.Fatalf("state %s, failures %v: the asset must stay processing for the retry", got.State, got.ExtraCodecFailures)
	}
}

// cancelOnCodec ends the job's context when the named codec is about to be transcoded, as a shutdown would.
type cancelOnCodec struct {
	*fakeTools
	codec  media.Codec
	cancel context.CancelFunc
}

func (c *cancelOnCodec) Transcode(ctx context.Context, spec media.TranscodeSpec, progress func(time.Duration)) error {
	if spec.Codec == c.codec {
		c.cancel()
		return ctx.Err()
	}
	return c.fakeTools.Transcode(ctx, spec, progress)
}
