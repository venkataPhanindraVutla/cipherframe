//go:build media

package media_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
)

// These tests run the real binaries. They need:
//
//	CIPHERFRAME_TEST_FFMPEG           the worker image's ffmpeg
//	CIPHERFRAME_TEST_FFPROBE          the worker image's ffprobe
//	CIPHERFRAME_TEST_FFMPEG_FIXTURES  the test-only generator (the Dockerfile's `fixtures` stage)
//
// Run: go test -tags media ./internal/media/...  (see docs/usage.md and the CI job `media`).

var defaultLimits = media.Limits{MaxDuration: 4 * time.Hour, MaxWidth: 3840, MaxHeight: 2160}

func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: point it at the binary under test (see the comment at the top of this file)", name)
	}
	return v
}

func tools(t *testing.T) media.Tools {
	t.Helper()
	return media.Tools{FFmpeg: env(t, "CIPHERFRAME_TEST_FFMPEG"), FFprobe: env(t, "CIPHERFRAME_TEST_FFPROBE")}
}

func generate(t *testing.T, s testmedia.Spec) string {
	t.Helper()
	g := testmedia.Generator{FFmpeg: env(t, "CIPHERFRAME_TEST_FFMPEG_FIXTURES")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := g.Generate(ctx, t.TempDir(), s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func probe(t *testing.T, path string) media.Info {
	t.Helper()
	info, err := tools(t).Probe(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestCapabilitiesOfTheWorkerBuild(t *testing.T) {
	if err := tools(t).CheckCapabilities(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilitiesFailOnALimitedBuild(t *testing.T) {
	limited := media.Tools{FFmpeg: env(t, "CIPHERFRAME_TEST_FFMPEG_FIXTURES"), FFprobe: tools(t).FFprobe}
	err := limited.CheckCapabilities(context.Background())
	if err == nil {
		t.Fatal("the fixtures build has no hls muxer or AV1 decoder; the check must fail")
	}
	for _, want := range []string{"hls", "libdav1d", "hevc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q: %v", want, err)
		}
	}
}

func TestCapabilitiesFailOnAFakeBinary(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "ffmpeg")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // test fake
		t.Fatal(err)
	}
	err := media.Tools{FFmpeg: fake, FFprobe: fake}.CheckCapabilities(context.Background())
	if err == nil || !strings.Contains(err.Error(), "libx264") {
		t.Fatalf("a binary that lists nothing must fail naming what is missing, got %v", err)
	}
	err = media.Tools{FFmpeg: filepath.Join(t.TempDir(), "absent"), FFprobe: tools(t).FFprobe}.CheckCapabilities(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ffmpeg") {
		t.Fatalf("got %v", err)
	}
}

func TestProbeLandscape(t *testing.T) {
	info := probe(t, generate(t, testmedia.Spec{Name: "landscape.mp4", Width: 320, Height: 180, Audio: true}))
	if info.Container != media.ContainerMP4 {
		t.Errorf("container %q", info.Container)
	}
	if d := info.Duration; d < 1900*time.Millisecond || d > 2300*time.Millisecond {
		t.Errorf("duration %v", d)
	}
	v := info.Video
	if v == nil || v.Codec != "h264" || v.Width != 320 || v.Height != 180 || v.DisplayWidth != 320 ||
		v.DisplayHeight != 180 || v.Rotation != 0 || v.PixelFormat != "yuv420p" || v.FrameRate < 14.9 || v.FrameRate > 15.1 {
		t.Errorf("video: %+v", v)
	}
	if a := info.Audio; a == nil || a.Codec != "aac" || a.Channels != 2 || a.SampleRate != 48000 {
		t.Errorf("audio: %+v", a)
	}
	if err := media.Validate(info, defaultLimits); err != nil {
		t.Errorf("validate: %v", err)
	}
	if got := media.Ladder(info, nil); len(got) != 1 || got[0].Name != "180p" || got[0].Width != 320 || got[0].AudioKbps != 96 {
		t.Errorf("ladder: %+v", got)
	}
}

func TestProbePortraitStored(t *testing.T) {
	info := probe(t, generate(t, testmedia.Spec{Name: "portrait.mp4", Width: 180, Height: 320}))
	v := info.Video
	if v.Width != 180 || v.Height != 320 || v.DisplayWidth != 180 || v.DisplayHeight != 320 || v.Rotation != 0 {
		t.Errorf("video: %+v", v)
	}
	if info.Audio != nil {
		t.Errorf("an audio-less fixture reported audio: %+v", info.Audio)
	}
}

func TestProbeRotatedByDisplayMatrix(t *testing.T) {
	for _, rot := range []int{90, 180, 270} {
		t.Run(strconv.Itoa(rot), func(t *testing.T) {
			info := probe(t, generate(t, testmedia.Spec{Name: "rotated.mp4", Width: 320, Height: 180, Rotation: rot}))
			v := info.Video
			if v.Width != 320 || v.Height != 180 {
				t.Fatalf("coded size must not change: %+v", v)
			}
			if v.Rotation != rot {
				t.Fatalf("rotation %d, want %d: %+v", v.Rotation, rot, v)
			}
			wantW, wantH := 320, 180
			if rot != 180 {
				wantW, wantH = 180, 320
			}
			if v.DisplayWidth != wantW || v.DisplayHeight != wantH {
				t.Fatalf("display %dx%d, want %dx%d", v.DisplayWidth, v.DisplayHeight, wantW, wantH)
			}
		})
	}
}

func TestProbeWithoutAudioAndMatroska(t *testing.T) {
	info := probe(t, generate(t, testmedia.Spec{Name: "silent.mkv", Width: 256, Height: 144}))
	if info.Container != media.ContainerMatroska || info.Audio != nil || info.Video == nil || info.Video.Codec != "h264" {
		t.Fatalf("%+v %+v", info, info.Video)
	}
	if err := media.Validate(info, defaultLimits); err != nil {
		t.Fatal(err)
	}
	// 144p source: one rendition at its own height.
	if got := media.Ladder(info, nil); len(got) != 1 || got[0].Height != 144 || got[0].Width != 256 || got[0].AudioKbps != 0 {
		t.Fatalf("ladder: %+v", got)
	}
}

func TestProbeCatchesALyingDuration(t *testing.T) {
	p := generate(t, testmedia.Spec{Name: "long.mp4", Width: 320, Height: 180, Audio: true})
	if err := testmedia.SetMP4Duration(p, 5*time.Hour); err != nil {
		t.Fatal(err)
	}
	info := probe(t, p)
	if info.Duration < 4*time.Hour {
		t.Fatalf("ffprobe duration %v; the metadata trick did not take", info.Duration)
	}
	err := media.Validate(info, defaultLimits)
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != errs.InvalidRequest || !strings.Contains(e.Detail, "4 hours") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(e.Detail, p) || strings.Contains(e.Detail, filepath.Dir(p)) {
		t.Fatalf("detail leaks the path: %q", e.Detail)
	}
}

func TestProbeRejectsNonMedia(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"text.mp4":   "this is not a video\n",
		"empty.mp4":  "",
		"-i":         "x", // a file name that looks like an option
		"playlist.m": "#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:1,\nhttp://127.0.0.1:9/never.ts\n",
		"concat.txt": "ffconcat version 1.0\nfile '/etc/passwd'\n",
	}
	for name, body := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := tools(t).Probe(context.Background(), p)
		var e *errs.Error
		if !errors.As(err, &e) || e.Code != errs.InvalidRequest {
			t.Errorf("%s: want invalid_request, got %v", name, err)
			continue
		}
		if strings.Contains(e.Detail, dir) || strings.Contains(e.Error(), dir) {
			t.Errorf("%s: error leaks the path: %v", name, e)
		}
	}
	if _, err := tools(t).Probe(context.Background(), filepath.Join(dir, "missing.mp4")); err == nil {
		t.Error("a missing file must fail")
	}
}

func TestProbeHonoursContext(t *testing.T) {
	p := generate(t, testmedia.Spec{Name: "ctx.mp4", Width: 320, Height: 180})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tools(t).Probe(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

// The ladder's sizes must be what FFmpeg produces: scale the rotated fixture to its first rung and
// probe the result. This also exercises libx264, the filters and the autorotate transposes in the
// minimal build.
func TestTranscodeToLadderRung(t *testing.T) {
	src := generate(t, testmedia.Spec{Name: "src.mp4", Width: 640, Height: 360, Audio: true, Rotation: 90})
	info := probe(t, src)
	rungs := media.Ladder(info, nil)
	if len(rungs) != 3 || rungs[0].Name != "480p" || rungs[0].Width != 270 || rungs[0].Height != 480 {
		t.Fatalf("ladder: %+v", rungs)
	}
	r := rungs[0]
	out := filepath.Join(t.TempDir(), "out.mp4")
	srcURL, err := media.SourceURL(src)
	if err != nil {
		t.Fatal(err)
	}
	run(t, tools(t).FFmpeg, "-hide_banner", "-nostdin", "-v", "error", "-protocol_whitelist", "file,pipe", "-y",
		"-i", srcURL,
		"-vf", "scale="+strconv.Itoa(r.Width)+":"+strconv.Itoa(r.Height)+",setsar=1,format=yuv420p",
		"-c:v", "libx264", "-crf", strconv.Itoa(r.CRF), "-maxrate", strconv.Itoa(r.MaxrateKbps)+"k",
		"-bufsize", strconv.Itoa(r.BufsizeKbps)+"k", "-profile:v", "high",
		"-c:a", "aac", "-b:a", strconv.Itoa(r.AudioKbps)+"k", "-f", "mp4", "file:"+out)
	got := probe(t, out).Video
	if got.DisplayWidth != r.Width || got.DisplayHeight != r.Height || got.Rotation != 0 {
		t.Fatalf("transcoded display %dx%d rotation %d, ladder said %dx%d", got.DisplayWidth, got.DisplayHeight, got.Rotation, r.Width, r.Height)
	}
}

// fMP4 HLS output is the packaging ADR 0024 chooses; make sure the minimal build can write it.
func TestHLSFragmentedMP4Output(t *testing.T) {
	src := generate(t, testmedia.Spec{Name: "hls.mp4", Width: 320, Height: 180, Audio: true, Duration: 5 * time.Second})
	srcURL, err := media.SourceURL(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	run(t, tools(t).FFmpeg, "-hide_banner", "-nostdin", "-v", "error", "-protocol_whitelist", "file,pipe", "-y",
		"-i", srcURL, "-c:v", "libx264", "-g", "30", "-sc_threshold", "0", "-c:a", "aac",
		"-f", "hls", "-hls_time", "2", "-hls_playlist_type", "vod", "-hls_segment_type", "fmp4",
		"-hls_fmp4_init_filename", "init.mp4", "-hls_segment_filename", filepath.Join(dir, "seg%d.m4s"),
		"file:"+filepath.Join(dir, "index.m3u8"))
	for _, f := range []string{"index.m3u8", "init.mp4", "seg0.m4s"} {
		if st, err := os.Stat(filepath.Join(dir, f)); err != nil || st.Size() == 0 {
			t.Errorf("%s missing or empty: %v", f, err)
		}
	}
	pl, _ := os.ReadFile(filepath.Join(dir, "index.m3u8")) //nolint:gosec // test reads its own temp dir
	if !strings.Contains(string(pl), "#EXT-X-MAP") {
		t.Errorf("playlist has no fMP4 init map:\n%s", pl)
	}
}

func run(t *testing.T, bin string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // test: argument array
	cmd.Env = []string{"LC_ALL=C"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s failed: %v\n%s", filepath.Base(bin), err, out)
	}
}
