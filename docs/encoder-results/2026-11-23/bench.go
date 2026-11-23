//go:build ignore

// bench measures an encoder against libx264 on generated fixtures (docs/hardware-encoders.md). It
// builds each ladder with the worker's own argument builder (media.TranscodeArgs), runs ONE FFmpeg
// process per encoder and fixture, one at a time, and records size, wall and CPU time, VMAF against
// the fixture, and keyframe alignment.
//
//	go run docs/encoder-results/2026-11-23/bench.go -ffmpeg F -ffprobe P -work DIR -out results.json \
//	    -encoders software,videotoolbox [-vt-quality N]
//
// The FFmpeg must have libvmaf and the encoders under test. Fixtures are written into -work.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
)

type rungResult struct {
	Name      string  `json:"name"`
	Bytes     int64   `json:"bytes"`
	KbpsVideo float64 `json:"kbps"`
	VMAF      float64 `json:"vmaf"`
}

type result struct {
	Fixture     string       `json:"fixture"`
	Encoder     string       `json:"encoder"`
	WallSeconds float64      `json:"wall_seconds"`
	CPUSeconds  float64      `json:"cpu_seconds"`
	Rungs       []rungResult `json:"rungs"`
	Aligned     bool         `json:"segments_aligned"`
	Keyframes   string       `json:"keyframes"`
}

func main() {
	ffmpeg := flag.String("ffmpeg", "ffmpeg", "")
	ffprobe := flag.String("ffprobe", "ffprobe", "")
	work := flag.String("work", "", "scratch directory (absolute)")
	out := flag.String("out", "results.json", "")
	encs := flag.String("encoders", "software,videotoolbox", "")
	flag.Parse()
	if !filepath.IsAbs(*work) {
		fatal(fmt.Errorf("-work must be an absolute path"))
	}
	ctx := context.Background()
	tools := media.Tools{FFmpeg: *ffmpeg, FFprobe: *ffprobe}
	var all []result
	for _, fx := range fixtures(ctx, *ffmpeg, *work) {
		info, err := tools.Probe(ctx, fx.path)
		fatal(err)
		for _, name := range strings.Split(*encs, ",") {
			r, err := run(ctx, tools, fx, info, media.Encoder(name), *work)
			fatal(err)
			all = append(all, r)
			fmt.Fprintf(os.Stderr, "%s %s: wall %.1fs cpu %.1fs aligned=%v keyframes=%s\n", fx.name, name, r.WallSeconds, r.CPUSeconds, r.Aligned, r.Keyframes)
		}
	}
	b, _ := json.MarshalIndent(all, "", "  ")
	fatal(os.WriteFile(*out, append(b, '\n'), 0o644))
}

type fixture struct{ name, path string }

// fixtures makes two 20 s, 1080p, 30 fps sources with stereo audio: testsrc2 (the project's test
// pattern: flat colours, hard edges) and mandelbrot (continuous fine detail, closer to camera
// footage in how hard it is to compress, though still synthetic).
func fixtures(ctx context.Context, ffmpeg, work string) []fixture {
	dir := filepath.Join(work, "src")
	fatal(os.MkdirAll(dir, 0o755))
	p, err := testmedia.Generator{FFmpeg: ffmpeg}.Generate(ctx, dir, testmedia.Spec{
		Name: "testsrc2.mp4", Width: 1920, Height: 1080, Duration: 20 * time.Second, FPS: 30, Audio: true,
	})
	fatal(err)
	mb := filepath.Join(dir, "mandelbrot.mp4")
	fatal(exec.CommandContext(ctx, ffmpeg, "-hide_banner", "-nostdin", "-v", "error", "-y",
		"-f", "lavfi", "-i", "mandelbrot=size=1920x1080:rate=30", "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000",
		"-t", "20", "-c:v", "libx264", "-preset", "veryfast", "-crf", "10", "-pix_fmt", "yuv420p", "-g", "30",
		"-c:a", "aac", "-b:a", "64k", "-ac", "2", "-f", "mp4", mb).Run())
	return []fixture{{"testsrc2", p}, {"mandelbrot", mb}}
}

func run(ctx context.Context, tools media.Tools, fx fixture, info media.Info, enc media.Encoder, work string) (result, error) {
	res := result{Fixture: fx.name, Encoder: string(enc)}
	outDir := filepath.Join(work, "out", fx.name, string(enc))
	if err := os.RemoveAll(outDir); err != nil {
		return res, err
	}
	rends := media.Ladder(info, nil)
	spec := media.TranscodeSpec{Source: fx.path, OutDir: outDir, Info: info, Renditions: rends, Encoder: enc}
	args, err := media.TranscodeArgs(spec)
	if err != nil {
		return res, err
	}
	for _, r := range rends {
		if err := os.MkdirAll(spec.RenditionDir(r), 0o755); err != nil {
			return res, err
		}
	}
	cmd := exec.CommandContext(ctx, tools.FFmpeg, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	t0 := time.Now()
	if err := cmd.Run(); err != nil {
		return res, fmt.Errorf("%s encode: %w: %s", enc, err, stderr.String())
	}
	res.WallSeconds = time.Since(t0).Seconds()
	res.CPUSeconds = (cmd.ProcessState.UserTime() + cmd.ProcessState.SystemTime()).Seconds()

	var outs []media.RenditionOutput
	keyOK := true
	var firstKF []float64
	for _, r := range rends {
		dir := spec.RenditionDir(r)
		o, err := media.ReadRenditionOutput(dir, r)
		if err != nil {
			return res, err
		}
		outs = append(outs, o)
		var size int64
		for _, s := range o.Segments {
			size += s.Size
		}
		rr := rungResult{Name: r.Name, Bytes: size, KbpsVideo: float64(size) * 8 / 1000 / info.Duration.Seconds()}
		if rr.VMAF, err = vmaf(ctx, tools.FFmpeg, fx.path, dir, r, work); err != nil {
			return res, err
		}
		kf, err := keyframes(ctx, tools.FFprobe, dir)
		if err != nil {
			return res, err
		}
		if !onGrid(kf, info.Duration) || (firstKF != nil && !slices.Equal(kf, firstKF)) {
			keyOK = false
		}
		if firstKF == nil {
			firstKF = kf
		}
		res.Rungs = append(res.Rungs, rr)
	}
	res.Aligned = media.CheckAligned(outs, 2*time.Millisecond) == nil
	res.Keyframes = "identical on every rendition, exactly 2 s apart"
	if !keyOK {
		res.Keyframes = "MISMATCH"
	}
	return res, nil
}

// vmaf scores the rendition against the source scaled to the rendition's size, so the number
// isolates what the encoder lost (the scaling is the same for every encoder).
func vmaf(ctx context.Context, ffmpeg, src, dir string, r media.Rendition, work string) (float64, error) {
	log := filepath.Join(work, "vmaf.json")
	fg := fmt.Sprintf("[0:v]setpts=PTS-STARTPTS[d];[1:v]scale=%d:%d:flags=bicubic,setsar=1,format=yuv420p,setpts=PTS-STARTPTS[r];"+
		"[d]format=yuv420p[d2];[d2][r]libvmaf=n_threads=2:n_subsample=3:log_fmt=json:log_path=%s", r.Width, r.Height, log)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, ffmpeg, "-hide_banner", "-nostdin", "-v", "error", "-allowed_extensions", "ALL",
		"-i", filepath.Join(dir, media.PlaylistFile), "-i", src, "-filter_complex", fg, "-an", "-f", "null", "-")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("vmaf: %w: %s", err, stderr.String())
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		return 0, err
	}
	var doc struct {
		Pooled struct {
			VMAF struct{ Mean float64 } `json:"vmaf"`
		} `json:"pooled_metrics"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, err
	}
	return doc.Pooled.VMAF.Mean, nil
}

// keyframes lists the presentation times of the keyframes of a rendition.
func keyframes(ctx context.Context, ffprobe, dir string) ([]float64, error) {
	b, err := exec.CommandContext(ctx, ffprobe, "-v", "error", "-allowed_extensions", "ALL", "-select_streams", "v:0",
		"-show_entries", "packet=pts_time,flags", "-of", "csv=p=0", filepath.Join(dir, media.PlaylistFile)).Output()
	if err != nil {
		return nil, err
	}
	var out []float64
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		t, flags, ok := strings.Cut(line, ",")
		if ok && strings.HasPrefix(flags, "K") {
			f, err := strconv.ParseFloat(t, 64)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// onGrid: keyframes sit exactly KeyframeSeconds apart from the first one and cover the whole
// source. The first keyframe's own timestamp is the encoder's start delay (B-frame reordering), the
// same on every rendition of one encoder, so each list is compared to the first rendition's.
func onGrid(kf []float64, d time.Duration) bool {
	want := int(d.Seconds() / media.KeyframeSeconds)
	if d.Seconds() > float64(want*media.KeyframeSeconds)+0.5 {
		want++
	}
	if len(kf) != want {
		return false
	}
	for i, t := range kf {
		if diff := t - kf[0] - float64(i*media.KeyframeSeconds); diff < -0.001 || diff > 0.001 {
			return false
		}
	}
	return true
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
