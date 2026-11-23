//go:build ignore

// codecs-bench measures the extra codecs against H.264 on generated fixtures (docs/codecs.md). It builds
// each ladder with the worker's own argument builder (media.TranscodeArgs and media.LadderFor), runs ONE
// FFmpeg process per codec and fixture, one at a time, and records size, wall and CPU time, VMAF against
// the fixture, and whether the keyframes and the first timestamp match H.264's.
//
//	go run codecs-bench.go -mode ladder -ffmpeg F -ffprobe P -fixtures-ffmpeg G -vmaf-ffmpeg V -vmaf-ffprobe W \
//	    -work DIR -out codecs.json
//	go run codecs-bench.go -mode sweep  ... -out codecs-sweep.json
//	go run codecs-bench.go -mode caps   ... -out codecs-caps.json
//
// ladder: the full ladder of every codec, the numbers of docs/codecs.md. sweep: one 720p rung, no bitrate
// cap, over CRF values and presets, which is how the starting points of ADR 0067 were chosen. caps: one 720p
// rung at the codec's CRF over bitrate caps, which is how the caps were chosen.
// The scoring FFmpeg (libvmaf) and its ffprobe come from the Dockerfile's `measure` target; F and P are the
// worker image's own and G is the `fixtures` stage's (testsrc2 and mandelbrot sources). Fixtures are written
// into -work. The runs of docs/codecs.md were made inside a linux/arm64 container limited to 4 CPUs
// (docker run --cpus=4), the binary built with GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
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
	Name  string  `json:"name"`
	Bytes int64   `json:"bytes"`
	Kbps  float64 `json:"kbps"`
	VMAF  float64 `json:"vmaf"`
	// FirstPTS is the presentation time of the first video packet; every codec's is compared with H.264's.
	FirstPTS float64 `json:"first_pts"`
}

type result struct {
	Fixture     string       `json:"fixture"`
	Codec       string       `json:"codec"`
	Variant     string       `json:"variant,omitempty"` // sweep: what was changed
	WallSeconds float64      `json:"wall_seconds"`
	CPUSeconds  float64      `json:"cpu_seconds"`
	Rungs       []rungResult `json:"rungs"`
	Aligned     bool         `json:"segments_aligned_with_h264"`
	Keyframes   string       `json:"keyframes"`
}

type tool struct{ ffmpeg, ffprobe, fixtures, vmaf, vmafProbe, work string }

func main() {
	var t tool
	mode := flag.String("mode", "ladder", "ladder, sweep or caps")
	flag.StringVar(&t.ffmpeg, "ffmpeg", "ffmpeg", "the worker's FFmpeg")
	flag.StringVar(&t.ffprobe, "ffprobe", "ffprobe", "the worker's FFprobe")
	flag.StringVar(&t.fixtures, "fixtures-ffmpeg", "", "the test-only FFmpeg with lavfi")
	flag.StringVar(&t.vmaf, "vmaf-ffmpeg", "", "an FFmpeg with libvmaf that reads HLS")
	flag.StringVar(&t.vmafProbe, "vmaf-ffprobe", "", "an ffprobe that reads HLS")
	flag.StringVar(&t.work, "work", "", "scratch directory (absolute)")
	out := flag.String("out", "codecs.json", "")
	secs := flag.Int("seconds", 20, "length of each fixture")
	flag.Parse()
	if !filepath.IsAbs(t.work) {
		fatal(fmt.Errorf("-work must be an absolute path"))
	}
	ctx := context.Background()
	tools := media.Tools{FFmpeg: t.ffmpeg, FFprobe: t.ffprobe}
	var all []result
	for _, fx := range t.makeFixtures(ctx, *secs) {
		info, err := tools.Probe(ctx, fx.path)
		fatal(err)
		var runs []job
		switch *mode {
		case "sweep":
			runs = sweepJobs(info)
		case "caps":
			runs = capJobs(info)
		default:
			for _, c := range []media.Codec{media.CodecH264, media.CodecHEVC, media.CodecAV1} {
				runs = append(runs, job{codec: c, rends: media.LadderFor(c, info, nil)})
			}
		}
		var ref *refKeyframes
		for _, j := range runs {
			r, kf, err := t.run(ctx, tools, fx, info, j, ref)
			fatal(err)
			if ref == nil {
				ref = kf
			}
			all = append(all, r)
			fmt.Fprintf(os.Stderr, "%s %s %s: wall %.1fs cpu %.1fs aligned=%v keyframes=%s\n", fx.name, j.codec, j.variant, r.WallSeconds, r.CPUSeconds, r.Aligned, r.Keyframes)
		}
	}
	b, _ := json.MarshalIndent(all, "", "  ")
	fatal(os.WriteFile(*out, append(b, '\n'), 0o644))
}

// job is one FFmpeg process: a codec, its renditions and, for a sweep, edits to the argument list.
type job struct {
	codec   media.Codec
	rends   []media.Rendition
	variant string
	edit    func([]string) []string
}

// sweepJobs vary one thing at a time on the 720p rung with the bitrate cap lifted, so the CRF and the
// preset show their own effect: libx264 CRF 23 as the reference, x265 over CRF, SVT-AV1 over CRF and preset.
func sweepJobs(info media.Info) []job {
	pick := func(c media.Codec, crf int) []media.Rendition {
		for _, r := range media.LadderFor(c, info, []int{720}) {
			r.CRF, r.MaxrateKbps, r.BufsizeKbps = crf, 100000, 200000 // no cap: the CRF decides
			return []media.Rendition{r}
		}
		return nil
	}
	setArg := func(name, val string) func([]string) []string {
		return func(a []string) []string {
			a = slices.Clone(a)
			if i := slices.Index(a, name); i >= 0 {
				a[i+1] = val
			}
			return a
		}
	}
	jobs := []job{{codec: media.CodecH264, rends: pick(media.CodecH264, 23), variant: "crf 23 preset medium"}}
	for _, crf := range []int{22, 24, 26, 28} {
		jobs = append(jobs, job{codec: media.CodecHEVC, rends: pick(media.CodecHEVC, crf), variant: fmt.Sprintf("crf %d preset medium", crf)})
	}
	for _, p := range []string{"fast", "slow"} {
		jobs = append(jobs, job{codec: media.CodecHEVC, rends: pick(media.CodecHEVC, media.CRFHEVC), variant: "crf 26 preset " + p, edit: setArg("-preset", p)})
	}
	for _, crf := range []int{30, 33, 35, 38} {
		jobs = append(jobs, job{codec: media.CodecAV1, rends: pick(media.CodecAV1, crf), variant: fmt.Sprintf("crf %d preset 8", crf)})
	}
	for _, p := range []string{"6", "10", "12"} {
		jobs = append(jobs, job{codec: media.CodecAV1, rends: pick(media.CodecAV1, media.CRFAV1), variant: "crf 35 preset " + p, edit: setArg("-preset", p)})
	}
	return jobs
}

// capJobs vary the rung's bitrate cap at the codec's own CRF on the 720p rung: H.264 at its own cap as the
// reference, then HEVC and AV1 at the shares of it that ADR 0067 weighed.
func capJobs(info media.Info) []job {
	pick := func(c media.Codec, maxrate int) []media.Rendition {
		for _, r := range media.LadderFor(c, info, []int{720}) {
			r.MaxrateKbps, r.BufsizeKbps = maxrate, 2*maxrate
			return []media.Rendition{r}
		}
		return nil
	}
	jobs := []job{{codec: media.CodecH264, rends: pick(media.CodecH264, 2500), variant: "cap 2500 (1.0)"}}
	for _, k := range []int{1500, 1750, 2000, 2500} {
		jobs = append(jobs, job{codec: media.CodecHEVC, rends: pick(media.CodecHEVC, k), variant: fmt.Sprintf("cap %d (%.2f)", k, float64(k)/2500)})
	}
	for _, k := range []int{1250, 1500, 1750, 2000, 2500} {
		jobs = append(jobs, job{codec: media.CodecAV1, rends: pick(media.CodecAV1, k), variant: fmt.Sprintf("cap %d (%.2f)", k, float64(k)/2500)})
	}
	return jobs
}

type fixture struct{ name, path string }

// makeFixtures writes two 1080p, 30 fps sources with stereo audio: testsrc2 (the project's test pattern:
// flat colours, hard edges) and mandelbrot (continuous fine detail, harder to compress; still synthetic).
func (t tool) makeFixtures(ctx context.Context, secs int) []fixture {
	dir := filepath.Join(t.work, "src")
	fatal(os.MkdirAll(dir, 0o755))
	p, err := testmedia.Generator{FFmpeg: t.fixtures}.Generate(ctx, dir, testmedia.Spec{
		Name: "testsrc2.mp4", Width: 1920, Height: 1080, Duration: time.Duration(secs) * time.Second, FPS: 30, Audio: true,
	})
	fatal(err)
	mb := filepath.Join(dir, "mandelbrot.mp4")
	fatal(exec.CommandContext(ctx, t.fixtures, "-hide_banner", "-nostdin", "-v", "error", "-y",
		"-f", "lavfi", "-i", "mandelbrot=size=1920x1080:rate=30", "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000",
		"-t", strconv.Itoa(secs), "-c:v", "libx264", "-preset", "veryfast", "-crf", "10", "-pix_fmt", "yuv420p", "-g", "30",
		"-c:a", "aac", "-b:a", "64k", "-ac", "2", "-f", "mp4", mb).Run())
	return []fixture{{"testsrc2", p}, {"mandelbrot", mb}}
}

// refKeyframes is H.264's: the keyframe times of its first rung, the segment structure of the whole ladder
// and each rung's first timestamp, which every other codec is held to.
type refKeyframes struct {
	times    []float64
	outs     []media.RenditionOutput
	firstPTS map[string]float64
	// start is where the H.264 ladder presents its first picture (media.FirstVideoPTS).
	start time.Duration
}

func (t tool) run(ctx context.Context, tools media.Tools, fx fixture, info media.Info, j job, ref *refKeyframes) (result, *refKeyframes, error) {
	res := result{Fixture: fx.name, Codec: string(j.codec), Variant: j.variant}
	outDir := filepath.Join(t.work, "out", fx.name, string(j.codec)+strings.ReplaceAll(j.variant, " ", "_"))
	if err := os.RemoveAll(outDir); err != nil {
		return res, nil, err
	}
	spec := media.TranscodeSpec{Source: fx.path, OutDir: outDir, Info: info, Renditions: j.rends, Codec: j.codec}
	if ref != nil {
		spec.TSOffset = ref.start // the worker starts every extra codec where H.264's first picture is (ADR 0067)
	}
	args, err := media.TranscodeArgs(spec)
	if err != nil {
		return res, nil, err
	}
	if j.edit != nil {
		args = j.edit(args)
	}
	for _, r := range j.rends {
		if err := os.MkdirAll(spec.RenditionDir(r), 0o755); err != nil {
			return res, nil, err
		}
	}
	cmd := exec.CommandContext(ctx, tools.FFmpeg, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	t0 := time.Now()
	if err := cmd.Run(); err != nil {
		return res, nil, fmt.Errorf("%s encode: %w: %s", j.codec, err, stderr.String())
	}
	res.WallSeconds = time.Since(t0).Seconds()
	res.CPUSeconds = (cmd.ProcessState.UserTime() + cmd.ProcessState.SystemTime()).Seconds()

	got := &refKeyframes{firstPTS: map[string]float64{}}
	var outs []media.RenditionOutput
	keyOK := true
	for i, r := range j.rends {
		dir := spec.RenditionDir(r)
		o, err := media.ReadRenditionOutput(dir, r)
		if err != nil {
			return res, nil, err
		}
		outs = append(outs, o)
		var size int64
		for _, s := range o.Segments {
			size += s.Size
		}
		rr := rungResult{Name: r.Name, Bytes: size, Kbps: float64(size) * 8 / 1000 / info.Duration.Seconds()}
		if rr.VMAF, err = t.score(ctx, fx.path, dir, r); err != nil {
			return res, nil, err
		}
		kf, first, err := t.keyframes(ctx, dir)
		if err != nil {
			return res, nil, err
		}
		rr.FirstPTS = first
		got.firstPTS[r.Name] = first
		if i == 0 {
			got.times = kf
		}
		// Within a codec every rung's keyframes are those of its first rung, exactly 2 s apart.
		if !onGrid(kf, info.Duration) || !slices.Equal(kf, got.times) {
			keyOK = false
		}
		res.Rungs = append(res.Rungs, rr)
	}
	got.outs = outs
	if init, err := os.ReadFile(outs[0].InitPath); err == nil {
		if seg, err := os.ReadFile(outs[0].Segments[0].Path); err == nil {
			got.start, _ = media.FirstVideoPTS(init, seg)
		}
	}
	res.Keyframes = "identical on every rendition, exactly 2 s apart"
	if !keyOK {
		res.Keyframes = "MISMATCH within the codec"
	}
	res.Aligned = true
	if ref != nil {
		// Across codecs: the same segment count and durations as H.264's rungs, and the same keyframe times
		// (the extra codecs are started where H.264's first picture is, as the worker does).
		res.Aligned = media.CheckAligned(append([]media.RenditionOutput{ref.outs[0]}, outs[0]), 2*time.Millisecond) == nil
		same := len(got.times) == len(ref.times)
		for i := range got.times {
			same = same && i < len(ref.times) && math.Abs(got.times[i]-ref.times[i]) < 0.001
		}
		if !same {
			res.Keyframes += "; keyframe times differ from H.264's"
		} else {
			res.Keyframes += "; the same times as H.264's"
		}
	}
	return res, got, nil
}

// score is the VMAF of the rendition against the source scaled to the rendition's size, so the number
// isolates what the encoder lost (the scaling is the same for every codec).
func (t tool) score(ctx context.Context, src, dir string, r media.Rendition) (float64, error) {
	log := filepath.Join(t.work, "vmaf.json")
	fg := fmt.Sprintf("[0:v]setpts=PTS-STARTPTS[d];[1:v]scale=%d:%d:flags=bicubic,setsar=1,format=yuv420p,setpts=PTS-STARTPTS[r];"+
		"[d]format=yuv420p[d2];[d2][r]libvmaf=n_threads=2:n_subsample=3:log_fmt=json:log_path=%s", r.Width, r.Height, log)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, t.vmaf, "-hide_banner", "-nostdin", "-v", "error", "-allowed_extensions", "ALL",
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

// keyframes lists the presentation times of a rendition's keyframes and of its first packet.
func (t tool) keyframes(ctx context.Context, dir string) ([]float64, float64, error) {
	b, err := exec.CommandContext(ctx, t.vmafProbe, "-v", "error", "-allowed_extensions", "ALL", "-select_streams", "v:0",
		"-show_entries", "packet=pts_time,flags", "-of", "csv=p=0", filepath.Join(dir, media.PlaylistFile)).Output()
	if err != nil {
		return nil, 0, err
	}
	var out []float64
	first := -1.0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		ts, flags, ok := strings.Cut(line, ",")
		if !ok {
			continue
		}
		f, err := strconv.ParseFloat(ts, 64)
		if err != nil {
			return nil, 0, err
		}
		if first < 0 || f < first {
			first = f
		}
		if strings.HasPrefix(flags, "K") {
			out = append(out, f)
		}
	}
	return out, first, nil
}

// onGrid: keyframes sit exactly KeyframeSeconds apart from the first one and cover the whole source.
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
