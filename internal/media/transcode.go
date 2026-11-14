package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// Packaging constants of ADR 0024. Segments are cut at keyframes, so a segment is a whole number
// of GOPs: SegmentSeconds must be a multiple of KeyframeSeconds.
const (
	// SegmentSeconds is the target segment duration.
	SegmentSeconds = 6
	// KeyframeSeconds is the keyframe interval, identical on every rendition.
	KeyframeSeconds = 2
	// MaxFrameRate caps the output frame rate; a 120 fps source is delivered at 60.
	MaxFrameRate = 60
	// DefaultFrameRate is used when the source's rate is unknown.
	DefaultFrameRate = 30
	// X264Preset trades CPU time for compression. It does not change the segment structure.
	X264Preset = "medium"
	// OutputSampleRate is the audio sample rate of every rendition.
	OutputSampleRate = 48000
)

// FFmpeg's HLS output of one rendition, relative to the rendition's directory. The names are
// fixed so Go can find the files without trusting a path read from a playlist.
const (
	// PlaylistFile is FFmpeg's own playlist. Only its segment durations are used: the playlists
	// that are stored are written by Go (package hls).
	PlaylistFile = "playlist.m3u8"
	// InitFile is the init segment.
	InitFile = "init.mp4"
	// SegmentPattern is FFmpeg's segment file name template; numbers start at FirstSegmentNumber.
	SegmentPattern     = "seg_%d.m4s"
	FirstSegmentNumber = 1
)

// FrameRate is the constant output frame rate of every rendition.
type FrameRate struct {
	// Expr is the value handed to FFmpeg's fps filter, an exact rational for NTSC rates.
	Expr string
	// FPS is the same rate as a number, for the master playlist's FRAME-RATE.
	FPS float64
	// GOP is the keyframe interval in frames (the ceiling of KeyframeSeconds * FPS).
	GOP int
}

// OutputFrameRate picks the output rate for a source: the source's own rate, capped at MaxFrameRate,
// with the NTSC rates (24000/1001, 30000/1001, 60000/1001) kept exact so a 29.97 fps source does
// not drift against its audio. An unknown rate gives DefaultFrameRate.
func OutputFrameRate(src float64) FrameRate {
	if math.IsNaN(src) || math.IsInf(src, 0) || src < 1 {
		src = DefaultFrameRate
	}
	src = math.Min(src, MaxFrameRate)
	for _, n := range []struct {
		num  int
		rate float64
	}{{24000, 24000.0 / 1001}, {30000, 30000.0 / 1001}, {60000, 60000.0 / 1001}} {
		if math.Abs(src-n.rate) < 0.02 {
			return FrameRate{Expr: strconv.Itoa(n.num) + "/1001", FPS: n.rate, GOP: gop(n.rate)}
		}
	}
	if r := math.Round(src); math.Abs(src-r) < 0.01 {
		return FrameRate{Expr: strconv.Itoa(int(r)), FPS: r, GOP: gop(r)}
	}
	r := math.Round(src*1000) / 1000
	return FrameRate{Expr: strconv.FormatFloat(r, 'f', 3, 64), FPS: r, GOP: gop(r)}
}

func gop(fps float64) int { return int(math.Ceil(KeyframeSeconds * fps)) }

// TranscodeSpec describes one transcode of a validated source into the whole ladder.
type TranscodeSpec struct {
	// Source is the absolute path of the source file.
	Source string
	// OutDir is the absolute directory that receives one subdirectory per rendition, named by
	// Rendition.Name. Create it (empty) before the run.
	OutDir string
	// Info is the probe result of the source and Renditions the ladder chosen for it.
	Info       Info
	Renditions []Rendition
}

// RenditionDir is where FFmpeg writes a rendition's files.
func (s TranscodeSpec) RenditionDir(r Rendition) string { return filepath.Join(s.OutDir, r.Name) }

// TranscodeArgs builds the FFmpeg arguments for the whole ladder: ONE process that decodes the
// source once and fans the frames out through a split filter into one scaled branch per rendition.
//
//	-i file:SRC
//	-filter_complex [v]fps=R,split=N[s0]..[sN];[s0]scale=WxH,setsar=1,format=yuv420p[v0];...
//	per rendition:  -map [vI] -map 0:A  libx264 High, capped CRF, maxrate/bufsize, keyframes
//	                every 2 s at the same timestamps (forced, no scene cuts, closed GOP),
//	                AAC 96 kbps stereo, and an HLS fMP4 muxer with 6 s segments
//
// Keyframe placement is what makes the renditions switchable (pitfall 4). Every branch sees the
// same frames at the same constant frame rate, and each encoder is told to emit a keyframe on the
// first frame at or after every multiple of KeyframeSeconds (-force_key_frames), to add none of its
// own (-sc_threshold 0, -keyint_min equal to -g) and to make them IDR frames with closed GOPs. The
// HLS muxer then cuts a segment on the first keyframe after SegmentSeconds, which is the same
// frame on every rendition. Rotation needs no argument: FFmpeg applies the display matrix when it
// decodes (autorotate), before the filter graph.
func TranscodeArgs(spec TranscodeSpec) ([]string, error) {
	src, err := SourceURL(spec.Source)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(spec.OutDir) || strings.ContainsRune(spec.OutDir, 0) {
		return nil, errors.New("media: output directory must be absolute")
	}
	v := spec.Info.Video
	if v == nil || len(spec.Renditions) == 0 {
		return nil, errors.New("media: nothing to transcode")
	}
	rate := OutputFrameRate(v.FrameRate)

	var fg strings.Builder
	fmt.Fprintf(&fg, "[0:%d]fps=%s,split=%d", v.Index, rate.Expr, len(spec.Renditions))
	for i := range spec.Renditions {
		fmt.Fprintf(&fg, "[s%d]", i)
	}
	for i, r := range spec.Renditions {
		if r.Width < 2 || r.Height < 2 || r.Width%2 != 0 || r.Height%2 != 0 {
			return nil, errors.New("media: rendition size must be even")
		}
		fmt.Fprintf(&fg, ";[s%d]scale=%d:%d:flags=bicubic,setsar=1,format=yuv420p[v%d]", i, r.Width, r.Height, i)
	}

	args := []string{
		"-hide_banner", "-nostdin", "-v", "error", "-nostats",
		"-progress", "pipe:1",
		"-protocol_whitelist", "file,pipe",
		"-y",
		"-i", src,
		"-filter_complex", fg.String(),
	}
	for i, r := range spec.Renditions {
		dir := spec.RenditionDir(r)
		args = append(args,
			"-map", fmt.Sprintf("[v%d]", i))
		if spec.Info.Audio != nil {
			args = append(args, "-map", fmt.Sprintf("0:%d", spec.Info.Audio.Index))
		}
		args = append(args,
			"-c:v", "libx264", "-profile:v", "high", "-preset", X264Preset,
			"-crf", strconv.Itoa(r.CRF),
			"-maxrate", strconv.Itoa(r.MaxrateKbps)+"k", "-bufsize", strconv.Itoa(r.BufsizeKbps)+"k",
			"-g", strconv.Itoa(rate.GOP), "-keyint_min", strconv.Itoa(rate.GOP),
			"-sc_threshold", "0", "-x264-params", "open-gop=0", "-forced-idr", "1",
			"-force_key_frames", "expr:gte(t,n_forced*"+strconv.Itoa(KeyframeSeconds)+")",
			"-fps_mode", "cfr",
		)
		if spec.Info.Audio != nil {
			args = append(args,
				"-c:a", "aac", "-b:a", strconv.Itoa(r.AudioKbps)+"k", "-ac", "2", "-ar", strconv.Itoa(OutputSampleRate))
			// Audio longer than the video would extend the media past the last frame, so cap each
			// output at the video's duration. Shorter audio is untouched: video is never cut.
			if v.Duration > 0 {
				args = append(args, "-t", strconv.FormatFloat(v.Duration.Seconds(), 'f', 6, 64))
			}
		}
		args = append(args,
			"-f", "hls",
			"-hls_time", strconv.Itoa(SegmentSeconds),
			"-hls_playlist_type", "vod",
			"-hls_segment_type", "fmp4",
			"-hls_flags", "independent_segments",
			"-hls_list_size", "0",
			"-start_number", strconv.Itoa(FirstSegmentNumber),
			"-hls_fmp4_init_filename", InitFile,
			"-hls_segment_filename", "file:"+filepath.Join(dir, SegmentPattern),
			"file:"+filepath.Join(dir, PlaylistFile),
		)
	}
	return args, nil
}

// maxProgressLine bounds one line of FFmpeg's progress output.
const maxProgressLine = 4096

// Transcode runs the single FFmpeg process for the whole ladder and waits for it. progress, when
// not nil, is called with the position in the output (how much of the source has been encoded)
// every time FFmpeg reports it, about twice a second; the callback must return quickly.
//
// The child process gets an empty environment (see run) and is killed when ctx ends. A deadline
// gives a timeout error, a cancelled context returns the context's error, a source FFmpeg cannot
// decode gives an invalid_request error with a fixed detail, and any other failure is an
// internal_error. FFmpeg's stderr is kept in the error's cause only.
func (t Tools) Transcode(ctx context.Context, spec TranscodeSpec, progress func(done time.Duration)) error {
	args, err := TranscodeArgs(spec)
	if err != nil {
		return errs.Wrap(errs.InternalError, "", err)
	}
	for _, r := range spec.Renditions {
		if err := os.MkdirAll(spec.RenditionDir(r), 0o700); err != nil {
			return errs.Wrap(errs.InternalError, "", fmt.Errorf("media: create rendition directory: %w", err))
		}
	}
	stderr, err := runStreaming(ctx, t.FFmpeg, args, progressWriter(progress))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		return errs.Wrap(errs.Timeout, "Transcoding took too long.", err)
	case errors.Is(err, context.Canceled):
		return err
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return errs.Wrap(errs.InvalidRequest, "The media file could not be transcoded.",
			fmt.Errorf("ffmpeg exited with code %d: %s", ee.ExitCode(), stderr))
	}
	return errs.Wrap(errs.InternalError, "", err)
}

// runStreaming is run for a long process whose stdout is consumed as it arrives. It returns the
// start of stderr (for the error's cause) and the process error.
func runStreaming(ctx context.Context, bin string, args []string, stdout io.Writer) (string, error) {
	if strings.TrimSpace(bin) == "" {
		return "", errors.New("media: no binary configured")
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // I1: argument array, never a shell; the binary is operator configuration
	cmd.Env = []string{"LC_ALL=C"}
	cmd.WaitDelay = waitDelay
	errBuf := &cappedBuffer{limit: 16 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = tolerantWriter{errBuf}
	err := cmd.Run()
	if cerr := ctx.Err(); cerr != nil {
		return "", cerr
	}
	return strings.TrimSpace(errBuf.buf.String()), err
}

// progressWriter parses FFmpeg's "-progress" key=value lines as they arrive and reports each
// out_time_us. It never fails a write: progress is a convenience, and a failed write would make
// FFmpeg stop. exec calls Write from one goroutine at a time.
func progressWriter(fn func(time.Duration)) io.Writer {
	if fn == nil {
		return io.Discard
	}
	return &lineParser{fn: fn}
}

type lineParser struct {
	fn   func(time.Duration)
	buf  []byte
	skip bool // inside a line longer than maxProgressLine
}

func (l *lineParser) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if !l.skip && len(l.buf)+len(p) <= maxProgressLine {
				l.buf = append(l.buf, p...)
			} else {
				l.skip, l.buf = true, l.buf[:0]
			}
			return n, nil
		}
		if !l.skip && len(l.buf)+i <= maxProgressLine {
			l.buf = append(l.buf, p[:i]...)
			if d, ok := ParseProgressLine(string(l.buf)); ok {
				l.fn(d)
			}
		}
		l.buf, l.skip = l.buf[:0], false
		p = p[i+1:]
	}
	return n, nil
}

// ParseProgressLine reads one line of FFmpeg's "-progress" output. It returns the output position
// for an "out_time_us=" line and false for every other line (and for "N/A" or garbage).
func ParseProgressLine(line string) (time.Duration, bool) {
	us, ok := strings.CutPrefix(line, "out_time_us=")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(us), 10, 64)
	if err != nil || n < 0 || n > int64(maxDuration/time.Microsecond) {
		return 0, false
	}
	return time.Duration(n) * time.Microsecond, true
}
