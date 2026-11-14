package config

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
)

// Media environment variable names (ADR 0024, ADR 0025).
const (
	EnvFFmpegPath        = "CIPHERFRAME_FFMPEG_PATH"
	EnvFFprobePath       = "CIPHERFRAME_FFPROBE_PATH"
	EnvMaxSourceDuration = "CIPHERFRAME_MAX_SOURCE_DURATION"
	EnvMaxSourceWidth    = "CIPHERFRAME_MAX_SOURCE_WIDTH"
	EnvMaxSourceHeight   = "CIPHERFRAME_MAX_SOURCE_HEIGHT"
	EnvTranscodeTimeout  = "CIPHERFRAME_TRANSCODE_TIMEOUT"
	EnvWorkDir           = "CIPHERFRAME_WORK_DIR"
	EnvMediaConcurrency  = "CIPHERFRAME_WORKER_MEDIA_CONCURRENCY"
	EnvMaskTimeout       = "CIPHERFRAME_WORKER_MASK_TIMEOUT"
	EnvMaskConcurrency   = "CIPHERFRAME_WORKER_MASK_CONCURRENCY"
	EnvLadderHeights     = "CIPHERFRAME_WORKER_LADDER_HEIGHTS"
)

// Media defaults and ceilings. The ceilings keep a typo from disabling a limit.
const (
	defaultFFmpegPath        = "ffmpeg"
	defaultFFprobePath       = "ffprobe"
	defaultMaxSourceDur      = 4 * time.Hour
	defaultMaxSourceWidth    = 3840
	defaultMaxSourceHeight   = 2160
	defaultTranscodeTimeout  = 6 * time.Hour
	maxSourceDurationCeiling = 7 * 24 * time.Hour
	transcodeTimeoutCeiling  = 7 * 24 * time.Hour
	defaultMaskTimeout       = 2 * time.Hour
	maskTimeoutCeiling       = 7 * 24 * time.Hour
	defaultMediaConcurrency  = 1
	defaultMaskConcurrency   = 1
	maxMediaConcurrency      = 64
	minSourceDimension       = 16
	maxSourceDimension       = 16384
)

// Media configures the FFmpeg toolchain and the limits on a source (ADR 0024, ADR 0025). Only the
// worker role uses it; api and edge never run FFmpeg.
type Media struct {
	// FFmpegPath and FFprobePath are a path or a bare name that is looked up on PATH. They are
	// executed directly, never through a shell.
	FFmpegPath  string
	FFprobePath string
	// MaxSourceDuration, MaxSourceWidth and MaxSourceHeight are enforced by the probe step before
	// any encoding. Width and height bound both the coded frame and the display size.
	MaxSourceDuration time.Duration
	MaxSourceWidth    int
	MaxSourceHeight   int
	// TranscodeTimeout bounds one whole transcode.
	TranscodeTimeout time.Duration
	// MaskTimeout bounds how long an asset.mask job waits for the masker (ADR 0036) to finish one
	// video. Past it the asset's masked variant is marked failed; the original stays playable.
	MaskTimeout time.Duration
	// WorkDir is the private directory under which each processing job gets its own subdirectory
	// for the downloaded source and the plaintext segments FFmpeg writes. The worker creates it
	// with mode 0700 and removes a job's subdirectory when the job ends.
	WorkDir string
	// Concurrency is how many asset.process jobs one worker process runs at once (the media
	// queue). Each FFmpeg run already uses every core, so the default is 1.
	Concurrency int
	// MaskConcurrency is how many asset.mask jobs one worker process runs at once (the mask
	// queue, ADR 0037). The masker is the heavy part, so the default is 1.
	MaskConcurrency int
	// LadderHeights restricts the ladder to these ADR 0024 rung heights, tallest first. Empty
	// means every rung. Both variants use it.
	LadderHeights []int
}

func (l *loader) media() Media {
	return Media{
		FFmpegPath:        l.toolPath(EnvFFmpegPath, defaultFFmpegPath),
		FFprobePath:       l.toolPath(EnvFFprobePath, defaultFFprobePath),
		MaxSourceDuration: l.positiveDuration(EnvMaxSourceDuration, defaultMaxSourceDur, maxSourceDurationCeiling),
		MaxSourceWidth:    l.dimension(EnvMaxSourceWidth, defaultMaxSourceWidth),
		MaxSourceHeight:   l.dimension(EnvMaxSourceHeight, defaultMaxSourceHeight),
		TranscodeTimeout:  l.positiveDuration(EnvTranscodeTimeout, defaultTranscodeTimeout, transcodeTimeoutCeiling),
		MaskTimeout:       l.positiveDuration(EnvMaskTimeout, defaultMaskTimeout, maskTimeoutCeiling),
		WorkDir:           l.workDir(),
		Concurrency:       l.concurrency(EnvMediaConcurrency, defaultMediaConcurrency),
		MaskConcurrency:   l.concurrency(EnvMaskConcurrency, defaultMaskConcurrency),
		LadderHeights:     l.ladderHeights(),
	}
}

// workDir reads CIPHERFRAME_WORK_DIR. The default is "cipherframe" under the operating system's
// temporary directory. The path must be absolute (FFmpeg is handed absolute file: URLs).
func (l *loader) workDir() string {
	v := l.plain(EnvWorkDir, "")
	if v == "" {
		return filepath.Join(os.TempDir(), "cipherframe")
	}
	if strings.ContainsAny(v, "\x00\r\n") || strings.TrimSpace(v) != v || !filepath.IsAbs(v) {
		l.errf("%s must be an absolute path without control characters or surrounding spaces", EnvWorkDir)
		return v
	}
	return filepath.Clean(v)
}

func (l *loader) toolPath(name, def string) string {
	v := l.plain(name, def)
	if strings.ContainsAny(v, "\x00\r\n") || strings.TrimSpace(v) != v {
		l.errf("%s must be a path without control characters or surrounding spaces", name)
	}
	if strings.HasPrefix(v, "-") {
		l.errf("%s must not start with '-'", name)
	}
	return v
}

func (l *loader) positiveDuration(name string, def, ceiling time.Duration) time.Duration {
	v := l.plain(name, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 || d > ceiling {
		l.errf("%s must be a duration above zero and at most %s, for example 4h", name, ceiling)
		return def
	}
	return d
}

func (l *loader) dimension(name string, def int) int {
	v := l.plain(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < minSourceDimension || n > maxSourceDimension {
		l.errf("%s must be a whole number of pixels from %d to %d", name, minSourceDimension, maxSourceDimension)
		return def
	}
	return n
}

func (l *loader) concurrency(name string, def int) int {
	v := l.plain(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > maxMediaConcurrency {
		l.errf("%s must be a whole number from 1 to %d", name, maxMediaConcurrency)
		return def
	}
	return n
}

// ladderHeights reads CIPHERFRAME_WORKER_LADDER_HEIGHTS: a comma-separated subset of the rung
// heights of ADR 0024, returned tallest first. Unset means every rung (nil).
func (l *loader) ladderHeights() []int {
	v := l.plain(EnvLadderHeights, "")
	if v == "" {
		return nil
	}
	known := media.RungHeights()
	var picked []int
	for part := range strings.SplitSeq(v, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || !slices.Contains(known, n) || slices.Contains(picked, n) {
			l.errf("%s must be a comma-separated list of distinct rung heights from %v, for example 720,360", EnvLadderHeights, known)
			return nil
		}
		picked = append(picked, n)
	}
	slices.SortFunc(picked, func(a, b int) int { return b - a })
	return picked
}
