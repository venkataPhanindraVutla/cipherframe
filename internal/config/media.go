package config

import (
	"strconv"
	"strings"
	"time"
)

// Media environment variable names (ADR 0024, ADR 0025).
const (
	EnvFFmpegPath        = "CIPHERFRAME_FFMPEG_PATH"
	EnvFFprobePath       = "CIPHERFRAME_FFPROBE_PATH"
	EnvMaxSourceDuration = "CIPHERFRAME_MAX_SOURCE_DURATION"
	EnvMaxSourceWidth    = "CIPHERFRAME_MAX_SOURCE_WIDTH"
	EnvMaxSourceHeight   = "CIPHERFRAME_MAX_SOURCE_HEIGHT"
	EnvTranscodeTimeout  = "CIPHERFRAME_TRANSCODE_TIMEOUT"
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
}

func (l *loader) media() Media {
	return Media{
		FFmpegPath:        l.toolPath(EnvFFmpegPath, defaultFFmpegPath),
		FFprobePath:       l.toolPath(EnvFFprobePath, defaultFFprobePath),
		MaxSourceDuration: l.positiveDuration(EnvMaxSourceDuration, defaultMaxSourceDur, maxSourceDurationCeiling),
		MaxSourceWidth:    l.dimension(EnvMaxSourceWidth, defaultMaxSourceWidth),
		MaxSourceHeight:   l.dimension(EnvMaxSourceHeight, defaultMaxSourceHeight),
		TranscodeTimeout:  l.positiveDuration(EnvTranscodeTimeout, defaultTranscodeTimeout, transcodeTimeoutCeiling),
	}
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
