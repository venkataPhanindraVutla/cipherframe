package media

import (
	"fmt"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// Supported inputs (ADR 0024): the demuxers and decoders the worker's FFmpeg build contains.
var (
	supportedVideoCodecs = map[string]bool{"h264": true, "hevc": true, "vp8": true, "vp9": true, "av1": true}
	supportedAudioCodecs = map[string]bool{"aac": true, "opus": true, "mp3": true}
)

// Dimension bounds that no real video violates.
const (
	minDimension = 16
	maxAspect    = 32 // longest side over shortest side
)

// Limits are the largest source the worker accepts (ADR 0025).
type Limits struct {
	MaxDuration time.Duration
	// MaxWidth and MaxHeight bound the picture a viewer sees. They apply to the display size, and
	// the picture may be rotated: a 2160x3840 portrait video passes a 3840x2160 limit, a
	// 3840x3840 one does not.
	MaxWidth, MaxHeight int
}

// Validate decides whether the probed source may be transcoded. Every failure is an invalid_request
// error whose detail names the problem and the limit, never a path or other internal text.
func Validate(info Info, lim Limits) error {
	bad := func(format string, a ...any) error {
		return errs.New(errs.InvalidRequest, fmt.Sprintf(format, a...))
	}
	if info.Container != ContainerMP4 && info.Container != ContainerMatroska {
		return bad("Unsupported container. Supported: MP4, MOV, WebM and Matroska.")
	}
	v := info.Video
	if v == nil {
		return bad("The file has no video stream.")
	}
	if !supportedVideoCodecs[v.Codec] {
		return bad("Unsupported video codec. Supported: H.264, HEVC, VP8, VP9 and AV1.")
	}
	if info.Audio != nil && !supportedAudioCodecs[info.Audio.Codec] {
		return bad("Unsupported audio codec. Supported: AAC, Opus and MP3.")
	}
	if v.Width <= 0 || v.Height <= 0 || v.DisplayWidth <= 0 || v.DisplayHeight <= 0 {
		return bad("The video has invalid dimensions.")
	}
	long, short := max(v.DisplayWidth, v.DisplayHeight), min(v.DisplayWidth, v.DisplayHeight)
	if short < minDimension {
		return bad("The video is too small: at least %d pixels on each side.", minDimension)
	}
	if long/short > maxAspect {
		return bad("The video's aspect ratio is not supported.")
	}
	// The stored frame is what the decoder allocates, so it is bounded too, in either orientation.
	if exceeds(v.Width, v.Height, lim) || exceeds(v.DisplayWidth, v.DisplayHeight, lim) {
		return bad("The video resolution exceeds the limit of %dx%d.", lim.MaxWidth, lim.MaxHeight)
	}
	if info.Duration <= 0 {
		return bad("The video's duration could not be determined.")
	}
	if info.Duration > lim.MaxDuration {
		return bad("The video is longer than the limit of %s.", formatDuration(lim.MaxDuration))
	}
	return nil
}

// exceeds reports whether a w x h frame does not fit the limit in either orientation.
func exceeds(w, h int, lim Limits) bool {
	long, short := max(w, h), min(w, h)
	limLong, limShort := max(lim.MaxWidth, lim.MaxHeight), min(lim.MaxWidth, lim.MaxHeight)
	return long > limLong || short > limShort
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%d hours", int(d/time.Hour))
	case d%time.Minute == 0:
		return fmt.Sprintf("%d minutes", int(d/time.Minute))
	}
	return d.String()
}
