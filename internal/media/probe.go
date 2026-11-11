package media

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// Probe limits.
const (
	// DefaultProbeTimeout bounds one FFprobe run.
	DefaultProbeTimeout = 60 * time.Second
	// maxProbeOutput caps FFprobe's JSON. A file with thousands of streams or tags cannot make the
	// worker buffer more than this.
	maxProbeOutput = 4 << 20
	// maxDuration is the longest duration Info reports; it keeps time.Duration from overflowing on
	// a hostile header.
	maxDuration = 100 * 365 * 24 * time.Hour
)

// Container families, after FFprobe's comma-separated format_name is normalised.
const (
	ContainerMP4      = "mp4"      // MP4 and QuickTime (the mov demuxer)
	ContainerMatroska = "matroska" // Matroska and WebM
)

// Info is what FFprobe reported about a source, reduced to what Cipherframe uses. It describes an
// untrusted file: run Validate before relying on it.
type Info struct {
	// Container is ContainerMP4 or ContainerMatroska, or the raw FFprobe format name when it is
	// neither. FormatName is always the raw value.
	Container  string
	FormatName string
	// Duration is zero when FFprobe could not tell.
	Duration time.Duration
	// Video is the first non-cover-art video stream, nil when there is none.
	Video *VideoStream
	// Audio is the first audio stream, nil when there is none.
	Audio *AudioStream
}

// VideoStream describes the chosen video stream.
type VideoStream struct {
	Index int
	Codec string
	// Width and Height are the stored (coded) frame size.
	Width, Height int
	// DisplayWidth and DisplayHeight are the size a player shows: the sample aspect ratio is
	// applied to the width, and width and height swap when the display matrix rotates the picture
	// by 90 or 270 degrees.
	DisplayWidth, DisplayHeight int
	// Rotation is the clockwise rotation a player applies, 0, 90, 180 or 270 degrees.
	Rotation int
	// FrameRate is frames per second, 0 when unknown.
	FrameRate   float64
	PixelFormat string
}

// AudioStream describes the chosen audio stream.
type AudioStream struct {
	Index      int
	Codec      string
	Channels   int
	SampleRate int
}

// Probe runs FFprobe on the absolute path of a source and returns what it found. The path is passed
// as a "file:" URL with network protocols disabled (see SourceURL). A file FFprobe cannot read as
// media gives an invalid_request error with a fixed detail; an FFprobe that cannot run gives
// internal_error; a deadline gives timeout.
func (t Tools) Probe(ctx context.Context, path string) (Info, error) {
	src, err := SourceURL(path)
	if err != nil {
		return Info{}, errs.Wrap(errs.InternalError, "", err)
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultProbeTimeout)
	defer cancel()

	res, err := run(ctx, t.FFprobe, []string{
		"-hide_banner",
		"-v", "error",
		"-protocol_whitelist", "file,pipe",
		"-print_format", "json",
		"-show_format",
		"-show_streams",
		"-i", src,
	}, maxProbeOutput)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return Info{}, errs.Wrap(errs.Timeout, "Inspecting the media file took too long.", err)
	case errors.Is(err, context.Canceled):
		return Info{}, err
	case errors.Is(err, errOutputTooLarge):
		return Info{}, errs.Wrap(errs.InvalidRequest, "The media file's metadata is too large to inspect.", err)
	case err != nil && res.exitCode != 0:
		// FFprobe ran and rejected the file.
		return Info{}, errs.Wrap(errs.InvalidRequest, "The file is not a readable, supported media file.", err)
	case err != nil:
		return Info{}, errs.Wrap(errs.InternalError, "", err)
	}
	info, err := ParseProbe(res.stdout)
	if err != nil {
		return Info{}, errs.Wrap(errs.InvalidRequest, "The file is not a readable, supported media file.", err)
	}
	return info, nil
}

// ffprobe JSON, only the fields we read. Numbers FFprobe prints as strings stay strings.
type probeJSON struct {
	Streams []probeStream `json:"streams"`
	Format  struct {
		FormatName string `json:"format_name"`
		Duration   string `json:"duration"`
	} `json:"format"`
}

type probeStream struct {
	Index             int    `json:"index"`
	CodecName         string `json:"codec_name"`
	CodecType         string `json:"codec_type"`
	Width             int    `json:"width"`
	Height            int    `json:"height"`
	SampleAspectRatio string `json:"sample_aspect_ratio"`
	PixFmt            string `json:"pix_fmt"`
	AvgFrameRate      string `json:"avg_frame_rate"`
	RFrameRate        string `json:"r_frame_rate"`
	Duration          string `json:"duration"`
	Channels          int    `json:"channels"`
	SampleRate        string `json:"sample_rate"`
	Disposition       struct {
		AttachedPic int `json:"attached_pic"`
	} `json:"disposition"`
	Tags     map[string]string `json:"tags"`
	SideData []struct {
		Type     string   `json:"side_data_type"`
		Rotation *float64 `json:"rotation"`
	} `json:"side_data_list"`
}

// ParseProbe turns FFprobe's JSON into Info. It is exported so callers that already hold FFprobe
// output (and tests) can reuse the exact interpretation rules.
func ParseProbe(data []byte) (Info, error) {
	var p probeJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return Info{}, fmt.Errorf("media: parse ffprobe output: %w", err)
	}
	if p.Format.FormatName == "" && len(p.Streams) == 0 {
		return Info{}, errors.New("media: ffprobe reported no format and no streams")
	}
	info := Info{
		FormatName: p.Format.FormatName,
		Container:  normalizeContainer(p.Format.FormatName),
		Duration:   parseDuration(p.Format.Duration),
	}
	for i := range p.Streams {
		s := &p.Streams[i]
		switch s.CodecType {
		case "video":
			if info.Video != nil || s.Disposition.AttachedPic != 0 {
				continue
			}
			v, err := videoStream(s)
			if err != nil {
				return Info{}, err
			}
			info.Video = v
			if info.Duration == 0 {
				info.Duration = parseDuration(s.Duration)
			}
		case "audio":
			if info.Audio != nil {
				continue
			}
			rate, _ := strconv.Atoi(s.SampleRate)
			info.Audio = &AudioStream{Index: s.Index, Codec: s.CodecName, Channels: s.Channels, SampleRate: rate}
		}
	}
	return info, nil
}

func videoStream(s *probeStream) (*VideoStream, error) {
	v := &VideoStream{
		Index:       s.Index,
		Codec:       s.CodecName,
		Width:       s.Width,
		Height:      s.Height,
		PixelFormat: s.PixFmt,
		FrameRate:   parseRate(s.AvgFrameRate),
	}
	if v.FrameRate == 0 {
		v.FrameRate = parseRate(s.RFrameRate)
	}
	rot, err := rotation(s)
	if err != nil {
		return nil, err
	}
	v.Rotation = rot

	dw, dh := s.Width, s.Height
	if num, den, ok := parseRatio(s.SampleAspectRatio); ok && dw > 0 && num != den {
		// Anamorphic: the stored width is stretched by the sample aspect ratio when displayed.
		scaled := math.Round(float64(dw) * float64(num) / float64(den))
		if scaled >= 1 && scaled <= math.MaxInt32 {
			dw = int(scaled)
		}
	}
	if rot == 90 || rot == 270 {
		dw, dh = dh, dw
	}
	v.DisplayWidth, v.DisplayHeight = dw, dh
	return v, nil
}

// rotation returns the clockwise rotation in degrees from the display matrix (or the legacy rotate
// tag). FFprobe reports the matrix angle counter-clockwise ("rotation": -90 means a 90 degree
// clockwise turn). Angles that are not a multiple of 90 are refused.
func rotation(s *probeStream) (int, error) {
	var deg float64
	found := false
	for _, sd := range s.SideData {
		if sd.Rotation != nil && strings.EqualFold(sd.Type, "Display Matrix") {
			deg, found = -*sd.Rotation, true
			break
		}
	}
	if !found {
		if tag, ok := s.Tags["rotate"]; ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(tag), 64)
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				return 0, errors.New("media: unreadable rotate tag")
			}
			deg, found = f, true
		}
	}
	if !found {
		return 0, nil
	}
	if math.Abs(deg) > 1e6 {
		return 0, errors.New("media: absurd rotation")
	}
	nearest := math.Round(deg/90) * 90
	if math.Abs(deg-nearest) > 0.5 {
		return 0, errors.New("media: rotation is not a multiple of 90 degrees")
	}
	r := int(nearest) % 360
	if r < 0 {
		r += 360
	}
	return r, nil
}

func normalizeContainer(format string) string {
	names := strings.Split(format, ",")
	has := func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
	switch {
	case has("mov") || has("mp4"):
		return ContainerMP4
	case has("matroska") || has("webm"):
		return ContainerMatroska
	}
	return format
}

// parseDuration reads FFprobe's seconds string. Unknown or unusable values give 0.
func parseDuration(s string) time.Duration {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) || f <= 0 {
		return 0
	}
	if math.IsInf(f, 1) || f >= maxDuration.Seconds() {
		return maxDuration
	}
	return time.Duration(f * float64(time.Second))
}

func parseRatio(s string) (num, den int64, ok bool) {
	a, b, found := strings.Cut(strings.TrimSpace(s), ":")
	if !found {
		a, b, found = strings.Cut(strings.TrimSpace(s), "/")
	}
	if !found {
		return 0, 0, false
	}
	n, err1 := strconv.ParseInt(a, 10, 64)
	d, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil || n <= 0 || d <= 0 {
		return 0, 0, false
	}
	return n, d, true
}

func parseRate(s string) float64 {
	n, d, ok := parseRatio(s)
	if !ok {
		return 0
	}
	return float64(n) / float64(d)
}
