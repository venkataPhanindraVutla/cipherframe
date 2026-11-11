package media

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

var testLimits = Limits{MaxDuration: 4 * time.Hour, MaxWidth: 3840, MaxHeight: 2160}

func goodInfo() Info {
	return Info{
		Container: ContainerMP4, FormatName: mp4Format, Duration: time.Minute,
		Video: &VideoStream{Codec: "h264", Width: 1920, Height: 1080, DisplayWidth: 1920, DisplayHeight: 1080},
		Audio: &AudioStream{Codec: "aac", Channels: 2, SampleRate: 48000},
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Info)
		wantErr string // substring of the detail; empty means valid
	}{
		{"valid", func(*Info) {}, ""},
		{"valid without audio", func(i *Info) { i.Audio = nil }, ""},
		{"valid matroska vp9 opus", func(i *Info) {
			i.Container = ContainerMatroska
			i.Video.Codec = "vp9"
			i.Audio.Codec = "opus"
		}, ""},
		{"at the duration limit", func(i *Info) { i.Duration = 4 * time.Hour }, ""},
		{"at the resolution limit", func(i *Info) {
			i.Video.Width, i.Video.Height, i.Video.DisplayWidth, i.Video.DisplayHeight = 3840, 2160, 3840, 2160
		}, ""},
		{"portrait 4K passes a landscape limit", func(i *Info) {
			i.Video.Width, i.Video.Height, i.Video.DisplayWidth, i.Video.DisplayHeight = 3840, 2160, 2160, 3840
			i.Video.Rotation = 90
		}, ""},
		{"unknown container", func(i *Info) { i.Container = "avi" }, "Unsupported container"},
		{"no video", func(i *Info) { i.Video = nil }, "no video stream"},
		{"unsupported video codec", func(i *Info) { i.Video.Codec = "mpeg2video" }, "Unsupported video codec"},
		{"unsupported audio codec", func(i *Info) { i.Audio.Codec = "ac3" }, "Unsupported audio codec"},
		{"zero width", func(i *Info) { i.Video.DisplayWidth = 0 }, "invalid dimensions"},
		{"zero coded height", func(i *Info) { i.Video.Height = 0 }, "invalid dimensions"},
		{"negative", func(i *Info) { i.Video.Width = -4 }, "invalid dimensions"},
		{"tiny", func(i *Info) {
			i.Video.Width, i.Video.Height, i.Video.DisplayWidth, i.Video.DisplayHeight = 8, 8, 8, 8
		}, "too small"},
		{"absurd aspect", func(i *Info) {
			i.Video.Width, i.Video.Height, i.Video.DisplayWidth, i.Video.DisplayHeight = 3840, 20, 3840, 20
		}, "aspect ratio"},
		{"too wide", func(i *Info) { i.Video.Width, i.Video.DisplayWidth = 4096, 4096 }, "exceeds the limit of 3840x2160"},
		{"too tall", func(i *Info) { i.Video.Width, i.Video.Height, i.Video.DisplayWidth, i.Video.DisplayHeight = 3840, 2304, 3840, 2304 }, "exceeds the limit"},
		{"square too big for the short side", func(i *Info) {
			i.Video.Width, i.Video.Height, i.Video.DisplayWidth, i.Video.DisplayHeight = 3840, 3840, 3840, 3840
		}, "exceeds the limit"},
		{"coded frame over the limit, display under", func(i *Info) {
			i.Video.Width, i.Video.Height = 8192, 4320
		}, "exceeds the limit"},
		{"anamorphic stretched past the limit", func(i *Info) { i.Video.DisplayWidth = 5000 }, "exceeds the limit"},
		{"too long", func(i *Info) { i.Duration = 4*time.Hour + time.Second }, "longer than the limit of 4 hours"},
		{"unknown duration", func(i *Info) { i.Duration = 0 }, "duration could not be determined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info := goodInfo()
			c.mutate(&info)
			err := Validate(info, testLimits)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var e *errs.Error
			if !errors.As(err, &e) {
				t.Fatalf("want *errs.Error, got %v", err)
			}
			if e.Code != errs.InvalidRequest || !strings.Contains(e.Detail, c.wantErr) {
				t.Fatalf("code %q detail %q; want invalid_request containing %q", e.Code, e.Detail, c.wantErr)
			}
			if strings.ContainsAny(e.Detail, "/\\") && !strings.Contains(e.Detail, "x") {
				t.Fatalf("detail looks like a path: %q", e.Detail)
			}
		})
	}
}

func TestValidateLimitsAreConfigurable(t *testing.T) {
	info := goodInfo()
	if err := Validate(info, Limits{MaxDuration: 30 * time.Second, MaxWidth: 3840, MaxHeight: 2160}); err == nil ||
		!strings.Contains(err.Error(), "30s") {
		t.Fatalf("got %v", err)
	}
	if err := Validate(info, Limits{MaxDuration: time.Hour, MaxWidth: 1280, MaxHeight: 720}); err == nil ||
		!strings.Contains(err.Error(), "1280x720") {
		t.Fatalf("got %v", err)
	}
}
