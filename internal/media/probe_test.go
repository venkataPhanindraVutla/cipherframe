package media

import (
	"fmt"
	"testing"
	"time"
)

// probeFixture builds FFprobe-shaped JSON.
func probeFixture(format, duration string, streams ...string) []byte {
	s := ""
	for i, st := range streams {
		if i > 0 {
			s += ","
		}
		s += st
	}
	return []byte(fmt.Sprintf(`{"streams":[%s],"format":{"format_name":%q,"duration":%q}}`, s, format, duration))
}

func vstream(index int, codec string, w, h int, extra string) string {
	return fmt.Sprintf(`{"index":%d,"codec_name":%q,"codec_type":"video","width":%d,"height":%d,`+
		`"pix_fmt":"yuv420p","avg_frame_rate":"30000/1001","r_frame_rate":"30/1"%s}`, index, codec, w, h, extra)
}

func astream(index int, codec string) string {
	return fmt.Sprintf(`{"index":%d,"codec_name":%q,"codec_type":"audio","channels":2,"sample_rate":"48000"}`, index, codec)
}

const mp4Format = "mov,mp4,m4a,3gp,3g2,mj2"

func TestParseProbeLandscape(t *testing.T) {
	info, err := ParseProbe(probeFixture(mp4Format, "12.500000",
		vstream(0, "h264", 1920, 1080, `,"sample_aspect_ratio":"1:1"`), astream(1, "aac")))
	if err != nil {
		t.Fatal(err)
	}
	if info.Container != ContainerMP4 || info.Duration != 12500*time.Millisecond {
		t.Fatalf("container/duration: %+v", info)
	}
	v := info.Video
	if v == nil || v.Codec != "h264" || v.Width != 1920 || v.Height != 1080 || v.DisplayWidth != 1920 ||
		v.DisplayHeight != 1080 || v.Rotation != 0 || v.PixelFormat != "yuv420p" {
		t.Fatalf("video: %+v", v)
	}
	if v.FrameRate < 29.96 || v.FrameRate > 29.98 {
		t.Fatalf("frame rate %v", v.FrameRate)
	}
	if a := info.Audio; a == nil || a.Codec != "aac" || a.Channels != 2 || a.SampleRate != 48000 {
		t.Fatalf("audio: %+v", a)
	}
}

func TestParseProbeRotation(t *testing.T) {
	cases := []struct {
		name         string
		extra        string
		wantRot      int
		wantW, wantH int
		wantErr      bool
	}{
		{"none", ``, 0, 1920, 1080, false},
		{"matrix -90 is 90 clockwise", `,"side_data_list":[{"side_data_type":"Display Matrix","rotation":-90}]`, 90, 1080, 1920, false},
		{"matrix 90 is 270 clockwise", `,"side_data_list":[{"side_data_type":"Display Matrix","rotation":90}]`, 270, 1080, 1920, false},
		{"matrix 180", `,"side_data_list":[{"side_data_type":"Display Matrix","rotation":180}]`, 180, 1920, 1080, false},
		{"matrix -180", `,"side_data_list":[{"side_data_type":"Display Matrix","rotation":-180}]`, 180, 1920, 1080, false},
		{"matrix 0", `,"side_data_list":[{"side_data_type":"Display Matrix","rotation":0}]`, 0, 1920, 1080, false},
		{"legacy tag 90", `,"tags":{"rotate":"90"}`, 90, 1080, 1920, false},
		{"legacy tag 270", `,"tags":{"rotate":"270"}`, 270, 1080, 1920, false},
		{"matrix wins over tag", `,"tags":{"rotate":"90"},"side_data_list":[{"side_data_type":"Display Matrix","rotation":0}]`, 0, 1920, 1080, false},
		{"other side data ignored", `,"side_data_list":[{"side_data_type":"Mastering display metadata"}]`, 0, 1920, 1080, false},
		{"odd angle refused", `,"side_data_list":[{"side_data_type":"Display Matrix","rotation":33}]`, 0, 0, 0, true},
		{"bad tag refused", `,"tags":{"rotate":"x"}`, 0, 0, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info, err := ParseProbe(probeFixture(mp4Format, "5", vstream(0, "h264", 1920, 1080, c.extra)))
			if c.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			v := info.Video
			if v.Rotation != c.wantRot || v.DisplayWidth != c.wantW || v.DisplayHeight != c.wantH {
				t.Fatalf("rotation %d display %dx%d; want %d %dx%d", v.Rotation, v.DisplayWidth, v.DisplayHeight, c.wantRot, c.wantW, c.wantH)
			}
			if v.Width != 1920 || v.Height != 1080 {
				t.Fatalf("coded size changed: %dx%d", v.Width, v.Height)
			}
		})
	}
}

func TestParseProbeSampleAspectRatio(t *testing.T) {
	// 720x576 PAL widescreen: SAR 64:45 displays 1024 wide.
	info, err := ParseProbe(probeFixture(mp4Format, "5", vstream(0, "h264", 720, 576, `,"sample_aspect_ratio":"64:45"`)))
	if err != nil {
		t.Fatal(err)
	}
	if v := info.Video; v.DisplayWidth != 1024 || v.DisplayHeight != 576 {
		t.Fatalf("display %dx%d", v.DisplayWidth, v.DisplayHeight)
	}
	// "0:1" and "N/A" mean unknown and must not change the size.
	for _, sar := range []string{"0:1", "N/A", ""} {
		info, err := ParseProbe(probeFixture(mp4Format, "5", vstream(0, "h264", 640, 360, fmt.Sprintf(`,"sample_aspect_ratio":%q`, sar))))
		if err != nil {
			t.Fatal(err)
		}
		if v := info.Video; v.DisplayWidth != 640 || v.DisplayHeight != 360 {
			t.Fatalf("sar %q: display %dx%d", sar, v.DisplayWidth, v.DisplayHeight)
		}
	}
	// Anamorphic and rotated: swap after stretching.
	info, err = ParseProbe(probeFixture(mp4Format, "5",
		vstream(0, "h264", 720, 576, `,"sample_aspect_ratio":"64:45","tags":{"rotate":"90"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if v := info.Video; v.DisplayWidth != 576 || v.DisplayHeight != 1024 {
		t.Fatalf("display %dx%d", v.DisplayWidth, v.DisplayHeight)
	}
}

func TestParseProbeStreams(t *testing.T) {
	t.Run("no audio", func(t *testing.T) {
		info, err := ParseProbe(probeFixture(mp4Format, "5", vstream(0, "h264", 640, 360, "")))
		if err != nil || info.Audio != nil || info.Video == nil {
			t.Fatalf("%+v %v", info, err)
		}
	})
	t.Run("no video", func(t *testing.T) {
		info, err := ParseProbe(probeFixture(mp4Format, "5", astream(0, "aac")))
		if err != nil || info.Video != nil || info.Audio == nil {
			t.Fatalf("%+v %v", info, err)
		}
	})
	t.Run("cover art is not video", func(t *testing.T) {
		cover := vstream(0, "mjpeg", 500, 500, `,"disposition":{"attached_pic":1}`)
		info, err := ParseProbe(probeFixture("mp3", "5", cover, astream(1, "mp3")))
		if err != nil || info.Video != nil {
			t.Fatalf("%+v %v", info, err)
		}
	})
	t.Run("first video and first audio win", func(t *testing.T) {
		info, err := ParseProbe(probeFixture("matroska,webm", "5",
			astream(0, "opus"), vstream(1, "vp9", 1280, 720, ""), vstream(2, "h264", 320, 240, ""), astream(3, "aac")))
		if err != nil {
			t.Fatal(err)
		}
		if info.Container != ContainerMatroska || info.Video.Index != 1 || info.Audio.Index != 0 {
			t.Fatalf("%+v %+v %+v", info, info.Video, info.Audio)
		}
	})
	t.Run("duration falls back to the stream", func(t *testing.T) {
		info, err := ParseProbe(probeFixture(mp4Format, "N/A", vstream(0, "h264", 640, 360, `,"duration":"7.5"`)))
		if err != nil || info.Duration != 7500*time.Millisecond {
			t.Fatalf("%+v %v", info, err)
		}
	})
	t.Run("absurd duration is clamped", func(t *testing.T) {
		info, err := ParseProbe(probeFixture(mp4Format, "1e300", vstream(0, "h264", 640, 360, "")))
		if err != nil || info.Duration != maxDuration {
			t.Fatalf("%+v %v", info.Duration, err)
		}
	})
	t.Run("negative and NaN duration are unknown", func(t *testing.T) {
		for _, d := range []string{"-5", "NaN", "abc", ""} {
			info, err := ParseProbe(probeFixture(mp4Format, d, vstream(0, "h264", 640, 360, "")))
			if err != nil || info.Duration != 0 {
				t.Fatalf("%q: %+v %v", d, info.Duration, err)
			}
		}
	})
}

func TestParseProbeGarbage(t *testing.T) {
	for _, in := range []string{``, `not json`, `{}`, `{"streams":[],"format":{}}`, `[1,2]`} {
		if _, err := ParseProbe([]byte(in)); err == nil {
			t.Errorf("%q: expected an error", in)
		}
	}
}

func TestSourceURL(t *testing.T) {
	for _, bad := range []string{"", "relative.mp4", "-i", "../x", "http://example.com/x"} {
		if _, err := SourceURL(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	got, err := SourceURL("/work/-evil name.mp4")
	if err != nil || got != "file:/work/-evil name.mp4" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = SourceURL("/work/a/../b.mp4")
	if err != nil || got != "file:/work/b.mp4" {
		t.Fatalf("%q %v", got, err)
	}
}
