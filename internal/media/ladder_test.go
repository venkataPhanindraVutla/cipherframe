package media

import (
	"fmt"
	"testing"
)

func infoWithDisplay(w, h int, audio bool) Info {
	i := Info{Video: &VideoStream{Width: w, Height: h, DisplayWidth: w, DisplayHeight: h}}
	if audio {
		i.Audio = &AudioStream{Codec: "aac", Channels: 2, SampleRate: 48000}
	}
	return i
}

type rd struct {
	name string
	w, h int
}

func TestLadder(t *testing.T) {
	cases := []struct {
		name string
		info Info
		want []rd
	}{
		{"4K landscape", infoWithDisplay(3840, 2160, true), []rd{
			{"1080p", 1920, 1080}, {"720p", 1280, 720}, {"480p", 854, 480}, {"360p", 640, 360}, {"240p", 426, 240},
		}},
		{"1080p exact", infoWithDisplay(1920, 1080, true), []rd{
			{"1080p", 1920, 1080}, {"720p", 1280, 720}, {"480p", 854, 480}, {"360p", 640, 360}, {"240p", 426, 240},
		}},
		{"1079 is not tall enough for 1080", infoWithDisplay(1918, 1079, true), []rd{
			{"720p", 1280, 720}, {"480p", 854, 480}, {"360p", 640, 360}, {"240p", 426, 240},
		}},
		{"720p exact", infoWithDisplay(1280, 720, true), []rd{
			{"720p", 1280, 720}, {"480p", 854, 480}, {"360p", 640, 360}, {"240p", 426, 240},
		}},
		{"480p 4:3", infoWithDisplay(640, 480, true), []rd{
			{"480p", 640, 480}, {"360p", 480, 360}, {"240p", 320, 240},
		}},
		{"360p", infoWithDisplay(640, 360, true), []rd{{"360p", 640, 360}, {"240p", 426, 240}}},
		{"240p exact", infoWithDisplay(426, 240, true), []rd{{"240p", 426, 240}}},
		{"239 is below every rung: own height rounded down to even", infoWithDisplay(426, 239, true), []rd{{"238p", 424, 238}}},
		{"144p source keeps its height", infoWithDisplay(256, 144, true), []rd{{"144p", 256, 144}}},
		{"odd 145 height rounds down", infoWithDisplay(257, 145, true), []rd{{"144p", 256, 144}}},
		{"odd width, tiny", infoWithDisplay(161, 121, true), []rd{{"120p", 160, 120}}},
		{"very small", infoWithDisplay(16, 16, true), []rd{{"16p", 16, 16}}},
		{"1px short of even minimum still yields a rung", infoWithDisplay(3, 3, true), []rd{{"2p", 2, 2}}},
		{"cinematic 2.39:1 1920 wide", infoWithDisplay(1920, 804, true), []rd{
			{"720p", 1720, 720}, {"480p", 1146, 480}, {"360p", 860, 360}, {"240p", 574, 240},
		}},
		{"portrait 1080x1920 (display height 1920)", infoWithDisplay(1080, 1920, true), []rd{
			{"1080p", 608, 1080}, {"720p", 406, 720}, {"480p", 270, 480}, {"360p", 202, 360}, {"240p", 136, 240},
		}},
		{"portrait 720x1280 (still 1280 tall)", infoWithDisplay(720, 1280, true), []rd{
			{"1080p", 608, 1080}, {"720p", 406, 720}, {"480p", 270, 480}, {"360p", 202, 360}, {"240p", 136, 240},
		}},
		{"portrait 2160x3840", infoWithDisplay(2160, 3840, true), []rd{
			{"1080p", 608, 1080}, {"720p", 406, 720}, {"480p", 270, 480}, {"360p", 202, 360}, {"240p", 136, 240},
		}},
		{"square 1080", infoWithDisplay(1080, 1080, true), []rd{
			{"1080p", 1080, 1080}, {"720p", 720, 720}, {"480p", 480, 480}, {"360p", 360, 360}, {"240p", 240, 240},
		}},
		{"odd display width never widens", infoWithDisplay(1919, 1080, true), []rd{
			{"1080p", 1918, 1080}, {"720p", 1280, 720}, {"480p", 852, 480}, {"360p", 640, 360}, {"240p", 426, 240},
		}},
		{"no audio", infoWithDisplay(1280, 720, false), []rd{
			{"720p", 1280, 720}, {"480p", 854, 480}, {"360p", 640, 360}, {"240p", 426, 240},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Ladder(c.info)
			if len(got) != len(c.want) {
				t.Fatalf("got %d renditions %v, want %v", len(got), got, c.want)
			}
			for i, w := range c.want {
				g := got[i]
				if g.Name != w.name || g.Width != w.w || g.Height != w.h {
					t.Errorf("rung %d: got %s %dx%d, want %s %dx%d", i, g.Name, g.Width, g.Height, w.name, w.w, w.h)
				}
				if g.Width%2 != 0 || g.Height%2 != 0 || g.Width < 2 || g.Height < 2 {
					t.Errorf("rung %d: %dx%d is not an even size", i, g.Width, g.Height)
				}
				if g.CRF != 23 || g.BufsizeKbps != 2*g.MaxrateKbps || g.MaxrateKbps <= 0 {
					t.Errorf("rung %d: rate control %+v", i, g)
				}
				wantAudio := 0
				if c.info.Audio != nil {
					wantAudio = 96
				}
				if g.AudioKbps != wantAudio {
					t.Errorf("rung %d: audio %d, want %d", i, g.AudioKbps, wantAudio)
				}
			}
		})
	}
}

func TestLadderRateCaps(t *testing.T) {
	want := map[string]int{"1080p": 4500, "720p": 2500, "480p": 1200, "360p": 700, "240p": 350}
	for _, r := range Ladder(infoWithDisplay(3840, 2160, true)) {
		if r.MaxrateKbps != want[r.Name] {
			t.Errorf("%s: maxrate %d, want %d", r.Name, r.MaxrateKbps, want[r.Name])
		}
	}
	// Below the smallest rung the smallest rung's caps apply.
	r := Ladder(infoWithDisplay(256, 144, true))[0]
	if r.MaxrateKbps != 350 || r.BufsizeKbps != 700 {
		t.Errorf("144p caps: %+v", r)
	}
}

// Rotation changes the ladder: a 1920x1080 stored frame with a 90 degree display matrix is a
// portrait video 1080 wide and 1920 tall, so its rungs are cut by the 1920 height.
func TestLadderUsesDisplayHeightAfterRotation(t *testing.T) {
	info, err := ParseProbe(probeFixture(mp4Format, "5",
		vstream(0, "h264", 1920, 1080, `,"side_data_list":[{"side_data_type":"Display Matrix","rotation":-90}]`)))
	if err != nil {
		t.Fatal(err)
	}
	got := Ladder(info)
	if len(got) != 5 || got[0].Name != "1080p" || got[0].Width != 608 || got[0].Height != 1080 {
		t.Fatalf("rotated 1920x1080: %+v", got)
	}

	// A stored 1080x1920 frame rotated by 90 is a 1920x1080 landscape picture.
	info, err = ParseProbe(probeFixture(mp4Format, "5",
		vstream(0, "h264", 1080, 1920, `,"side_data_list":[{"side_data_type":"Display Matrix","rotation":90}]`)))
	if err != nil {
		t.Fatal(err)
	}
	got = Ladder(info)
	if len(got) != 5 || got[0].Width != 1920 || got[0].Height != 1080 {
		t.Fatalf("rotated 1080x1920: %+v", got)
	}

	// A stored 640x360 frame rotated by 90 is 360 wide and 640 tall: 480p and below.
	info, err = ParseProbe(probeFixture(mp4Format, "5",
		vstream(0, "h264", 640, 360, `,"tags":{"rotate":"90"}`)))
	if err != nil {
		t.Fatal(err)
	}
	got = Ladder(info)
	if len(got) != 3 || got[0].Name != "480p" {
		t.Fatalf("rotated 640x360: %+v", got)
	}
}

// Resolution and bitrate are decided separately: the ladder never looks at the source's bitrate,
// so Info has no bitrate field at all. This test pins that every rung of a resolution is present.
func TestLadderIgnoresSourceBitrate(t *testing.T) {
	a := Ladder(infoWithDisplay(1920, 1080, true))
	if len(a) != 5 {
		t.Fatalf("1080p source must get all five rungs, got %d", len(a))
	}
}

func TestLadderNoVideo(t *testing.T) {
	if got := Ladder(Info{}); got != nil {
		t.Fatalf("got %v", got)
	}
	if got := Ladder(Info{Video: &VideoStream{}}); got != nil {
		t.Fatalf("got %v", got)
	}
}

// Invariants over a sweep of sizes: strictly descending, never taller than the source, always
// at least one rendition, always even, width within 1 percent of the aspect ratio (2 px minimum).
func TestLadderInvariants(t *testing.T) {
	for h := 16; h <= 4320; h += 7 {
		for _, aspect := range []float64{1, 4.0 / 3, 16.0 / 9, 9.0 / 16, 21.0 / 9, 3.0 / 4} {
			w := int(float64(h) * aspect)
			if w < 16 {
				continue
			}
			t.Run(fmt.Sprintf("%dx%d", w, h), func(t *testing.T) {
				got := Ladder(infoWithDisplay(w, h, true))
				if len(got) == 0 {
					t.Fatal("no renditions")
				}
				prev := 1 << 30
				for _, r := range got {
					if r.Height >= prev {
						t.Fatalf("not descending: %+v", got)
					}
					prev = r.Height
					if r.Height > h || r.Width > w {
						t.Fatalf("upscaled %dx%d to %+v", w, h, r)
					}
					if r.Width%2 != 0 || r.Height%2 != 0 {
						t.Fatalf("odd size %+v", r)
					}
					exact := float64(r.Height) * float64(w) / float64(h)
					if d := float64(r.Width) - exact; d > 2 || d < -2 {
						t.Fatalf("%+v: width %d too far from %.1f", r, r.Width, exact)
					}
				}
			})
		}
	}
}
