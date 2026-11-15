package media

import (
	"strings"
	"testing"
)

func testLogo(corner string, opacity int) *LogoSpec {
	return &LogoSpec{Path: "/work/job/logo.rgba", Width: 200, Height: 100, Corner: corner, OpacityPercent: opacity}
}

func TestLogoPlacement(t *testing.T) {
	for name, c := range map[string]struct {
		logo *LogoSpec
		w, h int
		want LogoPlacement
	}{
		// 15 percent of 1280 is 192; a 2:1 logo is 96 high; the margin is 2 percent of the width (26).
		"top left 720p":     {testLogo(CornerTopLeft, 100), 1280, 720, LogoPlacement{192, 96, 26, 26}},
		"top right 720p":    {testLogo(CornerTopRight, 100), 1280, 720, LogoPlacement{192, 96, 1280 - 192 - 26, 26}},
		"bottom left 720p":  {testLogo(CornerBottomLeft, 100), 1280, 720, LogoPlacement{192, 96, 26, 720 - 96 - 26}},
		"bottom right 720p": {testLogo(CornerBottomRight, 100), 1280, 720, LogoPlacement{192, 96, 1280 - 192 - 26, 720 - 96 - 26}},
		// A tall logo is shrunk to a quarter of the height (60 of 240), keeping its shape.
		"tall logo": {&LogoSpec{Path: "/x", Width: 100, Height: 400, Corner: CornerTopLeft, OpacityPercent: 100}, 426, 240, LogoPlacement{14, 60, 8, 8}},
		// Portrait picture: the share is of the width.
		"portrait":  {testLogo(CornerBottomRight, 100), 136, 240, LogoPlacement{20, 10, 136 - 20 - 2, 240 - 10 - 2}},
		"tiny tile": {testLogo(CornerTopLeft, 100), 160, 90, LogoPlacement{24, 12, 2, 2}},
	} {
		t.Run(name, func(t *testing.T) {
			got := c.logo.Place(c.w, c.h)
			if got != c.want {
				t.Fatalf("Place(%d, %d) = %+v, want %+v", c.w, c.h, got, c.want)
			}
			if got.X < 0 || got.Y < 0 || got.X+got.Width > c.w || got.Y+got.Height > c.h || got.Width%2 != 0 || got.Height%2 != 0 {
				t.Errorf("the logo leaves the picture or has an odd side: %+v", got)
			}
		})
	}
}

func TestTranscodeArgsWithALogo(t *testing.T) {
	spec := testSpec()
	spec.Logo = testLogo(CornerTopRight, 55)
	args, err := TranscodeArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	// The logo is a second input of raw RGBA pixels; the whitelist is repeated for it.
	inputs := argValues(args, "-i")
	if len(inputs) != 2 || inputs[1] != "file:/work/job/logo.rgba" {
		t.Fatalf("inputs = %v", inputs)
	}
	if got := argValues(args, "-pixel_format"); len(got) != 1 || got[0] != "rgba" {
		t.Errorf("-pixel_format = %v", got)
	}
	if got := argValues(args, "-f"); got[0] != "rawvideo" {
		t.Errorf("-f = %v: the logo input is not rawvideo", got)
	}
	if got := argValues(args, "-protocol_whitelist"); len(got) != 2 || got[1] != "file" {
		t.Errorf("-protocol_whitelist = %v, want one per input", got)
	}
	fg := argValues(args, "-filter_complex")[0]
	for _, want := range []string{
		"[1:v]format=rgba,colorchannelmixer=aa=0.55,split=4[l0][l1][l2][l3]",
		"[s0]scale=1280:720:flags=bicubic,setsar=1[b0];[l0]scale=192:96:flags=bicubic[g0];[b0][g0]overlay=x=1062:y=26:format=yuv420[o0];[o0]format=yuv420p[v0]",
		"[s3]scale=426:240:flags=bicubic,setsar=1[b3];[l3]scale=64:32:flags=bicubic[g3];[b3][g3]overlay=x=354:y=8:format=yuv420[o3];[o3]format=yuv420p[v3]",
	} {
		if !strings.Contains(fg, want) {
			t.Errorf("filter graph lacks %q:\n%s", want, fg)
		}
	}
	// The logo is drawn on the scaled picture, never before the split, so it is the same share of
	// every rendition.
	if strings.Index(fg, "overlay") < strings.Index(fg, "split=4[s0]") {
		t.Error("overlay comes before the split")
	}
	// Opacity 100 adds no mixer.
	spec.Logo = testLogo(CornerTopLeft, 100)
	args, _ = TranscodeArgs(spec)
	if fg := argValues(args, "-filter_complex")[0]; strings.Contains(fg, "colorchannelmixer") || !strings.Contains(fg, "[1:v]format=rgba,split=4") {
		t.Errorf("opacity 100 graph:\n%s", fg)
	}
}

func TestTranscodeArgsWithoutALogoAreUnchanged(t *testing.T) {
	args, err := TranscodeArgs(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	if got := argValues(args, "-i"); len(got) != 1 {
		t.Errorf("inputs = %v", got)
	}
	if fg := argValues(args, "-filter_complex")[0]; strings.Contains(fg, "overlay") || strings.Contains(fg, "[1:v]") {
		t.Errorf("a logo stage is in the graph:\n%s", fg)
	}
}

func TestThumbnailsGetTheLogoToo(t *testing.T) {
	spec := testSpec()
	plan, ok := PlanThumbnails(spec.Info.Duration, spec.Renditions[0])
	if !ok {
		t.Fatal("no plan")
	}
	spec.Thumbs = &ThumbnailSpec{Dir: "/work/job/thumbs", Plan: plan}
	spec.Logo = testLogo(CornerBottomRight, 80)
	args, err := TranscodeArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	fg := argValues(args, "-filter_complex")[0]
	for _, want := range []string{
		"split=6[s0][s1][s2][s3][s4][s5]",
		"[1:v]format=rgba,colorchannelmixer=aa=0.80,split=6[l0][l1][l2][l3][l4][l5]",
		// The poster (640 wide) and the tiles (160 wide) each get a logo scaled to their own width.
		"[l4]scale=96:48:flags=bicubic[g4];[pb][g4]overlay=x=532:y=300:format=yuv420[pc];[pc]format=yuvj420p[poster]",
		"[l5]scale=24:12:flags=bicubic[g5];[sb][g5]overlay=x=134:y=76:format=yuv420[sc];[sc]format=yuvj420p,tile=",
	} {
		if !strings.Contains(fg, want) {
			t.Errorf("filter graph lacks %q:\n%s", want, fg)
		}
	}
}

func TestLogoSpecIsValidated(t *testing.T) {
	for name, mut := range map[string]func(*LogoSpec){
		"relative path": func(l *LogoSpec) { l.Path = "logo.rgba" },
		"NUL in path":   func(l *LogoSpec) { l.Path = "/work/lo\x00go" },
		"width zero":    func(l *LogoSpec) { l.Width = 0 },
		"too wide":      func(l *LogoSpec) { l.Width = 1025 },
		"too short":     func(l *LogoSpec) { l.Height = 15 },
		"opacity 9":     func(l *LogoSpec) { l.OpacityPercent = 9 },
		"opacity 101":   func(l *LogoSpec) { l.OpacityPercent = 101 },
		"corner":        func(l *LogoSpec) { l.Corner = "middle" },
	} {
		spec := testSpec()
		spec.Logo = testLogo(CornerTopLeft, 50)
		mut(spec.Logo)
		if _, err := TranscodeArgs(spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
