package media

import (
	"strings"
	"testing"
)

func colorStream(transfer, primaries, space string) string {
	return vstream(0, "hevc", 1920, 1080, `,"color_transfer":"`+transfer+`","color_primaries":"`+primaries+`","color_space":"`+space+`"`)
}

func TestProbeClassifiesColour(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		transfer, prim, space   string
		hdr, wide               bool
		filterHas, filterHasNot string
		wantEmptyFilter         bool
	}{
		{"PQ", "smpte2084", "bt2020", "bt2020nc", true, false, "tonemap=tonemap=hable", "pin=", false},
		{"HLG", "arib-std-b67", "bt2020", "bt2020nc", true, false, "zscale=t=linear:npl=100,format=gbrpf32le", "min=", false},
		{"PQ without primaries or matrix", "smpte2084", "unknown", "", true, false, ":pin=bt2020:min=bt2020nc,format=gbrpf32le", "", false},
		{"wide-gamut SDR", "bt709", "bt2020", "bt2020nc", false, true, "zscale=p=bt709:t=bt709:m=bt709:r=tv,format=yuv420p", "tonemap", false},
		{"BT.2020 SDR transfer", "bt2020-10", "bt2020", "bt2020nc", false, true, "zscale=p=bt709", "tonemap", false},
		{"plain SDR", "bt709", "bt709", "bt709", false, false, "", "", true},
		{"untagged", "", "", "", false, false, "", "", true},
		{"BT.601", "smpte170m", "smpte170m", "smpte170m", false, false, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseProbe(probeFixture(mp4Format, "5", colorStream(tc.transfer, tc.prim, tc.space)))
			if err != nil {
				t.Fatal(err)
			}
			v := info.Video
			if v.ColorTransfer != tc.transfer || v.ColorPrimaries != tc.prim || v.ColorSpace != tc.space || v.PixelFormat != "yuv420p" {
				t.Errorf("colour fields: %+v", v)
			}
			if v.HDR() != tc.hdr || v.WideGamut() != tc.wide {
				t.Errorf("HDR %v, wide gamut %v; want %v, %v", v.HDR(), v.WideGamut(), tc.hdr, tc.wide)
			}
			f := v.ColorFilter()
			if (f == "") != tc.wantEmptyFilter || !strings.Contains(f, tc.filterHas) || (tc.filterHasNot != "" && strings.Contains(f, tc.filterHasNot)) {
				t.Errorf("filter %q", f)
			}
		})
	}
}

// The chain the owner asked for, character for character.
func TestToneMapFilterString(t *testing.T) {
	v := &VideoStream{ColorTransfer: TransferPQ, ColorPrimaries: "bt2020", ColorSpace: "bt2020nc"}
	const want = "zscale=t=linear:npl=100,format=gbrpf32le,zscale=p=bt709,tonemap=tonemap=hable:desat=0,zscale=t=bt709:m=bt709:r=tv,format=yuv420p"
	if got := v.ColorFilter(); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func hdrSpec(transfer string) TranscodeSpec {
	spec := testSpec()
	spec.Info.Video.ColorTransfer, spec.Info.Video.ColorPrimaries, spec.Info.Video.ColorSpace = transfer, "bt2020", "bt2020nc"
	return spec
}

func TestTranscodeArgsToneMapBeforeTheSplit(t *testing.T) {
	for _, enc := range append([]Encoder{""}, Encoders()...) {
		spec := hdrSpec(TransferHLG)
		spec.Encoder = enc
		plan, ok := PlanThumbnails(spec.Info.Duration, spec.Renditions[0])
		if !ok {
			t.Fatal("no thumbnail plan")
		}
		spec.Thumbs = &ThumbnailSpec{Dir: "/work/job/thumbs", Plan: plan}
		args, err := TranscodeArgs(spec)
		if err != nil {
			t.Fatal(err)
		}
		fg := argValues(args, "-filter_complex")[0]
		chain := spec.Info.Video.ColorFilter()
		// One conversion, ahead of the split: renditions, poster and sprite all read the converted frames,
		// and a hardware encoder's hwupload (in the rendition branch) comes after it.
		if strings.Count(fg, "tonemap=tonemap=") != 1 || !strings.HasPrefix(fg, "[0:0]fps=30,"+chain+",split=") {
			t.Errorf("%q: %s", enc, fg)
		}
		if i, j := strings.Index(fg, "tonemap="), strings.Index(fg, "hwupload"); j >= 0 && j < i {
			t.Errorf("%q: hwupload before the tone map: %s", enc, fg)
		}
	}
}

func TestTranscodeArgsSDRUnchanged(t *testing.T) {
	args, err := TranscodeArgs(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	if fg := argValues(args, "-filter_complex")[0]; strings.Contains(fg, "zscale") || !strings.HasPrefix(fg, "[0:0]fps=30,split=4") {
		t.Errorf("an SDR source must not be converted: %s", fg)
	}
	wide := hdrSpec("bt709")
	args, err = TranscodeArgs(wide)
	if err != nil {
		t.Fatal(err)
	}
	if fg := argValues(args, "-filter_complex")[0]; strings.Contains(fg, "tonemap") || !strings.Contains(fg, "fps=30,zscale=p=bt709:t=bt709:m=bt709:r=tv,format=yuv420p,split=") {
		t.Errorf("wide-gamut SDR is converted without tone mapping: %s", fg)
	}
}
