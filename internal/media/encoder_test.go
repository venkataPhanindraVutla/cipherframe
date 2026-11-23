package media

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rung720 is the ladder's 720p rung: 2500 kbps cap, CRF 23, 30 fps so a 60-frame GOP.
func rung720() Rendition {
	return Rendition{Name: "720p", Width: 1280, Height: 720, CRF: CRF, MaxrateKbps: 2500, BufsizeKbps: 5000, AudioKbps: 96}
}

func TestVideoArgsGolden(t *testing.T) {
	const keys = "-force_key_frames expr:gte(t,n_forced*2) -fps_mode cfr"
	for _, tc := range []struct {
		enc  Encoder
		want string
	}{
		{EncoderSoftware, "-c:v libx264 -profile:v high -preset medium -crf 23 -maxrate 2500k -bufsize 5000k -g 60 -keyint_min 60 -sc_threshold 0 -x264-params open-gop=0 -forced-idr 1 " + keys},
		{EncoderNVENC, "-c:v h264_nvenc -profile:v high -preset p5 -rc vbr -cq 23 -b:v 0 -maxrate 2500k -bufsize 5000k -no-scenecut 1 -forced-idr 1 -strict_gop 1 -g 60 " + keys},
		{EncoderVAAPI, "-c:v h264_vaapi -profile:v high -rc_mode QVBR -global_quality 23 -b:v 2500k -maxrate 2500k -bufsize 5000k -idr_interval 0 -g 60 " + keys},
		{EncoderQSV, "-c:v h264_qsv -profile:v high -preset medium -global_quality 23 -look_ahead 0 -maxrate 2500k -bufsize 5000k -adaptive_i 0 -adaptive_b 0 -idr_interval 0 -forced_idr 1 -g 60 " + keys},
		{EncoderVideoToolbox, "-c:v h264_videotoolbox -profile:v high -q:v 60 -realtime 0 -allow_sw 0 -maxrate 2500k -bufsize 5000k -g 60 " + keys},
	} {
		got, err := videoArgs(tc.enc, CodecH264, rung720(), X264Preset, OutputFrameRate(30))
		if err != nil {
			t.Fatalf("%s: %v", tc.enc, err)
		}
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("%s:\n got  %s\n want %s", tc.enc, s, tc.want)
		}
	}
}

// rung720For is the 720p rung of codec c as LadderFor makes it.
func rung720For(t *testing.T, c Codec) Rendition {
	t.Helper()
	for _, r := range LadderFor(c, testSpec().Info, nil) {
		if r.Height == 720 {
			return r
		}
	}
	t.Fatal("no 720p rung")
	return Rendition{}
}

// The extra codecs: libx265 and SVT-AV1 in software, the hardware encoders of ADR 0064 beside them. HEVC
// is tagged hvc1; keyframes are placed exactly as for H.264. 720p at 30 fps: HEVC cap 1500 kbps and
// CRF 26, AV1 cap 1500 kbps and CRF 35.
func TestVideoArgsGoldenExtraCodecs(t *testing.T) {
	const keys = "-force_key_frames expr:gte(t,n_forced*2) -fps_mode cfr"
	for _, tc := range []struct {
		enc  Encoder
		c    Codec
		want string
	}{
		{EncoderSoftware, CodecHEVC, "-c:v libx265 -tag:v hvc1 -preset medium -crf 26 -maxrate 1500k -bufsize 3000k -g 60 -keyint_min 60 -x265-params scenecut=0:open-gop=0 -forced-idr 1 " + keys},
		{EncoderSoftware, CodecAV1, "-c:v libsvtav1 -preset 8 -crf 35 -maxrate 1500k -bufsize 3000k -g 60 -svtav1-params scd=0:irefresh-type=2 -forced-idr 1 " + keys},
		{EncoderNVENC, CodecHEVC, "-c:v hevc_nvenc -tag:v hvc1 -profile:v main -preset p5 -rc vbr -cq 26 -b:v 0 -maxrate 1500k -bufsize 3000k -no-scenecut 1 -forced-idr 1 -strict_gop 1 -g 60 " + keys},
		{EncoderNVENC, CodecAV1, "-c:v av1_nvenc -preset p5 -rc vbr -cq 35 -b:v 0 -maxrate 1500k -bufsize 3000k -no-scenecut 1 -forced-idr 1 -strict_gop 1 -g 60 " + keys},
		{EncoderVAAPI, CodecHEVC, "-c:v hevc_vaapi -tag:v hvc1 -profile:v main -rc_mode QVBR -global_quality 26 -b:v 1500k -maxrate 1500k -bufsize 3000k -idr_interval 0 -g 60 " + keys},
		{EncoderVAAPI, CodecAV1, "-c:v av1_vaapi -rc_mode QVBR -global_quality 35 -b:v 1500k -maxrate 1500k -bufsize 3000k -idr_interval 0 -g 60 " + keys},
		{EncoderQSV, CodecHEVC, "-c:v hevc_qsv -tag:v hvc1 -profile:v main -preset medium -global_quality 26 -look_ahead 0 -maxrate 1500k -bufsize 3000k -adaptive_i 0 -adaptive_b 0 -idr_interval 0 -forced_idr 1 -g 60 " + keys},
		{EncoderQSV, CodecAV1, "-c:v av1_qsv -preset medium -global_quality 35 -look_ahead 0 -maxrate 1500k -bufsize 3000k -adaptive_i 0 -adaptive_b 0 -idr_interval 0 -forced_idr 1 -g 60 " + keys},
		{EncoderVideoToolbox, CodecHEVC, "-c:v hevc_videotoolbox -tag:v hvc1 -profile:v main -q:v 54 -realtime 0 -allow_sw 0 -maxrate 1500k -bufsize 3000k -g 60 " + keys},
		// VideoToolbox has no AV1 encoder: SVT-AV1 makes it, with the software arguments.
		{EncoderVideoToolbox, CodecAV1, "-c:v libsvtav1 -preset 8 -crf 35 -maxrate 1500k -bufsize 3000k -g 60 -svtav1-params scd=0:irefresh-type=2 -forced-idr 1 " + keys},
	} {
		got, err := videoArgs(tc.enc, tc.c, rung720For(t, tc.c), X264Preset, OutputFrameRate(30))
		if err != nil {
			t.Fatalf("%s %s: %v", tc.enc, tc.c, err)
		}
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("%s %s:\n got  %s\n want %s", tc.enc, tc.c, s, tc.want)
		}
	}
}

// Every extra codec has the full ladder with the rungs' own caps, lower than H.264's, and names that
// sit beside the H.264 ones.
func TestLadderForExtraCodecs(t *testing.T) {
	info := testSpec().Info
	base := Ladder(info, nil)
	for _, c := range ExtraCodecs() {
		got := LadderFor(c, info, nil)
		if len(got) != len(base) {
			t.Fatalf("%s: %d renditions, H.264 has %d", c, len(got), len(base))
		}
		for i, r := range got {
			if r.Name != base[i].Name+"_"+string(c) || r.Width != base[i].Width || r.Height != base[i].Height {
				t.Errorf("%s %s: %+v against %+v", c, r.Name, r, base[i])
			}
			if r.MaxrateKbps >= base[i].MaxrateKbps || r.BufsizeKbps != 2*r.MaxrateKbps || r.CRF != c.crf() {
				t.Errorf("%s %s: caps %d/%d crf %d", c, r.Name, r.MaxrateKbps, r.BufsizeKbps, r.CRF)
			}
		}
	}
	for i, r := range LadderFor(CodecH264, info, nil) {
		if r != base[i] {
			t.Errorf("LadderFor(h264) differs from Ladder: %+v %+v", r, base[i])
		}
	}
}

// Every encoder gets the rung's own caps and the same forced keyframe expression, so the renditions
// of one encoder cut at the same frames (pitfall 4).
func TestVideoArgsEveryRung(t *testing.T) {
	info := testSpec().Info
	for _, e := range Encoders() {
		for _, r := range Ladder(info, nil) {
			a, err := videoArgs(e, CodecH264, r, X264Preset, OutputFrameRate(30))
			if err != nil {
				t.Fatal(err)
			}
			if got := argValues(a, "-maxrate"); len(got) != 1 || got[0] != strconv.Itoa(r.MaxrateKbps)+"k" {
				t.Errorf("%s %s: -maxrate %v", e, r.Name, got)
			}
			if got := argValues(a, "-bufsize"); len(got) != 1 || got[0] != strconv.Itoa(r.BufsizeKbps)+"k" {
				t.Errorf("%s %s: -bufsize %v", e, r.Name, got)
			}
			if got := argValues(a, "-force_key_frames"); len(got) != 1 || got[0] != "expr:gte(t,n_forced*2)" {
				t.Errorf("%s %s: -force_key_frames %v", e, r.Name, got)
			}
			if got := argValues(a, "-g"); len(got) != 1 || got[0] != "60" {
				t.Errorf("%s %s: -g %v", e, r.Name, got)
			}
		}
	}
}

func TestVideoArgsRejects(t *testing.T) {
	if _, err := videoArgs("cuda", CodecH264, rung720(), X264Preset, OutputFrameRate(30)); err == nil {
		t.Error("an unknown encoder was accepted")
	}
	if _, err := videoArgs(EncoderNVENC, "vp9", rung720(), X264Preset, OutputFrameRate(30)); err == nil {
		t.Error("an unknown codec was accepted")
	}
}

func TestTranscodeArgsFilterAndDevice(t *testing.T) {
	for _, tc := range []struct {
		enc    Encoder
		tail   string
		device []string
	}{
		{"", "setsar=1,format=yuv420p[v0]", nil},
		{EncoderSoftware, "setsar=1,format=yuv420p[v0]", nil},
		{EncoderNVENC, "setsar=1,format=yuv420p[v0]", nil},
		{EncoderVideoToolbox, "setsar=1,format=yuv420p[v0]", nil},
		{EncoderVAAPI, "setsar=1,format=nv12,hwupload[v0]", []string{"-init_hw_device", "vaapi=hw:/dev/dri/renderD129", "-filter_hw_device", "hw"}},
		{
			EncoderQSV, "setsar=1,format=nv12,hwupload=extra_hw_frames=64[v0]",
			[]string{"-init_hw_device", "vaapi=va:/dev/dri/renderD129", "-init_hw_device", "qsv=hw@va", "-filter_hw_device", "hw"},
		},
	} {
		spec := testSpec()
		spec.Encoder, spec.HWDevice = tc.enc, "/dev/dri/renderD129"
		args, err := TranscodeArgs(spec)
		if err != nil {
			t.Fatal(err)
		}
		if fg := argValues(args, "-filter_complex")[0]; !strings.Contains(fg, tc.tail) {
			t.Errorf("%q: graph lacks %q:\n%s", tc.enc, tc.tail, fg)
		}
		i := slices.Index(args, "-i")
		if tc.device == nil {
			if slices.Contains(args, "-init_hw_device") {
				t.Errorf("%q: opens a hardware device", tc.enc)
			}
			continue
		}
		if i < len(tc.device) || !slices.Equal(args[i-len(tc.device):i], tc.device) {
			t.Errorf("%q: device options %v do not precede -i in %v", tc.enc, tc.device, args)
		}
	}
}

func TestTranscodeArgsRefusesUnsafeDevice(t *testing.T) {
	for _, d := range []string{"-x", "/dev/dri/a,b", "/dev/dri/a:b", "/dev/dri/a=b", "/dev/a\x00"} {
		spec := testSpec()
		spec.Encoder, spec.HWDevice = EncoderVAAPI, d
		if _, err := TranscodeArgs(spec); err == nil {
			t.Errorf("device %q was accepted", d)
		}
	}
	spec := testSpec()
	spec.Encoder = "cuda"
	if _, err := TranscodeArgs(spec); err == nil {
		t.Error("an unknown encoder was accepted")
	}
}

func TestFFmpegNameExtraCodecs(t *testing.T) {
	for _, tc := range []struct {
		e    Encoder
		c    Codec
		want string
	}{
		{EncoderSoftware, CodecHEVC, "libx265"},
		{EncoderSoftware, CodecAV1, "libsvtav1"},
		{EncoderNVENC, CodecHEVC, "hevc_nvenc"},
		{EncoderNVENC, CodecAV1, "av1_nvenc"},
		{EncoderVAAPI, CodecHEVC, "hevc_vaapi"},
		{EncoderQSV, CodecAV1, "av1_qsv"},
		{EncoderVideoToolbox, CodecHEVC, "hevc_videotoolbox"},
		{EncoderVideoToolbox, CodecAV1, "libsvtav1"},
	} {
		if got := tc.e.FFmpegName(tc.c); got != tc.want {
			t.Errorf("%s %s: %q, want %q", tc.e, tc.c, got, tc.want)
		}
	}
}

// AV1 under VideoToolbox is made by SVT-AV1 in software, so its graph ends in system-memory yuv420p
// and opens no device, whatever else the worker is set to.
func TestTranscodeArgsExtraCodec(t *testing.T) {
	spec := testSpec()
	spec.Encoder, spec.Codec = EncoderVAAPI, CodecHEVC
	spec.Renditions = LadderFor(CodecHEVC, spec.Info, nil)
	args, err := TranscodeArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "hevc_vaapi") || !strings.Contains(argValues(args, "-filter_complex")[0], "hwupload") {
		t.Errorf("hevc under vaapi: %v", args)
	}
	for _, r := range spec.Renditions {
		if !slices.Contains(args, "file:"+filepath.Join(spec.OutDir, r.Name, PlaylistFile)) {
			t.Errorf("no playlist for %s", r.Name)
		}
	}
	spec.Encoder, spec.Codec = EncoderVideoToolbox, CodecAV1
	spec.Renditions = LadderFor(CodecAV1, spec.Info, nil)
	if args, err = TranscodeArgs(spec); err != nil || !slices.Contains(args, "libsvtav1") || slices.Contains(args, "-init_hw_device") {
		t.Errorf("av1 under videotoolbox: %v %v", args, err)
	}
	spec.Codec = "vp9"
	if _, err = TranscodeArgs(spec); err == nil {
		t.Error("an unknown codec was accepted")
	}
	// TSOffset gives every rendition's output the same shift and nothing else carries it.
	spec = testSpec()
	if args, _ = TranscodeArgs(spec); slices.Contains(args, "-output_ts_offset") {
		t.Error("an offset without TSOffset")
	}
	spec.TSOffset = 66667 * time.Microsecond
	args, err = TranscodeArgs(spec)
	if err != nil || len(argValues(args, "-output_ts_offset")) != len(spec.Renditions) || argValues(args, "-output_ts_offset")[0] != "0.066667" {
		t.Errorf("offsets %v, %v", argValues(args, "-output_ts_offset"), err)
	}
}

func TestEncodableCodecs(t *testing.T) {
	listing := func(names ...string) string {
		out := " Encoders:\n V..... = Video\n ------\n"
		for _, n := range names {
			out += " V....D " + n + "   some encoder\n"
		}
		return out
	}
	for _, tc := range []struct {
		name string
		enc  Encoder
		have []string
		want []Codec
	}{
		{"x264 only", EncoderSoftware, []string{"libx264", "aac"}, nil},
		{"both software", EncoderSoftware, []string{"libx264", "libx265", "libsvtav1"}, []Codec{CodecHEVC, CodecAV1}},
		{"hevc only", EncoderSoftware, []string{"libx265"}, []Codec{CodecHEVC}},
		{"hardware only", EncoderNVENC, []string{"libx264", "hevc_nvenc", "av1_nvenc"}, []Codec{CodecHEVC, CodecAV1}},
		{"hardware encoder not selected", EncoderSoftware, []string{"libx264", "hevc_nvenc"}, nil},
	} {
		bin := filepath.Join(t.TempDir(), "ffmpeg")
		script := "#!/bin/sh\ncat <<'EOF'\n" + listing(tc.have...) + "EOF\n"
		if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
			t.Fatal(err)
		}
		got, err := (Tools{FFmpeg: bin}).EncodableCodecs(t.Context(), tc.enc)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v %v, want %v", tc.name, got, err, tc.want)
		}
	}
}

func TestFFmpegName(t *testing.T) {
	for e, want := range map[Encoder]string{
		"": "libx264", EncoderSoftware: "libx264", EncoderNVENC: "h264_nvenc", EncoderVAAPI: "h264_vaapi",
		EncoderQSV: "h264_qsv", EncoderVideoToolbox: "h264_videotoolbox",
	} {
		if got := e.FFmpegName(CodecH264); got != want {
			t.Errorf("%q: %q, want %q", e, got, want)
		}
	}
}

// probeFFmpeg is an "ffmpeg" that records its arguments and succeeds, or fails with a message that
// names the device.
func probeFFmpeg(t *testing.T, fail bool) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	bin, argsFile = filepath.Join(dir, "ffmpeg"), filepath.Join(dir, "args")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\n"
	if fail {
		script += "echo 'Cannot open /dev/dri/renderD128' >&2\nexit 1\n"
	}
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestProbeEncoder(t *testing.T) {
	for _, e := range Encoders() {
		bin, argsFile := probeFFmpeg(t, false)
		if err := (Tools{FFmpeg: bin}).ProbeEncoder(t.Context(), e, ""); err != nil {
			t.Fatalf("%s: %v", e, err)
		}
		got, _ := os.ReadFile(argsFile) //nolint:gosec // test reads its own temp file
		args := strings.Fields(string(got))
		for _, want := range []string{e.FFmpegName(CodecH264), "file:/dev/zero", "null"} {
			if !slices.Contains(args, want) {
				t.Errorf("%s: probe arguments lack %q: %s", e, want, got)
			}
		}
		if e == EncoderVAAPI && !slices.Contains(args, "vaapi=hw:"+DefaultHWDevice) {
			t.Errorf("vaapi probe does not open the default device: %s", got)
		}
	}
	bin, _ := probeFFmpeg(t, true)
	if err := (Tools{FFmpeg: bin}).ProbeEncoder(t.Context(), EncoderNVENC, ""); err == nil {
		t.Error("a failing test encode was reported as success")
	}
	if err := (Tools{FFmpeg: bin}).ProbeEncoder(t.Context(), "cuda", ""); err == nil {
		t.Error("an unknown encoder was probed")
	}
}
