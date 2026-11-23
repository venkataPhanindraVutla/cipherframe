package media

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
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
		{EncoderVideoToolbox, "-c:v h264_videotoolbox -profile:v high -q:v 54 -realtime 0 -allow_sw 0 -maxrate 2500k -bufsize 5000k -g 60 " + keys},
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
	if _, err := videoArgs(EncoderNVENC, "hevc", rung720(), X264Preset, OutputFrameRate(30)); err == nil {
		t.Error("hevc is M10-3 and must not be accepted yet")
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
		got, _ := os.ReadFile(argsFile)
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
