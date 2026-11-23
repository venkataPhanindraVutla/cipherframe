package media

import (
	"cmp"
	"context"
	"fmt"
	"strconv"
)

// Encoder selects what encodes the video of every rendition (ADR 0063). Decoding, scaling, masking
// and the logo stay in software for every encoder; only the encode itself moves to hardware.
type Encoder string

// The encoders CIPHERFRAME_WORKER_ENCODER accepts.
const (
	EncoderSoftware     Encoder = "software" // libx264, the default (ADR 0024)
	EncoderNVENC        Encoder = "nvenc"    // NVIDIA
	EncoderVAAPI        Encoder = "vaapi"    // Intel and AMD on Linux
	EncoderQSV          Encoder = "qsv"      // Intel Quick Sync
	EncoderVideoToolbox Encoder = "videotoolbox"
)

// Codec is the video codec of a rendition (ADR 0064). H.264 is always made; HEVC and AV1 are the
// optional extras a tenant turns on.
type Codec string

// The video codecs. The names of CodecHEVC and CodecAV1 are the values of the tenant setting
// extra_codecs.
const (
	CodecH264 Codec = "h264"
	CodecHEVC Codec = "hevc"
	CodecAV1  Codec = "av1"
)

// ExtraCodecs returns the codecs a tenant can add to H.264, in the order they are made and listed.
func ExtraCodecs() []Codec { return []Codec{CodecHEVC, CodecAV1} }

// Valid reports whether c is H.264 or one of ExtraCodecs.
func (c Codec) Valid() bool { return c == CodecH264 || c == CodecHEVC || c == CodecAV1 }

// Extra reports whether c is one of ExtraCodecs.
func (c Codec) Extra() bool { return c == CodecHEVC || c == CodecAV1 }

// nameSuffix is what a codec adds to a rendition name: nothing for H.264 (its names never change),
// "_hevc" or "_av1" otherwise.
func (c Codec) nameSuffix() string {
	if c.Extra() {
		return "_" + string(c)
	}
	return ""
}

// crf is the codec's starting constant-quality value.
func (c Codec) crf() int {
	switch c {
	case CodecHEVC:
		return CRFHEVC
	case CodecAV1:
		return CRFAV1
	}
	return CRF
}

// SVTAV1Preset and X265Preset are the software presets of the extra codecs (ADR 0067). Unlike
// libx264's they are not operator settings.
const (
	SVTAV1Preset = "8"
	X265Preset   = "medium"
)

// DefaultHWDevice is the render node VAAPI and QSV use when CIPHERFRAME_WORKER_HW_DEVICE is unset.
const DefaultHWDevice = "/dev/dri/renderD128"

// Encoders returns every encoder, software first.
func Encoders() []Encoder {
	return []Encoder{EncoderSoftware, EncoderNVENC, EncoderVAAPI, EncoderQSV, EncoderVideoToolbox}
}

// Valid reports whether e is one of Encoders.
func (e Encoder) Valid() bool {
	switch e {
	case EncoderSoftware, EncoderNVENC, EncoderVAAPI, EncoderQSV, EncoderVideoToolbox:
		return true
	}
	return false
}

// Hardware reports whether e encodes on a device. The zero value is software.
func (e Encoder) Hardware() bool { return e != "" && e != EncoderSoftware }

// For returns the encoder that makes codec c when the worker is set to e. It is e, except that
// VideoToolbox has no AV1 encoder, so AV1 falls back to SVT-AV1 in software (ADR 0064).
func (e Encoder) For(c Codec) Encoder {
	if e == EncoderVideoToolbox && c == CodecAV1 {
		return EncoderSoftware
	}
	return e
}

// FFmpegName is the name FFmpeg gives the encoder of codec c under e, which is also what the
// manifest records: libx264, libx265 or libsvtav1 in software, "<codec>_<encoder>" on hardware.
func (e Encoder) FFmpegName(c Codec) string {
	e = e.For(c)
	if c == "" {
		c = CodecH264
	}
	if !e.Hardware() {
		switch c {
		case CodecHEVC:
			return "libx265"
		case CodecAV1:
			return "libsvtav1"
		}
		return "libx264"
	}
	return string(c) + "_" + string(e)
}

// deviceArgs are the global options that open the hardware device a filter graph uploads to. They
// come before the input. NVENC and VideoToolbox take system-memory frames and need none.
func (e Encoder) deviceArgs(device string) []string {
	switch e {
	case EncoderVAAPI:
		return []string{"-init_hw_device", "vaapi=hw:" + device, "-filter_hw_device", "hw"}
	case EncoderQSV:
		// QSV on Linux is derived from a VAAPI device on the same render node.
		return []string{"-init_hw_device", "vaapi=va:" + device, "-init_hw_device", "qsv=hw@va", "-filter_hw_device", "hw"}
	}
	return nil
}

// pixelFormat is the end of every rendition's filter chain, after the scale and the logo: the
// frame is handed to the encoder as 4:2:0. VAAPI and QSV encode from device memory, so the frame
// is converted to NV12 and uploaded; the other encoders read system memory.
func (e Encoder) pixelFormat() string {
	switch e {
	case EncoderVAAPI:
		return "format=nv12,hwupload"
	case EncoderQSV:
		return "format=nv12,hwupload=extra_hw_frames=64"
	}
	return "format=yuv420p"
}

// videoArgs maps an encoder, a codec and a rung to the FFmpeg arguments of that rendition's video
// stream. It is the only place that does. Every encoder and codec gets the same placement of
// keyframes (every KeyframeSeconds at forced timestamps, IDR, none added by scene detection) and the
// rung's maxrate and bufsize caps; the quality target is each encoder's own constant-quality mode,
// starting from the rendition's CRF, which is the codec's own (libx264's 23, x265's 26, SVT-AV1's 35).
// qualityFor translates it for hardware encoders. HEVC is tagged hvc1 (Apple players need it); AV1
// keeps FFmpeg's av01.
func videoArgs(e Encoder, c Codec, r Rendition, preset string, rate FrameRate) ([]string, error) {
	if c == "" {
		c = CodecH264
	}
	if !c.Valid() {
		return nil, fmt.Errorf("media: codec %q is not supported", c)
	}
	e = e.For(c)
	gop := strconv.Itoa(rate.GOP)
	caps := []string{"-maxrate", strconv.Itoa(r.MaxrateKbps) + "k", "-bufsize", strconv.Itoa(r.BufsizeKbps) + "k"}
	keys := []string{"-g", gop, "-force_key_frames", "expr:gte(t,n_forced*" + strconv.Itoa(KeyframeSeconds) + ")", "-fps_mode", "cfr"}
	q := strconv.Itoa(qualityFor(e, r.CRF))
	crf := strconv.Itoa(r.CRF)
	// head names the encoder and the profile of a hardware encoder (software encoders pick their own).
	head := func(profile string) []string {
		a := []string{"-c:v", e.FFmpegName(c)}
		if c == CodecHEVC {
			a = append(a, "-tag:v", "hvc1")
		}
		if profile != "" {
			a = append(a, "-profile:v", profile)
		}
		return a
	}
	profile := map[Codec]string{CodecH264: "high", CodecHEVC: "main"}[c]
	var a []string
	switch e {
	case EncoderSoftware, "":
		switch c {
		case CodecHEVC:
			a = []string{"-c:v", "libx265", "-tag:v", "hvc1", "-preset", X265Preset, "-crf", crf}
			a = append(a, caps...)
			a = append(a, "-g", gop, "-keyint_min", gop, "-x265-params", "scenecut=0:open-gop=0", "-forced-idr", "1")
		case CodecAV1:
			a = []string{"-c:v", "libsvtav1", "-preset", SVTAV1Preset, "-crf", crf}
			a = append(a, caps...)
			a = append(a, "-g", gop, "-svtav1-params", "scd=0:irefresh-type=2", "-forced-idr", "1")
		default:
			a = []string{"-c:v", "libx264", "-profile:v", "high", "-preset", preset, "-crf", crf}
			a = append(a, caps...)
			a = append(a, "-g", gop, "-keyint_min", gop, "-sc_threshold", "0", "-x264-params", "open-gop=0", "-forced-idr", "1")
		}
		return append(a, keys[2:]...), nil
	case EncoderNVENC:
		// Variable bitrate in constant-quality mode: -cq sets the quality, -b:v 0 leaves the cap to maxrate.
		a = append(head(profile), "-preset", "p5", "-rc", "vbr", "-cq", q, "-b:v", "0")
		a = append(a, caps...)
		a = append(a, "-no-scenecut", "1", "-forced-idr", "1", "-strict_gop", "1")
	case EncoderVAAPI:
		// QVBR is VAAPI's constant-quality mode that still honours a bitrate cap. A driver without it
		// fails the encode, which falls back to software.
		a = append(head(profile), "-rc_mode", "QVBR", "-global_quality", q, "-b:v", strconv.Itoa(r.MaxrateKbps)+"k")
		a = append(a, caps...)
		a = append(a, "-idr_interval", "0")
	case EncoderQSV:
		// -global_quality with no bitrate is QSV's ICQ mode; the caps go in with it.
		a = append(head(profile), "-preset", "medium", "-global_quality", q, "-look_ahead", "0")
		a = append(a, caps...)
		a = append(a, "-adaptive_i", "0", "-adaptive_b", "0", "-idr_interval", "0", "-forced_idr", "1")
	case EncoderVideoToolbox:
		// -q:v is VideoToolbox's constant quality (1 to 100, higher is better); -maxrate and -bufsize
		// cap it. -realtime 0 and -allow_sw 0 keep the encode on the media engine and out of a
		// software path that is slower than libx264.
		a = append(head(profile), "-q:v", q, "-realtime", "0", "-allow_sw", "0")
		a = append(a, caps...)
	default:
		return nil, fmt.Errorf("media: unknown encoder %q", e)
	}
	return append(a, keys...), nil
}

// qualityFor translates a rendition's CRF into e's constant-quality value. NVENC, VAAPI and QSV
// scales run the same direction and about the same size as CRF, so they start from the CRF and are
// for whoever has the hardware to tune. VideoToolbox's -q:v runs the other way: 106-2*CRF gives 60 at
// libx264's CRF 23, which matched its VMAF on the fixtures (docs/hardware-encoders.md); the same
// formula gives HEVC's 54, which is not measured.
func qualityFor(e Encoder, crf int) int {
	if e == EncoderVideoToolbox {
		return min(max(106-2*crf, 1), 100)
	}
	return crf
}

// ProbeEncoder runs a short test encode (ten blank frames, discarded) with e and the same
// arguments a rendition gets, to learn whether the device and the driver work. The shipped FFmpeg
// has no test-pattern sources, so the frames come from the rawvideo demuxer reading /dev/zero. The
// error carries FFmpeg's stderr, which can name the device: callers log the encoder only.
func (t Tools) ProbeEncoder(ctx context.Context, e Encoder, device string) error {
	if !e.Valid() {
		return fmt.Errorf("media: unknown encoder %q", e)
	}
	device = cmp.Or(device, DefaultHWDevice)
	video, err := videoArgs(e, CodecH264, Rendition{Width: 640, Height: 360, CRF: CRF, MaxrateKbps: 700, BufsizeKbps: 1400},
		X264Preset, OutputFrameRate(DefaultFrameRate))
	if err != nil {
		return err
	}
	args := []string{"-hide_banner", "-nostdin", "-v", "error", "-nostats", "-protocol_whitelist", "file,pipe", "-y"}
	args = append(args, e.deviceArgs(device)...)
	args = append(args, "-f", "rawvideo", "-pix_fmt", "yuv420p", "-video_size", "640x360", "-framerate", "30",
		"-i", "file:/dev/zero", "-frames:v", "10", "-vf", e.pixelFormat())
	args = append(args, video...)
	args = append(args, "-f", "null", "-")
	_, err = runBounded(ctx, t.FFmpeg, args...)
	return err
}
