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

// Codec is the video codec of a rendition. Only H.264 is built; the parameter exists so that HEVC
// and AV1 (ADR 0064) add cases to videoArgs instead of rewriting it.
type Codec string

// CodecH264 is the codec of every rendition today.
const CodecH264 Codec = "h264"

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

// FFmpegName is the name FFmpeg gives the H.264 encoder, which is also what the manifest records.
func (e Encoder) FFmpegName(c Codec) string {
	switch {
	case !e.Hardware():
		return "libx264"
	case c == CodecH264 || c == "":
		return "h264_" + string(e)
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

// videoArgs maps an encoder and a rung to the FFmpeg arguments of that rendition's video stream.
// It is the only place that does. Every encoder gets the same placement of keyframes (every
// KeyframeSeconds at forced timestamps, IDR, none added by scene detection) and the rung's
// maxrate and bufsize caps; the quality target is each encoder's own constant-quality mode. The
// ladder's CRF is libx264's; qualityFor translates it.
func videoArgs(e Encoder, c Codec, r Rendition, preset string, rate FrameRate) ([]string, error) {
	if c != CodecH264 && c != "" {
		return nil, fmt.Errorf("media: codec %q is not supported", c)
	}
	gop := strconv.Itoa(rate.GOP)
	caps := []string{"-maxrate", strconv.Itoa(r.MaxrateKbps) + "k", "-bufsize", strconv.Itoa(r.BufsizeKbps) + "k"}
	keys := []string{"-g", gop, "-force_key_frames", "expr:gte(t,n_forced*" + strconv.Itoa(KeyframeSeconds) + ")", "-fps_mode", "cfr"}
	q := strconv.Itoa(qualityFor(e, r.CRF))
	var a []string
	switch e {
	case EncoderSoftware, "":
		a = []string{"-c:v", "libx264", "-profile:v", "high", "-preset", preset, "-crf", strconv.Itoa(r.CRF)}
		a = append(a, caps...)
		a = append(a, "-g", gop, "-keyint_min", gop, "-sc_threshold", "0", "-x264-params", "open-gop=0", "-forced-idr", "1")
		return append(a, keys[2:]...), nil
	case EncoderNVENC:
		// Variable bitrate in constant-quality mode: -cq sets the quality, -b:v 0 leaves the cap to maxrate.
		a = []string{"-c:v", "h264_nvenc", "-profile:v", "high", "-preset", "p5", "-rc", "vbr", "-cq", q, "-b:v", "0"}
		a = append(a, caps...)
		a = append(a, "-no-scenecut", "1", "-forced-idr", "1", "-strict_gop", "1")
	case EncoderVAAPI:
		// QVBR is VAAPI's constant-quality mode that still honours a bitrate cap. A driver without it
		// fails the encode, which falls back to software.
		a = []string{
			"-c:v", "h264_vaapi", "-profile:v", "high", "-rc_mode", "QVBR", "-global_quality", q,
			"-b:v", strconv.Itoa(r.MaxrateKbps) + "k",
		}
		a = append(a, caps...)
		a = append(a, "-idr_interval", "0")
	case EncoderQSV:
		// -global_quality with no bitrate is QSV's ICQ mode; the caps go in with it.
		a = []string{"-c:v", "h264_qsv", "-profile:v", "high", "-preset", "medium", "-global_quality", q, "-look_ahead", "0"}
		a = append(a, caps...)
		a = append(a, "-adaptive_i", "0", "-adaptive_b", "0", "-idr_interval", "0", "-forced_idr", "1")
	case EncoderVideoToolbox:
		// -q:v is VideoToolbox's constant quality (1 to 100, higher is better); -realtime 0 and
		// -allow_sw 0 keep it on the media engine and out of a software path that is slower than libx264.
		a = []string{"-c:v", "h264_videotoolbox", "-profile:v", "high", "-q:v", q, "-realtime", "0", "-allow_sw", "0"}
		a = append(a, caps...)
	default:
		return nil, fmt.Errorf("media: unknown encoder %q", e)
	}
	return append(a, keys...), nil
}

// qualityFor translates the ladder's libx264 CRF into e's constant-quality value. NVENC, VAAPI and
// QSV scales run the same direction and about the same size as CRF, so they start from the CRF;
// VideoToolbox's runs the other way (see docs/hardware-encoders.md for how it was tuned).
func qualityFor(e Encoder, crf int) int {
	if e == EncoderVideoToolbox {
		return min(max(100-2*crf, 1), 100)
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
