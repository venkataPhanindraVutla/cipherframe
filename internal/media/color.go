package media

import "strings"

// Colour handling of HDR and wide-gamut sources. Every rendition is 8-bit BT.709 SDR, so a source
// that is not already that is converted in software, in front of the scaling, with the zscale
// (zimg) and tonemap filters of the worker's FFmpeg. Without it the scaler would treat PQ or HLG
// code values as if they were SDR and the picture would come out washed out. The face masker
// (ml/src/cipherframe_ml/mask.py) repeats these filters; keep them in step.

// Transfer characteristics (FFprobe's color_transfer) that make a source HDR.
const (
	TransferPQ  = "smpte2084"    // HDR10, the base layer of Dolby Vision
	TransferHLG = "arib-std-b67" // HLG
)

// PrimariesBT2020 is the wide gamut phones record in.
const PrimariesBT2020 = "bt2020"

const (
	// The tone-map chain linearises at 100 nits, moves to BT.709 primaries, compresses the highlights
	// with Hable and encodes BT.709 limited range as 8-bit 4:2:0. hints go after the first zscale.
	tonemapHead = "zscale=t=linear:npl=100"
	tonemapTail = ",format=gbrpf32le,zscale=p=bt709,tonemap=tonemap=hable:desat=0,zscale=t=bt709:m=bt709:r=tv,format=yuv420p"
	// An SDR source with wide primaries only has its colours converted.
	wideGamutSDR = "zscale=p=bt709:t=bt709:m=bt709:r=tv,format=yuv420p"
)

// HDR reports whether the stream is PQ or HLG.
func (v *VideoStream) HDR() bool {
	return v.ColorTransfer == TransferPQ || v.ColorTransfer == TransferHLG
}

// WideGamut reports an SDR stream with BT.2020 primaries: its colours are converted to BT.709
// without tone mapping.
func (v *VideoStream) WideGamut() bool {
	return !v.HDR() && v.ColorPrimaries == PrimariesBT2020
}

// unset reports a colour tag that FFprobe leaves out or calls unknown.
func unset(tag string) bool {
	switch strings.ToLower(tag) {
	case "", "unknown", "unspecified", "reserved":
		return true
	}
	return false
}

// ColorFilter is the filter chain that converts the stream to 8-bit BT.709 SDR, or "" when it is SDR
// already. An HDR file tagged without its primaries or matrix is taken to be BT.2020 (what HDR is
// made in), because zscale refuses to convert from unknown primaries.
func (v *VideoStream) ColorFilter() string {
	switch {
	case v.HDR():
		hints := ""
		if unset(v.ColorPrimaries) {
			hints += ":pin=bt2020"
		}
		if unset(v.ColorSpace) {
			hints += ":min=bt2020nc"
		}
		return tonemapHead + hints + tonemapTail
	case v.WideGamut():
		return wideGamutSDR
	}
	return ""
}
