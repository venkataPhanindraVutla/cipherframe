package media

import (
	"fmt"
	"math"
	"slices"
)

// Encoding defaults of ADR 0024.
const (
	// CRF is the starting constant rate factor of every H.264 rung.
	CRF = 23
	// CRFHEVC and CRFAV1 are the starting points of libx265 and SVT-AV1 (ADR 0067). Their scales are
	// not libx264's: these were picked on the fixtures to land near libx264 CRF 23's VMAF.
	CRFHEVC = 26
	CRFAV1  = 35
	// AudioKbps is the AAC-LC stereo bitrate.
	AudioKbps = 96
)

// rung is one entry of the fixed ladder.
type rung struct {
	height int
	// maxrateKbps is the H.264 cap; hevcKbps and av1Kbps are the caps of the extra codecs (ADR 0064,
	// ADR 0067): 0.6 of H.264's for both, because those codecs reach about the same quality with fewer bits.
	// The cap only bounds peaks: on the measured fixtures the codec's CRF decides the size, except that
	// SVT-AV1's capped-CRF mode lands well under its cap on hard content, so AV1's 0.5 was raised.
	maxrateKbps, hevcKbps, av1Kbps int
}

// maxrate is the cap of the rung for codec c.
func (r rung) maxrate(c Codec) int {
	switch c {
	case CodecHEVC:
		return r.hevcKbps
	case CodecAV1:
		return r.av1Kbps
	}
	return r.maxrateKbps
}

// ladderRungs are the five rungs of ADR 0024, tallest first, with their maxrate caps. The buffer
// size is twice the maxrate (one second of cap at two-second keyframe spacing).
var ladderRungs = [...]rung{
	{1080, 4500, 2700, 2700},
	{720, 2500, 1500, 1500},
	{480, 1200, 720, 720},
	{360, 700, 420, 420},
	{240, 350, 210, 210},
}

// RungHeights returns the heights of the ADR 0024 rungs, tallest first.
func RungHeights() []int {
	out := make([]int, len(ladderRungs))
	for i, r := range ladderRungs {
		out[i] = r.height
	}
	return out
}

// CRFs are the constant-quality values of the three codecs: the operator's setting
// (CIPHERFRAME_WORKER_CRF, _CRF_HEVC and _CRF_AV1). The ladder starts from the constants above.
type CRFs struct{ H264, HEVC, AV1 int }

// DefaultCRFs are CRF, CRFHEVC and CRFAV1.
func DefaultCRFs() CRFs { return CRFs{H264: CRF, HEVC: CRFHEVC, AV1: CRFAV1} }

// Apply sets the CRF of every rendition to its codec's value and returns rs.
func (q CRFs) Apply(rs []Rendition) []Rendition {
	for i := range rs {
		switch rs[i].Codec {
		case CodecHEVC:
			rs[i].CRF = q.HEVC
		case CodecAV1:
			rs[i].CRF = q.AV1
		default:
			rs[i].CRF = q.H264
		}
	}
	return rs
}

// Rendition is one output of the ladder: a size and its rate-control settings. The transcoder
// scales the source to Width x Height after applying the display rotation.
type Rendition struct {
	// Name is "1080p", "720p" and so on, the display height, with "_hevc" or "_av1" after it for an
	// extra codec.
	Name string
	// Codec is CodecHEVC or CodecAV1 for the renditions of an extra codec and empty for H.264's.
	Codec         Codec
	Width, Height int // both even
	CRF           int
	MaxrateKbps   int
	BufsizeKbps   int
	// AudioKbps is 0 when the source has no audio.
	AudioKbps int
}

// Ladder returns the renditions for a source, tallest first. A rung is used only if the source's
// display height (after rotation and sample aspect ratio) is at least that tall, so nothing is
// ever upscaled. There is always at least one rendition: a source shorter than 240 pixels gets a
// single rendition at its own height rounded down to an even number. Width follows the display
// aspect ratio, rounded to an even number. Resolution decides the rungs; the source's bitrate does
// not, so a low-bitrate source still gets every rung its resolution allows.
//
// heights, when not empty, restricts the ladder to those rungs (ADR 0037); it holds heights from
// RungHeights, the config layer validates it. If the source is shorter than every selected rung
// it gets one rendition at its own height with the caps of the smallest selected rung.
//
// Ladder expects a source that passed Validate. A source with no video stream or no usable size
// gives no renditions.
func Ladder(info Info, heights []int) []Rendition { return LadderFor(CodecH264, info, heights) }

// LadderFor is Ladder for codec c: the same rungs, sizes and choice of rungs, with c's caps and CRF.
// The renditions of an extra codec are named "720p_hevc", "720p_av1" and so on, so they sit beside
// the H.264 ones ("720p") under one variant prefix; H.264 names are unchanged.
func LadderFor(c Codec, info Info, heights []int) []Rendition {
	v := info.Video
	if v == nil || v.DisplayWidth <= 0 || v.DisplayHeight <= 0 {
		return nil
	}
	audio := 0
	if info.Audio != nil {
		audio = AudioKbps
	}
	var out []Rendition
	last := ladderRungs[len(ladderRungs)-1]
	for _, r := range ladderRungs {
		if len(heights) > 0 && !slices.Contains(heights, r.height) {
			continue
		}
		last = r
		if v.DisplayHeight >= r.height {
			out = append(out, rendition(c, v, r.height, r.maxrate(c), audio))
		}
	}
	if len(out) == 0 {
		// Smaller than the smallest selected rung: keep the source's own height, with that rung's caps.
		h := max(v.DisplayHeight&^1, 2)
		out = append(out, rendition(c, v, h, last.maxrate(c), audio))
	}
	return out
}

func rendition(c Codec, v *VideoStream, height, maxrate, audio int) Rendition {
	r := Rendition{
		Name:        fmt.Sprintf("%dp", height) + c.nameSuffix(),
		Width:       widthFor(v.DisplayWidth, v.DisplayHeight, height),
		Height:      height,
		CRF:         c.crf(),
		MaxrateKbps: maxrate,
		BufsizeKbps: 2 * maxrate,
		AudioKbps:   audio,
	}
	if c.Extra() {
		r.Codec = c
	}
	return r
}

// widthFor scales the display width to the output height and rounds to the nearest even number. It
// never exceeds the display width, so a rung that equals the source height cannot widen the picture.
func widthFor(displayW, displayH, height int) int {
	w := float64(displayW) * float64(height) / float64(displayH)
	even := int(math.Round(w/2)) * 2
	if even > displayW && height <= displayH {
		even = displayW &^ 1
	}
	return max(even, 2)
}
