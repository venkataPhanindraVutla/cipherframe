package media

import (
	"fmt"
	"math"
	"slices"
)

// Encoding defaults of ADR 0024.
const (
	// CRF is the starting constant rate factor for every rung.
	CRF = 23
	// AudioKbps is the AAC-LC stereo bitrate.
	AudioKbps = 96
)

// rung is one entry of the fixed ladder.
type rung struct {
	height      int
	maxrateKbps int
}

// ladderRungs are the five rungs of ADR 0024, tallest first, with their maxrate caps. The buffer
// size is twice the maxrate (one second of cap at two-second keyframe spacing).
var ladderRungs = [...]rung{
	{1080, 4500},
	{720, 2500},
	{480, 1200},
	{360, 700},
	{240, 350},
}

// RungHeights returns the heights of the ADR 0024 rungs, tallest first.
func RungHeights() []int {
	out := make([]int, len(ladderRungs))
	for i, r := range ladderRungs {
		out[i] = r.height
	}
	return out
}

// Rendition is one output of the ladder: a size and its rate-control settings. The transcoder
// scales the source to Width x Height after applying the display rotation.
type Rendition struct {
	// Name is "1080p", "720p" and so on, the display height.
	Name          string
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
func Ladder(info Info, heights []int) []Rendition {
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
			out = append(out, rendition(v, r.height, r.maxrateKbps, audio))
		}
	}
	if len(out) == 0 {
		// Smaller than the smallest selected rung: keep the source's own height, with that rung's caps.
		h := max(v.DisplayHeight&^1, 2)
		out = append(out, rendition(v, h, last.maxrateKbps, audio))
	}
	return out
}

func rendition(v *VideoStream, height, maxrate, audio int) Rendition {
	return Rendition{
		Name:        fmt.Sprintf("%dp", height),
		Width:       widthFor(v.DisplayWidth, v.DisplayHeight, height),
		Height:      height,
		CRF:         CRF,
		MaxrateKbps: maxrate,
		BufsizeKbps: 2 * maxrate,
		AudioKbps:   audio,
	}
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
