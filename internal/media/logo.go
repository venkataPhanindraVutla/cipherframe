package media

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
)

// The brand logo (ADR 0049) is drawn on every rendition and on the poster and sprite tiles by the
// same FFmpeg run that encodes them. These constants are the fixed layout: the logo is scaled to a
// share of each picture's width, kept off the edge by a margin that is a share of the width too,
// and never taller than a share of the picture's height.
const (
	// LogoWidthPercent is the logo's width as a percentage of the picture's width.
	LogoWidthPercent = 15
	// logoMarginPercent is the gap to the picture's edges, as a percentage of its width.
	logoMarginPercent = 2
	// logoMaxHeightPercent caps a tall logo: it is shrunk to fit this share of the picture's height.
	logoMaxHeightPercent = 25
)

// The four corners, as the API and the manifest spell them.
const (
	CornerTopLeft     = "top_left"
	CornerTopRight    = "top_right"
	CornerBottomLeft  = "bottom_left"
	CornerBottomRight = "bottom_right"
)

// Bounds of the logo's pixel size and opacity (the API checks the same ones).
const (
	logoMinSide = 16
	logoMaxSide = 1024
)

// LogoSpec is a logo to draw. The pixels are given to FFmpeg as raw RGBA through its rawvideo
// input, so FFmpeg never decodes a PNG (or anything else the tenant sent): Path is a file of exactly
// Width*Height*4 bytes that Go wrote from the stored logo.
type LogoSpec struct {
	// Path is the absolute path of the raw RGBA file.
	Path          string
	Width, Height int
	Corner        string
	// OpacityPercent is 10 to 100.
	OpacityPercent int
}

func (l LogoSpec) validate() error {
	switch {
	case !filepath.IsAbs(l.Path) || strings.ContainsRune(l.Path, 0):
		return errors.New("media: the logo path must be absolute")
	case l.Width < logoMinSide || l.Width > logoMaxSide || l.Height < logoMinSide || l.Height > logoMaxSide:
		return errors.New("media: the logo size is out of range")
	case l.OpacityPercent < 10 || l.OpacityPercent > 100:
		return errors.New("media: the logo opacity must be 10 to 100 percent")
	}
	switch l.Corner {
	case CornerTopLeft, CornerTopRight, CornerBottomLeft, CornerBottomRight:
		return nil
	}
	return errors.New("media: unknown logo corner")
}

// LogoPlacement is where the logo goes on one picture, in pixels.
type LogoPlacement struct {
	Width, Height int
	X, Y          int
}

func evenAtLeast2(v float64) int { return max(2, int(math.Round(v))&^1) }

// Place computes the logo's size and position on a picture of w x h pixels: 15 percent of the width
// (even, so chroma lines up), the logo's own aspect ratio, shrunk to at most 25 percent of the
// height, and a margin of 2 percent of the width to the chosen corner.
func (l LogoSpec) Place(w, h int) LogoPlacement {
	lw := evenAtLeast2(float64(w) * LogoWidthPercent / 100)
	lh := evenAtLeast2(float64(lw) * float64(l.Height) / float64(l.Width))
	if limit := float64(h) * logoMaxHeightPercent / 100; float64(lh) > limit {
		lh = evenAtLeast2(limit)
		lw = evenAtLeast2(float64(lh) * float64(l.Width) / float64(l.Height))
	}
	m := evenAtLeast2(float64(w) * logoMarginPercent / 100)
	p := LogoPlacement{Width: lw, Height: lh, X: m, Y: m}
	switch l.Corner {
	case CornerTopRight:
		p.X = w - lw - m
	case CornerBottomLeft:
		p.Y = h - lh - m
	case CornerBottomRight:
		p.X, p.Y = w-lw-m, h-lh-m
	}
	p.X, p.Y = max(p.X, 0), max(p.Y, 0)
	return p
}

// prepare is the filter chain that makes the logo stream ready to split: straight-alpha RGBA, its
// alpha multiplied by the opacity.
func (l LogoSpec) prepare(in string, branches int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]format=rgba", in)
	if l.OpacityPercent < 100 {
		fmt.Fprintf(&b, ",colorchannelmixer=aa=%s", strconv.FormatFloat(float64(l.OpacityPercent)/100, 'f', 2, 64))
	}
	fmt.Fprintf(&b, ",split=%d", branches)
	for i := range branches {
		fmt.Fprintf(&b, "[l%d]", i)
	}
	return b.String()
}

// overlay is the chain that scales logo branch idx to a w x h picture and draws it on the labelled
// picture in, giving out. The picture is blended in 8-bit 4:2:0, which is what every output is.
func (l LogoSpec) overlay(idx int, in, out string, w, h int) string {
	p := l.Place(w, h)
	return fmt.Sprintf("[l%d]scale=%d:%d:flags=bicubic[g%d];[%s][g%d]overlay=x=%d:y=%d:format=yuv420[%s]",
		idx, p.Width, p.Height, idx, in, idx, p.X, p.Y, out)
}

// args are the input options of the logo: one raw RGBA frame. -protocol_whitelist applies per input,
// so it is repeated. Overlay repeats the last frame of a stream that has ended, so one frame
// covers the whole video.
func (l LogoSpec) args() []string {
	return []string{
		"-protocol_whitelist", "file", "-f", "rawvideo", "-pixel_format", "rgba",
		"-video_size", fmt.Sprintf("%dx%d", l.Width, l.Height), "-framerate", "1",
		"-i", "file:" + l.Path,
	}
}
