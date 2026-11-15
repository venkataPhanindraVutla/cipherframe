//go:build media

package media_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	_ "image/jpeg"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
)

// These tests burn a logo into a real transcode and read pixels back out of the result: the segments
// are decoded by the worker's own FFmpeg (h264 decoder, mov demuxer, mjpeg encoder) and the JPEG is
// read by Go.

// writeRaw writes a w x h logo as raw RGBA, as the pipeline hands it to FFmpeg. px gives each pixel.
func writeRaw(t *testing.T, w, h int, px func(x, y int) color.NRGBA) string {
	t.Helper()
	b := make([]byte, 0, w*h*4)
	for y := range h {
		for x := range w {
			c := px(x, y)
			b = append(b, c.R, c.G, c.B, c.A)
		}
	}
	p := filepath.Join(t.TempDir(), "logo.rgba")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func flat(c color.NRGBA) func(int, int) color.NRGBA { return func(int, int) color.NRGBA { return c } }

var (
	// magenta is far from every colour testsrc2 has at the corners (red on the left, cyan on the right).
	magenta = color.NRGBA{R: 255, B: 255, A: 255}
	white   = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
)

// burned is the output of one transcode.
type burned struct {
	out        string // directory of the rendition directories
	rungs      []media.Rendition
	thumbs     media.ThumbnailOutput
	thumbsPlan media.ThumbnailPlan
}

func transcodeLogo(t *testing.T, s testmedia.Spec, logo *media.LogoSpec) burned {
	t.Helper()
	src := generate(t, s)
	info := probe(t, src)
	rungs := media.Ladder(info, nil)
	plan, ok := media.PlanThumbnails(info.Duration, rungs[0])
	if !ok {
		t.Fatal("no thumbnail plan")
	}
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := media.TranscodeSpec{
		Source: src, OutDir: out, Info: info, Renditions: rungs, Logo: logo,
		Thumbs: &media.ThumbnailSpec{Dir: filepath.Join(root, "thumbs"), Plan: plan},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := tools(t).Transcode(ctx, spec, nil); err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	th, err := media.ReadThumbnails(spec.Thumbs.Dir, plan)
	if err != nil {
		t.Fatal(err)
	}
	return burned{out: out, rungs: rungs, thumbs: th, thumbsPlan: plan}
}

// frame decodes the first frame of one rendition: the init segment and the first media segment make
// a playable fragmented MP4 when put end to end.
func (b burned) frame(t *testing.T, r media.Rendition) image.Image {
	t.Helper()
	dir := filepath.Join(b.out, r.Name)
	init, err := os.ReadFile(filepath.Join(dir, media.InitFile)) //nolint:gosec // test reads its own temp dir
	if err != nil {
		t.Fatal(err)
	}
	seg, err := os.ReadFile(filepath.Join(dir, "seg_1.m4s")) //nolint:gosec // test reads its own temp dir
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	frag := filepath.Join(work, "frag.mp4")
	if err := os.WriteFile(frag, append(init, seg...), 0o600); err != nil { //nolint:gosec // test writes its own temp dir
		t.Fatal(err)
	}
	jpg := filepath.Join(work, "frame.jpg")
	run(t, tools(t).FFmpeg, "-hide_banner", "-nostdin", "-v", "error", "-i", "file:"+frag,
		"-vf", "format=yuvj420p", "-frames:v", "1", "-q:v", "1", "-update", "1", "-f", "image2", "-c:v", "mjpeg", "file:"+jpg)
	return readImage(t, jpg)
}

func readImage(t *testing.T, path string) image.Image {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test reads its own temp dir
	if err != nil {
		t.Fatal(err)
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// patch is the mean colour of the 8 x 8 pixels centred on (cx, cy), 0 to 255 per channel.
func patch(img image.Image, cx, cy int) [3]float64 {
	var sum [3]float64
	n := 0
	for y := cy - 4; y < cy+4; y++ {
		for x := cx - 4; x < cx+4; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			sum[0] += float64(r >> 8)
			sum[1] += float64(g >> 8)
			sum[2] += float64(b >> 8)
			n++
		}
	}
	return [3]float64{sum[0] / float64(n), sum[1] / float64(n), sum[2] / float64(n)}
}

func near(a, b [3]float64, tol float64) bool {
	for i := range a {
		if math.Abs(a[i]-b[i]) > tol {
			return false
		}
	}
	return true
}

// centre is the centre of the logo's rectangle for a corner on a w x h picture.
func centre(l *media.LogoSpec, corner string, w, h int) (int, int) {
	c := *l
	c.Corner = corner
	p := c.Place(w, h)
	return p.X + p.Width/2, p.Y + p.Height/2
}

var corners = []string{media.CornerTopLeft, media.CornerTopRight, media.CornerBottomLeft, media.CornerBottomRight}

var source720 = testmedia.Spec{Name: "logo.mp4", Width: 1280, Height: 720, Duration: 6 * time.Second}

// The logo sits in the chosen corner of every rung, at the planned size, and nowhere else.
func TestLogoIsInTheChosenCornerOfEveryRung(t *testing.T) {
	baseline := transcodeLogo(t, source720, nil)
	for _, corner := range corners {
		t.Run(corner, func(t *testing.T) {
			logo := &media.LogoSpec{Path: writeRaw(t, 128, 64, flat(magenta)), Width: 128, Height: 64, Corner: corner, OpacityPercent: 100}
			got := transcodeLogo(t, source720, logo)
			if len(got.rungs) != 4 {
				t.Fatalf("%d rungs, want 4", len(got.rungs))
			}
			for i, r := range got.rungs {
				img, base := got.frame(t, r), baseline.frame(t, baseline.rungs[i])
				for _, c := range corners {
					x, y := centre(logo, c, r.Width, r.Height)
					have, was := patch(img, x, y), patch(base, x, y)
					if c == corner {
						if !near(have, [3]float64{255, 0, 255}, 40) || near(have, was, 100) {
							t.Errorf("%s: the %s corner is %v (was %v), want magenta", r.Name, c, have, was)
						}
					} else if !near(have, was, 14) {
						t.Errorf("%s: the %s corner changed from %v to %v although the logo is elsewhere", r.Name, c, was, have)
					}
				}
			}
		})
	}
}

// Opacity blends the logo into the picture: out = (1-a)*picture + a*logo, across the allowed range.
func TestLogoOpacityBlendsAcrossTheRange(t *testing.T) {
	baseline := transcodeLogo(t, source720, nil)
	for _, opacity := range []int{10, 25, 50, 75, 100} {
		logo := &media.LogoSpec{Path: writeRaw(t, 64, 64, flat(white)), Width: 64, Height: 64, Corner: media.CornerTopRight, OpacityPercent: opacity}
		got := transcodeLogo(t, source720, logo)
		a := float64(opacity) / 100
		r := got.rungs[0]
		x, y := centre(logo, media.CornerTopRight, r.Width, r.Height)
		have, was := patch(got.frame(t, r), x, y), patch(baseline.frame(t, baseline.rungs[0]), x, y)
		want := [3]float64{(1-a)*was[0] + a*255, (1-a)*was[1] + a*255, (1-a)*was[2] + a*255}
		if !near(have, want, 16) {
			t.Errorf("opacity %d: logo area is %v, want about %v (picture was %v)", opacity, have, want, was)
		}
	}
}

// Transparent pixels of the logo let the picture show through; opaque ones cover it.
func TestLogoKeepsItsTransparency(t *testing.T) {
	baseline := transcodeLogo(t, source720, nil)
	half := func(x, _ int) color.NRGBA {
		if x < 64 {
			return color.NRGBA{} // transparent
		}
		return magenta
	}
	logo := &media.LogoSpec{Path: writeRaw(t, 128, 64, half), Width: 128, Height: 64, Corner: media.CornerBottomLeft, OpacityPercent: 100}
	got := transcodeLogo(t, source720, logo)
	r, b := got.rungs[0], baseline.rungs[0]
	p := logo.Place(r.Width, r.Height)
	img, base := got.frame(t, r), baseline.frame(t, b)
	left, right := patch(img, p.X+p.Width/4, p.Y+p.Height/2), patch(img, p.X+3*p.Width/4, p.Y+p.Height/2)
	if was := patch(base, p.X+p.Width/4, p.Y+p.Height/2); !near(left, was, 14) {
		t.Errorf("the transparent half changed the picture: %v, was %v", left, was)
	}
	if !near(right, [3]float64{255, 0, 255}, 40) {
		t.Errorf("the opaque half is %v, want magenta", right)
	}
}

// The poster and the sprite sheet are cut from the same frames, so they carry the logo too.
func TestPosterAndSpriteTilesShowTheLogo(t *testing.T) {
	baseline := transcodeLogo(t, source720, nil)
	logo := &media.LogoSpec{Path: writeRaw(t, 128, 64, flat(magenta)), Width: 128, Height: 64, Corner: media.CornerBottomRight, OpacityPercent: 100}
	got := transcodeLogo(t, source720, logo)
	p := got.thumbsPlan

	poster := readImage(t, got.thumbs.Poster)
	x, y := centre(logo, media.CornerBottomRight, p.PosterWidth, p.PosterHeight)
	if have := patch(poster, x, y); !near(have, [3]float64{255, 0, 255}, 40) {
		t.Errorf("poster logo area is %v, want magenta", have)
	}
	x, y = centre(logo, media.CornerTopLeft, p.PosterWidth, p.PosterHeight)
	if have, was := patch(poster, x, y), patch(readImage(t, baseline.thumbs.Poster), x, y); !near(have, was, 14) {
		t.Errorf("poster top left changed: %v, was %v", have, was)
	}

	sprite := readImage(t, got.thumbs.Sprite)
	for tile := range p.Tiles {
		ox, oy := (tile%p.Columns)*p.TileWidth, (tile/p.Columns)*p.TileHeight
		x, y := centre(logo, media.CornerBottomRight, p.TileWidth, p.TileHeight)
		if have := patch(sprite, ox+x, oy+y); !near(have, [3]float64{255, 0, 255}, 50) {
			t.Errorf("tile %d logo area is %v, want magenta", tile, have)
		}
	}
}

// A rotated source is drawn on after the rotation: the corner is a corner of what the viewer sees.
func TestLogoFollowsTheDisplayRotation(t *testing.T) {
	s := testmedia.Spec{Name: "rot.mp4", Width: 640, Height: 360, Duration: 4 * time.Second, Rotation: 90}
	logo := &media.LogoSpec{Path: writeRaw(t, 64, 64, flat(magenta)), Width: 64, Height: 64, Corner: media.CornerTopLeft, OpacityPercent: 100}
	got := transcodeLogo(t, s, logo)
	r := got.rungs[0]
	if r.Width >= r.Height {
		t.Fatalf("rendition %dx%d is not portrait", r.Width, r.Height)
	}
	x, y := centre(logo, media.CornerTopLeft, r.Width, r.Height)
	if have := patch(got.frame(t, r), x, y); !near(have, [3]float64{255, 0, 255}, 40) {
		t.Errorf("top left of the rotated picture is %v, want magenta", have)
	}
}

// The ladder's structure is untouched by a logo: the same renditions, still cut at the same places.
func TestLogoKeepsTheKeyframeAlignment(t *testing.T) {
	logo := &media.LogoSpec{Path: writeRaw(t, 64, 64, flat(magenta)), Width: 64, Height: 64, Corner: media.CornerTopLeft, OpacityPercent: 60}
	got := transcodeLogo(t, source720, logo)
	outs := make([]media.RenditionOutput, 0, len(got.rungs))
	for _, r := range got.rungs {
		o, err := media.ReadRenditionOutput(filepath.Join(got.out, r.Name), r)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, o)
	}
	if err := media.CheckAligned(outs, 2*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}
