//go:build media

package media_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
)

// hdrTranscode runs the real ladder, with the poster and the sprite sheet, on a generated HDR source and
// returns the 360p rendition's directory and the luma of the poster and of the sprite. info is the
// probe result the worker would use: pass it unchanged to convert the source, or with the colour tags
// removed to get what the worker did before it knew about HDR, which scales the PQ or HLG code values
// as if they were SDR.
func hdrTranscode(t *testing.T, src string, info media.Info) (dir string, poster, sprite lumaStats) {
	t.Helper()
	rungs := media.Ladder(info, []int{360})
	plan, ok := media.PlanThumbnails(info.Duration, rungs[0])
	if !ok {
		t.Fatalf("no thumbnail plan for %+v", info)
	}
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := media.TranscodeSpec{
		Source: src, OutDir: out, Info: info, Renditions: rungs,
		Thumbs: &media.ThumbnailSpec{Dir: filepath.Join(root, "thumbs"), Plan: plan},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := tools(t).Transcode(ctx, spec, nil); err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	got, err := media.ReadThumbnails(spec.Thumbs.Dir, plan)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(out, rungs[0].Name), imageLuma(t, got.Poster), imageLuma(t, got.Sprite)
}

// lumaStats describes the luma plane of a JPEG on a 0 to 255 scale: its mean, and its 5th and 95th
// percentiles, which stand for the black and the white of the picture.
type lumaStats struct{ mean, p5, p95 float64 }

func (l lumaStats) spread() float64 { return l.p95 - l.p5 }

func (l lumaStats) String() string {
	return fmt.Sprintf("mean %.0f, black %.0f, white %.0f", l.mean, l.p5, l.p95)
}

func imageLuma(t *testing.T, path string) lumaStats {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test reads its own temp dir
	if err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	ycc, ok := img.(*image.YCbCr)
	if !ok {
		t.Fatalf("%s is %T, want YCbCr", filepath.Base(path), img)
	}
	var hist [256]int
	var sum, n float64
	for y := ycc.Rect.Min.Y; y < ycc.Rect.Max.Y; y++ {
		for x := ycc.Rect.Min.X; x < ycc.Rect.Max.X; x++ {
			v := ycc.Y[ycc.YOffset(x, y)]
			hist[v]++
			sum += float64(v)
			n++
		}
	}
	percentile := func(p float64) float64 {
		var seen float64
		for v, c := range hist {
			if seen += float64(c); seen >= p*n {
				return float64(v)
			}
		}
		return 255
	}
	return lumaStats{mean: sum / n, p5: percentile(0.05), p95: percentile(0.95)}
}

// The worker converts PQ and HLG phone video to BT.709 SDR: the renditions are tagged BT.709, and the
// pictures (the poster and the sprite sheet are checked; they come out of the same graph as the ladder)
// are not the washed-out ones that scaling the HDR code values as SDR gives.
//
// The sources are one SDR test picture encoded into each HDR signal (testmedia.Spec.Transfer), so the
// right answer is known: the picture comes back as SDR. "Washed out" is measured on the luma of the JPEG,
// compared with the same source decoded naively (the colour tags removed from the probe result):
//   - black level, the 5th percentile of luma. HDR code values read as SDR lift the blacks (naive: 61
//     for PQ and 91 for HLG on these fixtures); a conversion puts them back near 0 (14 and 24). Asserted
//     at or below 45 and below the naive one.
//   - contrast, the distance from the 5th to the 95th percentile. Asserted at least 20 above the naive
//     one (measured +81 for PQ and +55 for HLG).
//   - mean, inside 70 to 180, so the picture is neither crushed nor blown out (measured 100 and 133; the
//     naive HLG decode is 191, too bright).
//
// Percentiles are used, not the extremes or a single mean, because one number can be equal for a washed
// out and a correct picture (the naive PQ mean is 112, the converted 100) while black level and contrast
// are what the eye sees. The thresholds leave a wide margin around the measured values, so a different
// FFmpeg or zimg build does not flip them, and sit far from the washed-out values.
func TestHDRSourcesAreToneMappedToBT709(t *testing.T) {
	for _, transfer := range []string{"arib-std-b67", "smpte2084"} {
		t.Run(transfer, func(t *testing.T) {
			src := generate(t, testmedia.Spec{Name: "hdr.mp4", Width: 640, Height: 360, Duration: 2 * time.Second, Transfer: transfer})
			info := probe(t, src)
			v := info.Video
			if v == nil || !v.HDR() || v.ColorTransfer != transfer || v.PixelFormat != "yuv420p10le" || v.ColorPrimaries != "bt2020" || v.ColorSpace != "bt2020nc" {
				t.Fatalf("the fixture is not tagged HDR: %+v", v)
			}

			dir, poster, sprite := hdrTranscode(t, src, info)

			untagged := info
			plain := *info.Video
			plain.ColorTransfer, plain.ColorPrimaries, plain.ColorSpace = "", "", ""
			untagged.Video = &plain
			if plain.HDR() || plain.WideGamut() {
				t.Fatal("the control still looks like HDR")
			}
			_, naive, _ := hdrTranscode(t, src, untagged)

			// The rendition's init segment carries its sample entry, with the colour description.
			out := probe(t, filepath.Join(dir, media.InitFile))
			if o := out.Video; o == nil || o.ColorPrimaries != "bt709" || o.ColorTransfer != "bt709" || o.ColorSpace != "bt709" {
				t.Errorf("the output is not tagged BT.709: %+v", o)
			}

			t.Logf("poster: converted %v; naive %v; sprite: converted %v", poster, naive, sprite)
			for name, l := range map[string]lumaStats{"poster": poster, "sprite": sprite} {
				if l.p5 > 45 || l.p5 >= naive.p5 {
					t.Errorf("%s: the blacks are lifted (%v), the picture is washed out (naive: %v)", name, l, naive)
				}
				if l.spread() < naive.spread()+20 {
					t.Errorf("%s: the contrast is not above the naive decode's (%v against %v)", name, l, naive)
				}
				if l.mean < 70 || l.mean > 180 {
					t.Errorf("%s: mean luma %.0f is outside the SDR mid-range (%v)", name, l.mean, l)
				}
			}
		})
	}
}
