//go:build media

package media_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	_ "image/jpeg"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media/testmedia"
)

// transcodeWithThumbnails runs the real ladder transcode of a generated source with the thumbnail
// branches and returns what was written.
func transcodeWithThumbnails(t *testing.T, s testmedia.Spec) (media.ThumbnailPlan, media.ThumbnailOutput, string) {
	t.Helper()
	src := generate(t, s)
	info := probe(t, src)
	rungs := media.Ladder(info, nil)
	plan, ok := media.PlanThumbnails(info.Duration, rungs[0])
	if !ok {
		t.Fatalf("no plan for %+v", info)
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
	return plan, got, out
}

func jpegSize(t *testing.T, path string) (int, int) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test reads its own temp dir
	if err != nil {
		t.Fatal(err)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil || format != "jpeg" {
		t.Fatalf("not a JPEG: %v", err)
	}
	return cfg.Width, cfg.Height
}

func TestTranscodeWritesPosterAndSpriteSheetInTheSameRun(t *testing.T) {
	for name, s := range map[string]testmedia.Spec{
		"landscape with audio, partial last row": {Name: "a.mp4", Width: 320, Height: 180, Audio: true, Duration: 35 * time.Second},
		"exact multiple of the interval":         {Name: "f.mp4", Width: 320, Height: 180, Duration: 20 * time.Second},
		"portrait, one tile":                     {Name: "b.mp4", Width: 180, Height: 320, Duration: 4 * time.Second},
		"rotated by the display matrix":          {Name: "c.mp4", Width: 320, Height: 180, Audio: true, Duration: 12 * time.Second, Rotation: 90},
	} {
		t.Run(name, func(t *testing.T) {
			plan, got, out := transcodeWithThumbnails(t, s)
			if w, h := jpegSize(t, got.Poster); w != plan.PosterWidth || h != plan.PosterHeight {
				t.Errorf("poster is %dx%d, plan %dx%d", w, h, plan.PosterWidth, plan.PosterHeight)
			}
			if w, h := jpegSize(t, got.Sprite); w != plan.Columns*plan.TileWidth || h != plan.Rows*plan.TileHeight {
				t.Errorf("sprite is %dx%d, plan %dx%d tiles of %dx%d", w, h, plan.Columns, plan.Rows, plan.TileWidth, plan.TileHeight)
			}
			if !strings.HasPrefix(string(got.Track), "WEBVTT\n") || strings.Count(string(got.Track), "-->") != plan.Tiles {
				t.Errorf("track:\n%s", got.Track)
			}
			// The ladder was still written by the same run.
			if _, err := os.Stat(filepath.Join(out, media.Ladder(probe(t, generate(t, s)), nil)[0].Name, media.PlaylistFile)); err != nil {
				t.Errorf("the rendition was not written: %v", err)
			}
		})
	}
}

// The tiles are not blank: the sprite sheet shows the source at different times, so its tiles
// differ from each other (testsrc2 animates).
func TestSpriteTilesShowDifferentMoments(t *testing.T) {
	_, got, _ := transcodeWithThumbnails(t, testmedia.Spec{Name: "d.mp4", Width: 320, Height: 180, Duration: 35 * time.Second})
	b, err := os.ReadFile(got.Sprite) //nolint:gosec // test reads its own temp dir
	if err != nil {
		t.Fatal(err)
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	// Four tiles of 160x90 side by side; compare a patch of the first and the third.
	same := true
	for y := range 90 {
		for x := range 160 {
			r1, g1, b1, _ := img.At(x, y).RGBA()
			r2, g2, b2, _ := img.At(2*160+x, y).RGBA()
			if r1 != r2 || g1 != g2 || b1 != b2 {
				same = false
			}
		}
	}
	if same {
		t.Error("the first and the third tile are identical")
	}
}

func TestTranscodeWithoutThumbnailsWritesNoImages(t *testing.T) {
	src := generate(t, testmedia.Spec{Name: "e.mp4", Width: 320, Height: 180, Duration: 5 * time.Second})
	info := probe(t, src)
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := tools(t).Transcode(context.Background(), media.TranscodeSpec{Source: src, OutDir: out, Info: info, Renditions: media.Ladder(info, nil)}, nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the transcode wrote more than its output directory: %v %v", entries, err)
	}
}
