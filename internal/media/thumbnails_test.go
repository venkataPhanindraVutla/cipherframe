package media

import (
	"bytes"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPlanThumbnails(t *testing.T) {
	land := Rendition{Width: 1920, Height: 1080}
	for name, c := range map[string]struct {
		dur              time.Duration
		r                Rendition
		interval         time.Duration
		tiles, cols      int
		rows             int
		tileW, tileH     int
		posterW, posterH int
	}{
		"short":    {27 * time.Second, land, 10 * time.Second, 3, 3, 1, 160, 90, 640, 360},
		"one tile": {4 * time.Second, land, 10 * time.Second, 1, 1, 1, 160, 90, 640, 360},
		"exact":    {20 * time.Second, land, 10 * time.Second, 2, 2, 1, 160, 90, 640, 360},
		"two rows": {105 * time.Second, land, 10 * time.Second, 11, 10, 2, 160, 90, 640, 360},
		"long":     {3 * time.Hour, land, 18 * time.Second, 600, 10, 60, 160, 90, 640, 360},
		"portrait": {30 * time.Second, Rendition{Width: 1080, Height: 1920}, 10 * time.Second, 3, 3, 1, 160, 284, 640, 1138},
		"tiny":     {30 * time.Second, Rendition{Width: 100, Height: 60}, 10 * time.Second, 3, 3, 1, 100, 60, 100, 60},
	} {
		t.Run(name, func(t *testing.T) {
			p, ok := PlanThumbnails(c.dur, c.r)
			if !ok {
				t.Fatal("no plan")
			}
			if p.Interval != c.interval || p.Tiles != c.tiles || p.Columns != c.cols || p.Rows != c.rows ||
				p.TileWidth != c.tileW || p.TileHeight != c.tileH || p.PosterWidth != c.posterW || p.PosterHeight != c.posterH {
				t.Fatalf("plan = %+v", p)
			}
			if p.PosterAt != c.dur/10 {
				t.Errorf("poster at %v, want 10%% of %v", p.PosterAt, c.dur)
			}
			if p.Columns*p.Rows < p.Tiles || p.TileWidth%2 != 0 || p.TileHeight%2 != 0 {
				t.Errorf("the grid cannot hold the tiles or a side is odd: %+v", p)
			}
		})
	}
	if _, ok := PlanThumbnails(0, land); ok {
		t.Error("an unknown duration must give no plan")
	}
}

func TestThumbnailTrack(t *testing.T) {
	p, _ := PlanThumbnails(25*time.Second+500*time.Millisecond, Rendition{Width: 1920, Height: 1080})
	want := "WEBVTT\n" +
		"\n00:00:00.000 --> 00:00:10.000\nsprite.jpg#xywh=0,0,160,90\n" +
		"\n00:00:10.000 --> 00:00:20.000\nsprite.jpg#xywh=160,0,160,90\n" +
		"\n00:00:20.000 --> 00:00:25.500\nsprite.jpg#xywh=320,0,160,90\n"
	if got := string(ThumbnailTrack(p)); got != want {
		t.Fatalf("track:\n%s\nwant:\n%s", got, want)
	}
	p, _ = PlanThumbnails(105*time.Second, Rendition{Width: 1920, Height: 1080})
	if got := string(ThumbnailTrack(p)); !strings.Contains(got, "00:01:40.000 --> 00:01:45.000\nsprite.jpg#xywh=0,90,160,90\n") {
		t.Errorf("the eleventh tile starts the second row:\n%s", got)
	}
}

func TestTranscodeArgsWithThumbnails(t *testing.T) {
	spec := testSpec()
	plan, _ := PlanThumbnails(60*time.Second, spec.Renditions[0])
	spec.Thumbs = &ThumbnailSpec{Dir: "/work/job/thumbs", Plan: plan}
	args, err := TranscodeArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	n := len(spec.Renditions)
	if !strings.Contains(joined, "split="+strconv.Itoa(n+2)) || !strings.Contains(joined, "[s"+strconv.Itoa(n)+"]trim=start=6.000") ||
		!strings.Contains(joined, "[s"+strconv.Itoa(n+1)+"]fps=1/10") || !strings.Contains(joined, "tile=6x1") {
		t.Errorf("filter graph lacks the thumbnail branches: %s", joined)
	}
	for _, w := range []string{"file:/work/job/thumbs/poster.jpg", "file:/work/job/thumbs/sprite.jpg", "mjpeg"} {
		if !strings.Contains(joined, w) {
			t.Errorf("args lack %q", w)
		}
	}
	// Without thumbnails nothing changes.
	plain, _ := TranscodeArgs(testSpec())
	if strings.Contains(strings.Join(plain, " "), "mjpeg") {
		t.Error("a plain transcode must not write images")
	}
	spec.Thumbs = &ThumbnailSpec{Dir: "thumbs", Plan: plan}
	if _, err := TranscodeArgs(spec); err == nil {
		t.Error("a relative thumbnail directory must be refused")
	}
}

func writeJPEG(t *testing.T, path string, w, h int) {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, image.NewGray(image.Rect(0, 0, w, h)), nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadThumbnails(t *testing.T) {
	plan, _ := PlanThumbnails(25*time.Second, Rendition{Width: 1920, Height: 1080})
	dir := t.TempDir()
	writeJPEG(t, filepath.Join(dir, PosterFile), plan.PosterWidth, plan.PosterHeight)
	writeJPEG(t, filepath.Join(dir, SpriteFile), plan.Columns*plan.TileWidth, plan.Rows*plan.TileHeight)
	out, err := ReadThumbnails(dir, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out.Track, []byte("WEBVTT\n")) {
		t.Errorf("track = %q", out.Track)
	}

	// A sprite of the wrong size, a file that is not a JPEG and a missing file are all refused.
	writeJPEG(t, filepath.Join(dir, SpriteFile), 10, 10)
	if _, err := ReadThumbnails(dir, plan); err == nil {
		t.Error("a sprite of the wrong size must be refused")
	}
	if err := os.WriteFile(filepath.Join(dir, SpriteFile), []byte("not an image"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadThumbnails(dir, plan); err == nil {
		t.Error("a file that is not a JPEG must be refused")
	}
	if _, err := ReadThumbnails(t.TempDir(), plan); err == nil {
		t.Error("missing files must be refused")
	}
}
