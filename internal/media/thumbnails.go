package media

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // registers the decoder image.DecodeConfig reads the sizes with
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Thumbnails (ADR 0046): a poster, a sprite sheet of tiles at a fixed interval and the WebVTT track
// that maps playback time to a tile. FFmpeg writes the two JPEGs in the same process that encodes
// the ladder, from the same decoded frames; Go writes the track.
const (
	// PosterFile and SpriteFile are the names FFmpeg writes under ThumbnailSpec.Dir.
	PosterFile = "poster.jpg"
	SpriteFile = "sprite.jpg"
	// ThumbnailTrackFile is the name of the WebVTT track. FFmpeg does not write it.
	ThumbnailTrackFile = "thumbnails.vtt"

	posterMaxWidth   = 640
	tileMaxWidth     = 160
	tileMaxHeight    = 288 // a portrait video stays under this, so the sheet never nears the JPEG size limit
	spriteColumns    = 10
	spriteInterval   = 10 // seconds, the least; longer videos use a longer interval
	maxSpriteTiles   = 600
	posterAtFraction = 10 // percent of the duration
)

// ThumbnailPlan is what the poster, the sprite sheet and the track are made from. All of it is
// derived from the source's duration and the first rendition's shape.
type ThumbnailPlan struct {
	Duration                  time.Duration
	PosterAt                  time.Duration
	PosterWidth, PosterHeight int
	Interval                  time.Duration
	// Tiles is the number of cues: one per interval, the last one short.
	Tiles                 int
	Columns, Rows         int
	TileWidth, TileHeight int
}

// PlanThumbnails plans the thumbnails of a source of the given duration whose renditions have the
// shape of r (the display aspect ratio). ok is false when the duration is unknown: there is then
// nothing to place a poster or tiles on.
func PlanThumbnails(duration time.Duration, r Rendition) (ThumbnailPlan, bool) {
	if duration <= 0 || r.Width < 2 || r.Height < 2 {
		return ThumbnailPlan{}, false
	}
	p := ThumbnailPlan{Duration: duration, PosterAt: duration * posterAtFraction / 100}
	p.PosterWidth, p.PosterHeight = fit(r.Width, r.Height, posterMaxWidth, math.MaxInt32)
	p.TileWidth, p.TileHeight = fit(r.Width, r.Height, tileMaxWidth, tileMaxHeight)

	secs := int(math.Ceil(duration.Seconds()))
	interval := max(spriteInterval, (secs+maxSpriteTiles-1)/maxSpriteTiles)
	p.Interval = time.Duration(interval) * time.Second
	p.Tiles = max(1, (secs+interval-1)/interval)
	p.Columns = min(spriteColumns, p.Tiles)
	p.Rows = (p.Tiles + p.Columns - 1) / p.Columns
	return p, true
}

// fit scales w x h down (never up) into maxW x maxH and rounds both sides to even numbers.
func fit(w, h, maxW, maxH int) (int, int) {
	scale := math.Min(1, math.Min(float64(maxW)/float64(w), float64(maxH)/float64(h)))
	even := func(v float64) int { return max(2, int(math.Round(v))&^1) }
	return even(float64(w) * scale), even(float64(h) * scale)
}

// ThumbnailSpec asks the transcode for thumbnails. Dir is absolute and receives PosterFile and
// SpriteFile; Transcode creates it.
type ThumbnailSpec struct {
	Dir  string
	Plan ThumbnailPlan
}

// graph returns the filter chains of the poster and the sprite sheet, reading the labelled
// streams in and sheetIn (both already at the output frame rate).
func (s ThumbnailSpec) graph(posterIn, sheetIn string) string {
	p := s.Plan
	return fmt.Sprintf("[%s]trim=start=%s,setpts=PTS-STARTPTS,scale=%d:%d:flags=bicubic,setsar=1,format=yuvj420p[poster];"+
		"[%s]fps=1/%d,scale=%d:%d:flags=bicubic,setsar=1,format=yuvj420p,tile=%dx%d[sheet]",
		posterIn, strconv.FormatFloat(p.PosterAt.Seconds(), 'f', 3, 64), p.PosterWidth, p.PosterHeight,
		sheetIn, int(p.Interval.Seconds()), p.TileWidth, p.TileHeight, p.Columns, p.Rows)
}

// args are the two outputs. Each writes one JPEG: -frames:v 1 stops the sheet after its first full
// grid, and the tile filter pads a grid the video ends in the middle of.
func (s ThumbnailSpec) args() []string {
	out := func(label string, q int, file string) []string {
		return []string{
			"-map", "[" + label + "]", "-c:v", "mjpeg", "-q:v", strconv.Itoa(q),
			"-frames:v", "1", "-fps_mode", "passthrough", "-update", "1", "-f", "image2",
			"file:" + filepath.Join(s.Dir, file),
		}
	}
	return append(out("poster", 3, PosterFile), out("sheet", 5, SpriteFile)...)
}

// ThumbnailOutput is what FFmpeg wrote for a ThumbnailSpec plus the track Go made from the plan.
type ThumbnailOutput struct {
	Poster, Sprite string // absolute paths
	Track          []byte // WebVTT; the cues name SpriteFile with no token
}

// ReadThumbnails checks the two JPEGs under dir (regular files, JPEG, exactly the size the plan
// says) and builds the track.
func ReadThumbnails(dir string, plan ThumbnailPlan) (ThumbnailOutput, error) {
	out := ThumbnailOutput{Poster: filepath.Join(dir, PosterFile), Sprite: filepath.Join(dir, SpriteFile)}
	for _, c := range []struct {
		path string
		w, h int
	}{
		{out.Poster, plan.PosterWidth, plan.PosterHeight},
		{out.Sprite, plan.Columns * plan.TileWidth, plan.Rows * plan.TileHeight},
	} {
		if _, err := regularFile(c.path); err != nil {
			return ThumbnailOutput{}, fmt.Errorf("media: thumbnail: %w", err)
		}
		b, err := os.ReadFile(c.path) //nolint:gosec // a file FFmpeg wrote in the job's private directory
		if err != nil {
			return ThumbnailOutput{}, fmt.Errorf("media: thumbnail: %w", err)
		}
		cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
		if err != nil || format != "jpeg" || cfg.Width != c.w || cfg.Height != c.h {
			return ThumbnailOutput{}, errors.New("media: a thumbnail is not the JPEG that was asked for")
		}
	}
	out.Track = ThumbnailTrack(plan)
	return out, nil
}

// ThumbnailTrack renders the WebVTT thumbnail track: one cue per interval whose payload is the
// sprite sheet and the tile's rectangle (the "#xywh=" media fragment players read).
func ThumbnailTrack(p ThumbnailPlan) []byte {
	var b strings.Builder
	b.WriteString("WEBVTT\n")
	for i := range p.Tiles {
		start := time.Duration(i) * p.Interval
		end := min(start+p.Interval, p.Duration)
		fmt.Fprintf(&b, "\n%s --> %s\n%s#xywh=%d,%d,%d,%d\n", vttTime(start), vttTime(end), SpriteFile,
			(i%p.Columns)*p.TileWidth, (i/p.Columns)*p.TileHeight, p.TileWidth, p.TileHeight)
	}
	return []byte(b.String())
}

func vttTime(d time.Duration) string {
	ms := d.Milliseconds()
	return fmt.Sprintf("%02d:%02d:%02d.%03d", ms/3600000, ms/60000%60, ms/1000%60, ms%1000)
}
