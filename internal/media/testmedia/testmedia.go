// Package testmedia generates small test videos at test time, so no binary fixtures are committed.
//
// Why a generator binary and not the worker's FFmpeg: the worker's FFmpeg is deliberately minimal
// (no lavfi test sources, no raw demuxers), because every feature in it is attack surface for
// untrusted uploads. Fixtures are made with a second, test-only FFmpeg that has lavfi (testsrc2 and
// sine) and the x264 and AAC encoders; the worker Dockerfile builds it in a separate stage
// (`fixtures`) that never ships. The generated files are then probed by the real worker binaries.
// The alternative, writing raw YUV and PCM from Go into the worker's FFmpeg, would have put the
// rawvideo and PCM demuxers into the shipped build for tests' sake alone.
package testmedia

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Generator creates fixtures with a test-capable FFmpeg.
type Generator struct {
	// FFmpeg is the path of an FFmpeg with the lavfi input device, testsrc2 and sine, libx264 and
	// the AAC encoder, and the mp4 and matroska muxers.
	FFmpeg string
}

// Spec describes one fixture.
type Spec struct {
	// Name is the file name inside the output directory, for example "landscape.mp4". A ".mkv"
	// extension selects Matroska; everything else is MP4.
	Name          string
	Width, Height int           // stored frame size; even numbers
	Duration      time.Duration // default 2 s
	FPS           int           // default 15
	Audio         bool          // add a sine tone (AAC)
	// Rotation is the clockwise rotation, 0, 90, 180 or 270, written to the display matrix of an
	// MP4 so that players (and ffprobe) show the picture turned. The stored frames do not change.
	Rotation int
}

// Generate writes the fixture into dir and returns its absolute path.
func (g Generator) Generate(ctx context.Context, dir string, s Spec) (string, error) {
	if g.FFmpeg == "" {
		return "", errors.New("testmedia: no generator FFmpeg configured")
	}
	if s.Name == "" || filepath.Base(s.Name) != s.Name {
		return "", errors.New("testmedia: Name must be a plain file name")
	}
	if s.Width < 16 || s.Height < 16 || s.Width%2 != 0 || s.Height%2 != 0 {
		return "", errors.New("testmedia: Width and Height must be even and at least 16")
	}
	if s.Rotation%90 != 0 || s.Rotation < 0 || s.Rotation > 270 {
		return "", errors.New("testmedia: Rotation must be 0, 90, 180 or 270")
	}
	if s.Duration <= 0 {
		s.Duration = 2 * time.Second
	}
	if s.FPS <= 0 {
		s.FPS = 15
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	out := filepath.Join(abs, s.Name)
	secs := strconv.FormatFloat(s.Duration.Seconds(), 'f', 3, 64)
	fps := strconv.Itoa(s.FPS)

	args := []string{
		"-hide_banner", "-nostdin", "-v", "error", "-y",
		"-f", "lavfi", "-i", fmt.Sprintf("testsrc2=size=%dx%d:rate=%s:duration=%s", s.Width, s.Height, fps, secs),
	}
	if s.Audio {
		args = append(args, "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration="+secs)
	}
	args = append(args, "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p", "-g", fps)
	if s.Audio {
		args = append(args, "-c:a", "aac", "-b:a", "64k", "-ac", "2")
	}
	format := "mp4"
	if filepath.Ext(s.Name) == ".mkv" {
		format = "matroska"
	}
	first := out
	if s.Rotation != 0 {
		first = filepath.Join(abs, "unrotated-"+s.Name)
	}
	args = append(args, "-f", format, "file:"+first)
	if err := g.run(ctx, args); err != nil {
		return "", err
	}
	if s.Rotation == 0 {
		return out, nil
	}
	if format != "mp4" {
		return "", errors.New("testmedia: Rotation needs an MP4")
	}
	// -display_rotation is counter-clockwise, so a clockwise rotation r is 360-r.
	ccw := strconv.Itoa((360 - s.Rotation) % 360)
	err = g.run(ctx, []string{
		"-hide_banner", "-nostdin", "-v", "error", "-y",
		"-display_rotation", ccw, "-i", "file:" + first, "-c", "copy", "-f", "mp4", "file:" + out,
	})
	_ = os.Remove(first)
	if err != nil {
		return "", err
	}
	return out, nil
}

func (g Generator) run(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, g.FFmpeg, args...) //nolint:gosec // test helper: argument array, never a shell
	cmd.Env = []string{"LC_ALL=C"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("testmedia: ffmpeg failed: %w: %s", err, stderr.String())
	}
	return nil
}

// SetMP4Duration rewrites the duration fields of an MP4 (the movie header, every track header and
// every media header) so that the file claims to be d long, without changing its frames. It
// stands in for a hostile file whose metadata lies about its length, which the duration limit
// has to catch before any encoding. Only version 0 headers (32-bit durations) are supported,
// which is what FFmpeg writes for short files.
func SetMP4Duration(path string, d time.Duration) error {
	data, err := os.ReadFile(path) //nolint:gosec // test helper on a path the test created
	if err != nil {
		return err
	}
	var movieScale uint32
	patched := 0
	// walk visits the boxes in [start, end) and descends into the containers of the movie header tree.
	var walk func(start, end int) error
	walk = func(start, end int) error {
		for pos := start; pos+8 <= end; {
			size := int(binary.BigEndian.Uint32(data[pos:]))
			typ := string(data[pos+4 : pos+8])
			if size < 8 || pos+size > end {
				return fmt.Errorf("testmedia: malformed box %q at %d", typ, pos)
			}
			body := pos + 8
			switch typ {
			case "moov", "trak", "mdia":
				if err := walk(body, pos+size); err != nil {
					return err
				}
			case "mvhd":
				if data[body] != 0 {
					return errors.New("testmedia: only version 0 mvhd is supported")
				}
				movieScale = binary.BigEndian.Uint32(data[body+12:])
				binary.BigEndian.PutUint32(data[body+16:], uint32(d.Seconds()*float64(movieScale)))
				patched++
			case "tkhd":
				if data[body] != 0 {
					return errors.New("testmedia: only version 0 tkhd is supported")
				}
				binary.BigEndian.PutUint32(data[body+20:], uint32(d.Seconds()*float64(movieScale)))
				patched++
			case "mdhd":
				if data[body] != 0 {
					return errors.New("testmedia: only version 0 mdhd is supported")
				}
				scale := binary.BigEndian.Uint32(data[body+12:])
				binary.BigEndian.PutUint32(data[body+16:], uint32(d.Seconds()*float64(scale)))
				patched++
			}
			pos += size
		}
		return nil
	}
	if err := walk(0, len(data)); err != nil {
		return err
	}
	if patched == 0 {
		return errors.New("testmedia: no movie header found")
	}
	return os.WriteFile(path, data, 0o600) //nolint:gosec // test helper rewrites a fixture the test created
}
