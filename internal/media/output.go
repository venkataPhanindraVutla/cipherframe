package media

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SegmentFile is one media segment FFmpeg wrote.
type SegmentFile struct {
	// Index is the zero-based position of the segment (FFmpeg's number minus FirstSegmentNumber).
	Index    int
	Path     string
	Duration time.Duration
	Size     int64
}

// RenditionOutput is what FFmpeg wrote for one rendition.
type RenditionOutput struct {
	Rendition Rendition
	InitPath  string
	Segments  []SegmentFile
}

// segmentName matches the files FFmpeg writes from SegmentPattern.
var segmentName = regexp.MustCompile(`^seg_([1-9][0-9]{0,8})\.m4s$`)

// maxPlaylistBytes bounds the FFmpeg playlist Go reads (a 4 hour source has about 2400 segments).
const maxPlaylistBytes = 4 << 20

// ReadRenditionOutput collects a rendition's init segment and media segments from dir. FFmpeg's
// playlist is read only for its segment durations (#EXTINF): the segment list comes from the files
// themselves and the two must agree, with numbers contiguous from FirstSegmentNumber. Every file
// must be a regular file (no symlinks) of nonzero size. The playlist text is never stored; Go
// writes the canonical playlists (package hls).
func ReadRenditionOutput(dir string, r Rendition) (RenditionOutput, error) {
	out := RenditionOutput{Rendition: r}

	initPath := filepath.Join(dir, InitFile)
	if _, err := regularFile(initPath); err != nil {
		return out, fmt.Errorf("media: init segment: %w", err)
	}
	out.InitPath = initPath

	f, err := os.Open(filepath.Join(dir, PlaylistFile)) //nolint:gosec // path built from a directory the worker created
	if err != nil {
		return out, fmt.Errorf("media: rendition playlist: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxPlaylistBytes+1))
	if err != nil {
		return out, fmt.Errorf("media: rendition playlist: %w", err)
	}
	if len(raw) > maxPlaylistBytes {
		return out, errors.New("media: rendition playlist is too large")
	}
	durations, names, err := parseSegmentList(string(raw))
	if err != nil {
		return out, err
	}

	for i, name := range names {
		m := segmentName.FindStringSubmatch(name)
		if m == nil {
			return out, errors.New("media: unexpected segment name in the rendition playlist")
		}
		num, _ := strconv.Atoi(m[1])
		if num != FirstSegmentNumber+i {
			return out, errors.New("media: segment numbers are not contiguous")
		}
		p := filepath.Join(dir, name)
		size, err := regularFile(p)
		if err != nil {
			return out, fmt.Errorf("media: segment %d: %w", i, err)
		}
		out.Segments = append(out.Segments, SegmentFile{Index: i, Path: p, Duration: durations[i], Size: size})
	}
	if len(out.Segments) == 0 {
		return out, errors.New("media: FFmpeg wrote no segments")
	}
	// Anything else FFmpeg left among the numbered segments would be an orphan.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, err
	}
	for _, e := range entries {
		if segmentName.MatchString(e.Name()) && !contains(names, e.Name()) {
			return out, errors.New("media: a segment file is not in the rendition playlist")
		}
	}
	return out, nil
}

func contains(list []string, s string) bool { return slices.Contains(list, s) }

// regularFile returns the size of a non-empty regular file that is not a symlink.
func regularFile(path string) (int64, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return 0, errors.New("missing")
	}
	if !st.Mode().IsRegular() {
		return 0, errors.New("not a regular file")
	}
	if st.Size() == 0 {
		return 0, errors.New("empty")
	}
	return st.Size(), nil
}

// parseSegmentList extracts (duration, name) pairs from an FFmpeg VOD playlist.
func parseSegmentList(text string) ([]time.Duration, []string, error) {
	var durs []time.Duration
	var names []string
	pending := time.Duration(-1)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "#EXTINF:"):
			v, _, _ := strings.Cut(strings.TrimPrefix(line, "#EXTINF:"), ",")
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || math.IsNaN(f) || f <= 0 || f > 3600 {
				return nil, nil, errors.New("media: unreadable segment duration in the rendition playlist")
			}
			pending = time.Duration(math.Round(f*1e6)) * time.Microsecond
		case strings.HasPrefix(line, "#"):
		default:
			if pending < 0 {
				return nil, nil, errors.New("media: segment without a duration in the rendition playlist")
			}
			durs = append(durs, pending)
			names = append(names, line)
			pending = -1
		}
	}
	return durs, names, nil
}

// CheckAligned verifies that every rendition has the same number of segments with the same
// durations (to within tolerance). Identical keyframe placement (ADR 0024, pitfall 4) makes that
// true; a difference means a viewer switching renditions would land in the wrong place.
func CheckAligned(outs []RenditionOutput, tolerance time.Duration) error {
	if len(outs) < 2 {
		return nil
	}
	ref := outs[0]
	for _, o := range outs[1:] {
		if len(o.Segments) != len(ref.Segments) {
			return fmt.Errorf("media: %s has %d segments but %s has %d", o.Rendition.Name, len(o.Segments), ref.Rendition.Name, len(ref.Segments))
		}
		for i := range o.Segments {
			d := o.Segments[i].Duration - ref.Segments[i].Duration
			if d < -tolerance || d > tolerance {
				return fmt.Errorf("media: segment %d of %s is %s long but %s of %s", i, o.Rendition.Name,
					o.Segments[i].Duration, ref.Segments[i].Duration, ref.Rendition.Name)
			}
		}
	}
	return nil
}
