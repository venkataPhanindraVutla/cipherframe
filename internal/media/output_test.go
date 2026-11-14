package media

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// tailOutput writes one file per duration, each holding its own letter repeated, and returns the
// rendition output that describes them.
func tailOutput(t *testing.T, durs ...time.Duration) RenditionOutput {
	t.Helper()
	dir := t.TempDir()
	var out RenditionOutput
	for i, d := range durs {
		p := filepath.Join(dir, "seg_"+strconv.Itoa(i+1)+".m4s")
		body := bytes.Repeat([]byte{byte('a' + i)}, 10)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		out.Segments = append(out.Segments, SegmentFile{Index: i, Path: p, Duration: d, Size: int64(len(body))})
	}
	return out
}

func TestMergeShortTail(t *testing.T) {
	sec := time.Second
	t.Run("short last segment is merged", func(t *testing.T) {
		in := tailOutput(t, 6006*time.Millisecond, 6006*time.Millisecond, 33*time.Millisecond)
		last := in.Segments[2].Path
		out, err := mergeShortTail(in)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Segments) != 2 {
			t.Fatalf("segments = %d, want 2", len(out.Segments))
		}
		if got, want := out.Segments[1].Duration, 6039*time.Millisecond; got != want {
			t.Errorf("duration = %s, want %s", got, want)
		}
		if out.Segments[1].Size != 20 {
			t.Errorf("size = %d, want 20", out.Segments[1].Size)
		}
		b, _ := os.ReadFile(out.Segments[1].Path) //nolint:gosec // test temp dir
		if string(b) != "bbbbbbbbbbcccccccccc" {
			t.Errorf("merged bytes = %q", b)
		}
		if _, err := os.Stat(last); !os.IsNotExist(err) {
			t.Errorf("the merged segment file still exists: %v", err)
		}
		if a, _ := os.ReadFile(out.Segments[0].Path); string(a) != "aaaaaaaaaa" { //nolint:gosec // test temp dir
			t.Errorf("an earlier segment changed: %q", a)
		}
	})
	t.Run("a last segment of one second or more is kept", func(t *testing.T) {
		out, err := mergeShortTail(tailOutput(t, 6*sec, sec))
		if err != nil || len(out.Segments) != 2 || out.Segments[1].Duration != sec {
			t.Fatalf("out = %+v, err = %v", out.Segments, err)
		}
	})
	t.Run("a single short segment is kept", func(t *testing.T) {
		out, err := mergeShortTail(tailOutput(t, 33*time.Millisecond))
		if err != nil || len(out.Segments) != 1 {
			t.Fatalf("out = %+v, err = %v", out.Segments, err)
		}
	})
}

func TestReadRenditionOutputMergesShortTail(t *testing.T) {
	dir := t.TempDir()
	pl := "#EXTM3U\n#EXT-X-TARGETDURATION:7\n#EXTINF:6.006,\nseg_1.m4s\n#EXTINF:6.006,\nseg_2.m4s\n#EXTINF:0.033,\nseg_3.m4s\n#EXT-X-ENDLIST\n"
	files := map[string]string{PlaylistFile: pl, InitFile: "init", "seg_1.m4s": "one", "seg_2.m4s": "two", "seg_3.m4s": "three"}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := ReadRenditionOutput(dir, Rendition{Name: "240p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Segments) != 2 || out.Segments[1].Duration != 6039*time.Millisecond {
		t.Fatalf("segments = %+v", out.Segments)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "seg_2.m4s")); string(b) != "twothree" { //nolint:gosec // test temp dir
		t.Errorf("seg_2 = %q", b)
	}
}
