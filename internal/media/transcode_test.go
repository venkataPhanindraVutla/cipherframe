package media

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOutputFrameRate(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		expr string
		fps  float64
		gop  int
	}{
		{30, "30", 30, 60},
		{25, "25", 25, 50},
		{24, "24", 24, 48},
		{60, "60", 60, 120},
		{120, "60", 60, 120}, // capped
		{240, "60", 60, 120},
		{30000.0 / 1001, "30000/1001", 30000.0 / 1001, 60}, // 29.97
		{24000.0 / 1001, "24000/1001", 24000.0 / 1001, 48}, // 23.976
		{60000.0 / 1001, "60000/1001", 60000.0 / 1001, 120},
		{29.97, "30000/1001", 30000.0 / 1001, 60},
		{12.5, "12.500", 12.5, 25},
		{0, "30", 30, 60},   // unknown
		{0.5, "30", 30, 60}, // implausible
		{29.999, "30", 30, 60},
	} {
		got := OutputFrameRate(tc.in)
		if got.Expr != tc.expr || got.FPS != tc.fps || got.GOP != tc.gop {
			t.Errorf("OutputFrameRate(%v) = %+v, want {%s %v %d}", tc.in, got, tc.expr, tc.fps, tc.gop)
		}
	}
}

func testSpec() TranscodeSpec {
	info := Info{
		Container: ContainerMP4, Duration: 20 * time.Second,
		Video: &VideoStream{Index: 0, Codec: "h264", Width: 1280, Height: 720, DisplayWidth: 1280, DisplayHeight: 720, FrameRate: 30},
		Audio: &AudioStream{Index: 1, Codec: "aac", Channels: 2, SampleRate: 48000},
	}
	return TranscodeSpec{Source: "/work/job/source", OutDir: "/work/job/out", Info: info, Renditions: Ladder(info)}
}

func argValues(args []string, flag string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			out = append(out, args[i+1])
		}
	}
	return out
}

func TestTranscodeArgsShape(t *testing.T) {
	spec := testSpec()
	args, err := TranscodeArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(spec.Renditions); n != 4 {
		t.Fatalf("ladder has %d rungs, want 4", n)
	}
	// One process, one input, one filter graph.
	if got := argValues(args, "-i"); len(got) != 1 || got[0] != "file:/work/job/source" {
		t.Errorf("-i = %v", got)
	}
	fg := argValues(args, "-filter_complex")
	if len(fg) != 1 {
		t.Fatalf("want exactly one filter graph, got %v", fg)
	}
	for _, want := range []string{
		"[0:0]fps=30,split=4[s0][s1][s2][s3]",
		"[s0]scale=1280:720:flags=bicubic,setsar=1,format=yuv420p[v0]",
		"[s1]scale=854:480:flags=bicubic,setsar=1,format=yuv420p[v1]",
		"[s2]scale=640:360:flags=bicubic,setsar=1,format=yuv420p[v2]",
		"[s3]scale=426:240:flags=bicubic,setsar=1,format=yuv420p[v3]",
	} {
		if !strings.Contains(fg[0], want) {
			t.Errorf("filter graph lacks %q:\n%s", want, fg[0])
		}
	}
	// The same keyframe settings on every rendition (pitfall 4).
	for flag, want := range map[string]string{
		"-g": "60", "-keyint_min": "60", "-sc_threshold": "0", "-force_key_frames": "expr:gte(t,n_forced*2)",
		"-c:v": "libx264", "-profile:v": "high", "-hls_time": "6", "-hls_segment_type": "fmp4",
		"-hls_playlist_type": "vod", "-start_number": "1", "-c:a": "aac", "-b:a": "96k", "-ac": "2",
		"-x264-params": "open-gop=0", "-fps_mode": "cfr", "-hls_flags": "independent_segments",
	} {
		got := argValues(args, flag)
		if len(got) != 4 {
			t.Errorf("%s appears %d times, want once per rendition", flag, len(got))
			continue
		}
		for _, g := range got {
			if g != want {
				t.Errorf("%s = %q, want %q", flag, g, want)
			}
		}
	}
	// Per-rendition rate control from the ladder.
	if got := argValues(args, "-maxrate"); !slices.Equal(got, []string{"2500k", "1200k", "700k", "350k"}) {
		t.Errorf("-maxrate = %v", got)
	}
	if got := argValues(args, "-bufsize"); !slices.Equal(got, []string{"5000k", "2400k", "1400k", "700k"}) {
		t.Errorf("-bufsize = %v", got)
	}
	if got := argValues(args, "-crf"); !slices.Equal(got, []string{"23", "23", "23", "23"}) {
		t.Errorf("-crf = %v", got)
	}
	// Each rendition writes into its own directory, with file: URLs only.
	maps := argValues(args, "-map")
	if len(maps) != 8 || maps[0] != "[v0]" || maps[1] != "0:1" || maps[2] != "[v1]" {
		t.Errorf("-map = %v", maps)
	}
	if got := argValues(args, "-hls_segment_filename"); got[0] != "file:/work/job/out/720p/seg_%d.m4s" || got[3] != "file:/work/job/out/240p/seg_%d.m4s" {
		t.Errorf("-hls_segment_filename = %v", got)
	}
	if args[len(args)-1] != "file:/work/job/out/240p/playlist.m3u8" {
		t.Errorf("last argument = %q", args[len(args)-1])
	}
	for _, flag := range []string{"-nostdin", "-progress", "-protocol_whitelist"} {
		if !slices.Contains(args, flag) {
			t.Errorf("missing %s", flag)
		}
	}
	// Segments are a whole number of GOPs.
	if SegmentSeconds%KeyframeSeconds != 0 {
		t.Error("segment length must be a multiple of the keyframe interval")
	}
}

func TestTranscodeArgsSourceWithoutAudioAndNTSC(t *testing.T) {
	spec := testSpec()
	spec.Info.Audio = nil
	spec.Info.Video.FrameRate = 30000.0 / 1001
	spec.Renditions = Ladder(spec.Info)
	args, err := TranscodeArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(args, "-c:a") || slices.Contains(args, "-b:a") {
		t.Error("audio encoder arguments for a source without audio")
	}
	if got := argValues(args, "-map"); len(got) != 4 {
		t.Errorf("-map = %v, want only the video branches", got)
	}
	if fg := argValues(args, "-filter_complex")[0]; !strings.HasPrefix(fg, "[0:0]fps=30000/1001,split=4") {
		t.Errorf("filter graph %q", fg)
	}
	if got := argValues(args, "-g"); got[0] != "60" {
		t.Errorf("-g = %v", got)
	}
}

func TestTranscodeArgsRefusesBadInput(t *testing.T) {
	spec := testSpec()
	for name, mod := range map[string]func(*TranscodeSpec){
		"relative source": func(s *TranscodeSpec) { s.Source = "source" },
		"relative out":    func(s *TranscodeSpec) { s.OutDir = "out" },
		"no video":        func(s *TranscodeSpec) { s.Info.Video = nil },
		"no renditions":   func(s *TranscodeSpec) { s.Renditions = nil },
		"odd size":        func(s *TranscodeSpec) { s.Renditions = []Rendition{{Name: "x", Width: 3, Height: 2}} },
	} {
		s := spec
		mod(&s)
		if _, err := TranscodeArgs(s); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseProgressLine(t *testing.T) {
	for line, want := range map[string]time.Duration{
		"out_time_us=18000000": 18 * time.Second, "out_time_us=0": 0, "out_time_us=1500000": 1500 * time.Millisecond,
	} {
		if got, ok := ParseProgressLine(line); !ok || got != want {
			t.Errorf("%q = %v, %v; want %v", line, got, ok, want)
		}
	}
	for _, line := range []string{"out_time_us=N/A", "out_time_us=-5", "out_time_ms=1", "progress=end", "", "out_time_us=99999999999999999999"} {
		if _, ok := ParseProgressLine(line); ok {
			t.Errorf("%q parsed", line)
		}
	}
}

func TestProgressWriterSplitsLinesAcrossWrites(t *testing.T) {
	var got []time.Duration
	w := progressWriter(func(d time.Duration) { got = append(got, d) })
	chunks := []string{"frame=1\nout_time", "_us=2000000\nprogress=con", "tinue\nout_time_us=4000000\n", "out_time_us=6000000"}
	for _, c := range chunks {
		if n, err := w.Write([]byte(c)); err != nil || n != len(c) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second} // the last line has no newline yet
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// A hostile, endless line neither grows memory nor fails the write.
	big := make([]byte, 10*maxProgressLine)
	for i := range big {
		big[i] = 'x'
	}
	if n, err := w.Write(big); err != nil || n != len(big) {
		t.Fatalf("Write(big) = %d, %v", n, err)
	}
	if n, err := w.Write([]byte("\nout_time_us=8000000\n")); err != nil || n == 0 {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != 8*time.Second {
		t.Errorf("did not recover after a long line: %v", got)
	}
}

const sampleFFmpegPlaylist = `#EXTM3U
#EXT-X-VERSION:7
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:1
#EXT-X-PLAYLIST-TYPE:VOD
#EXT-X-INDEPENDENT-SEGMENTS
#EXT-X-MAP:URI="init.mp4"
#EXTINF:6.000000,
seg_1.m4s
#EXTINF:6.000000,
seg_2.m4s
#EXTINF:2.002000,
seg_3.m4s
#EXT-X-ENDLIST
`

func writeRendition(t *testing.T, playlist string, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PlaylistFile), []byte(playlist), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReadRenditionOutput(t *testing.T) {
	dir := writeRendition(t, sampleFFmpegPlaylist, "init.mp4", "seg_1.m4s", "seg_2.m4s", "seg_3.m4s")
	out, err := ReadRenditionOutput(dir, Rendition{Name: "720p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Segments) != 3 || out.Segments[0].Index != 0 || out.Segments[2].Index != 2 ||
		out.Segments[2].Duration != 2002*time.Millisecond || out.Segments[1].Size != 4 ||
		out.Segments[0].Path != filepath.Join(dir, "seg_1.m4s") || out.InitPath != filepath.Join(dir, "init.mp4") {
		t.Fatalf("unexpected output %+v", out)
	}
}

func TestReadRenditionOutputRejectsBrokenOutput(t *testing.T) {
	all := []string{"init.mp4", "seg_1.m4s", "seg_2.m4s", "seg_3.m4s"}
	for name, tc := range map[string]struct {
		playlist string
		files    []string
	}{
		"missing segment":   {sampleFFmpegPlaylist, []string{"init.mp4", "seg_1.m4s", "seg_3.m4s"}},
		"missing init":      {sampleFFmpegPlaylist, all[1:]},
		"orphan segment":    {sampleFFmpegPlaylist, append([]string{"seg_9.m4s"}, all...)},
		"no segments":       {"#EXTM3U\n#EXT-X-ENDLIST\n", []string{"init.mp4"}},
		"bad duration":      {strings.Replace(sampleFFmpegPlaylist, "6.000000", "soon", 1), all},
		"name with a path":  {strings.Replace(sampleFFmpegPlaylist, "seg_2.m4s", "../seg_2.m4s", 1), all},
		"not contiguous":    {strings.Replace(sampleFFmpegPlaylist, "seg_2.m4s", "seg_4.m4s", 1), append([]string{"seg_4.m4s"}, all...)},
		"segment no length": {strings.Replace(sampleFFmpegPlaylist, "#EXTINF:6.000000,\nseg_1.m4s", "seg_1.m4s", 1), all},
	} {
		dir := writeRendition(t, tc.playlist, tc.files...)
		if _, err := ReadRenditionOutput(dir, Rendition{Name: "720p"}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A symlink in place of a segment is refused.
	dir := writeRendition(t, sampleFFmpegPlaylist, "init.mp4", "seg_1.m4s", "seg_3.m4s")
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "seg_2.m4s")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := ReadRenditionOutput(dir, Rendition{Name: "720p"}); err == nil {
		t.Error("a symlinked segment was accepted")
	}
}

func TestCheckAligned(t *testing.T) {
	mk := func(name string, ms ...int) RenditionOutput {
		o := RenditionOutput{Rendition: Rendition{Name: name}}
		for i, m := range ms {
			o.Segments = append(o.Segments, SegmentFile{Index: i, Duration: time.Duration(m) * time.Millisecond})
		}
		return o
	}
	a := mk("720p", 6000, 6000, 2002)
	if err := CheckAligned([]RenditionOutput{a, mk("480p", 6000, 6000, 2002), mk("240p", 6001, 6000, 2002)}, 2*time.Millisecond); err != nil {
		t.Errorf("aligned renditions rejected: %v", err)
	}
	if err := CheckAligned([]RenditionOutput{a, mk("480p", 6000, 6000)}, time.Millisecond); err == nil {
		t.Error("different segment counts accepted")
	}
	if err := CheckAligned([]RenditionOutput{a, mk("480p", 6000, 4000, 4002)}, time.Millisecond); err == nil {
		t.Error("different cut points accepted")
	}
	if err := CheckAligned([]RenditionOutput{a}, 0); err != nil {
		t.Error("a single rendition is trivially aligned")
	}
}
