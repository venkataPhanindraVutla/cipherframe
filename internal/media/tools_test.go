package media

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Listings in the format FFmpeg 9 prints.
const (
	fullEncoders = `Encoders:
 V..... = Video
 A..... = Audio
 ------
 V....D libx264              libx264 H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10 (codec h264)
 A....D aac                  AAC (Advanced Audio Coding)
`
	fullDecoders = `Decoders:
 V..... = Video
 ------
 V....D h264                 H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10
 VFS..D hevc                 HEVC (High Efficiency Video Coding)
 V....D vp8                  On2 VP8
 V....D vp9                  Google VP9
 V....D libdav1d             dav1d AV1 decoder by VideoLAN (codec av1)
 A....D aac                  AAC (Advanced Audio Coding)
 A....D opus                 Opus
 A....D mp3float             MP3 (MPEG audio layer 3) (codec mp3)
`
	fullMuxers = `File formats:
 D. = Demuxing supported
 .E = Muxing supported
 --
  E hls             Apple HTTP Live Streaming
  E mp4             MP4 (MPEG-4 Part 14)
  E null            raw null video
`
	fullDemuxers = `File formats:
 D. = Demuxing supported
 .E = Muxing supported
 --
 D  matroska,webm   Matroska / WebM
 D  mov,mp4,m4a,3gp,3g2,mj2 QuickTime / MOV
`
	fullProtocols = `Supported file protocols:
Input:
  file
  pipe
Output:
  file
  pipe
`
	fullFilters = `Filters:
  T.. = Timeline support
 ... scale             V->V       Scale the input video size.
 ... format            V->V       Convert the input video to one of the specified pixel formats.
 ... aresample         A->A       Resample audio data.
 ... null              V->V       Pass the source unchanged to the output.
 ... anull             A->A       Pass the source unchanged to the output.
 ... setsar            V->V       Set the pixel sample aspect ratio.
 ... fps               V->V       Force constant framerate.
`
)

// fakeFFmpeg writes a shell script that answers each listing flag with the given text.
func fakeFFmpeg(t *testing.T, listings map[string]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script fakes need a POSIX shell")
	}
	var b strings.Builder
	b.WriteString("#!/bin/sh\ncase \"$2\" in\n")
	for flag, text := range listings {
		b.WriteString("  " + flag + ")\n    cat <<'LISTING_END'\n" + text + "LISTING_END\n    ;;\n")
	}
	b.WriteString("  *) exit 0 ;;\nesac\n")
	path := filepath.Join(t.TempDir(), "ffmpeg")
	if err := os.WriteFile(path, []byte(b.String()), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	return path
}

func fullListings() map[string]string {
	return map[string]string{
		"-encoders": fullEncoders, "-decoders": fullDecoders, "-muxers": fullMuxers,
		"-demuxers": fullDemuxers, "-protocols": fullProtocols, "-filters": fullFilters,
		"-buildconf": "configuration:\n    --enable-gpl\n", "-version": "ffprobe version 9.0.2\n",
	}
}

func TestCheckCapabilitiesPasses(t *testing.T) {
	ff := fakeFFmpeg(t, fullListings())
	if err := (Tools{FFmpeg: ff, FFprobe: ff}).CheckCapabilities(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCapabilitiesAcceptsLibaomForAV1(t *testing.T) {
	l := fullListings()
	l["-decoders"] = strings.Replace(fullDecoders, "libdav1d", "libaom-av1", 1)
	ff := fakeFFmpeg(t, l)
	if err := (Tools{FFmpeg: ff, FFprobe: ff}).CheckCapabilities(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCapabilitiesReportsEverythingMissing(t *testing.T) {
	l := fullListings()
	l["-encoders"] = " V....D libopenh264 OpenH264\n A....D aac AAC\n"
	l["-muxers"] = "  E mp4  MP4\n"
	// Only the hardware-only native av1 decoder: not enough for software decoding.
	l["-decoders"] = strings.Replace(fullDecoders, "libdav1d", "av1", 1)
	l["-filters"] = strings.Replace(strings.Replace(fullFilters, "scale", "xscale", 1), " fps ", " fpsx ", 1)
	ff := fakeFFmpeg(t, l)
	err := (Tools{FFmpeg: ff, FFprobe: ff}).CheckCapabilities(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"missing encoder(s): libx264",
		"missing muxer(s): hls",
		"missing decoder(s): libdav1d or libaom-av1",
		"missing filter(s): fps, scale",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not contain %q:\n%v", want, err)
		}
	}
}

func TestCheckCapabilitiesMissingBinaries(t *testing.T) {
	ff := fakeFFmpeg(t, fullListings())
	missing := filepath.Join(t.TempDir(), "nope")
	err := (Tools{FFmpeg: ff, FFprobe: missing}).CheckCapabilities(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ffprobe") {
		t.Fatalf("got %v", err)
	}
	err = (Tools{FFmpeg: missing, FFprobe: ff}).CheckCapabilities(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ffmpeg") {
		t.Fatalf("got %v", err)
	}
	err = (Tools{}).CheckCapabilities(context.Background())
	if err == nil {
		t.Fatal("empty Tools must fail")
	}
}

func TestCheckCapabilitiesNotFFmpeg(t *testing.T) {
	// A binary that runs but knows none of the listings (for example /bin/true) lacks everything.
	ff := fakeFFmpeg(t, map[string]string{})
	err := (Tools{FFmpeg: ff, FFprobe: ff}).CheckCapabilities(context.Background())
	if err == nil || !strings.Contains(err.Error(), "libx264") {
		t.Fatalf("got %v", err)
	}
}

func TestParseListing(t *testing.T) {
	got := parseListing([]byte(fullDemuxers), "-demuxers")
	for _, n := range []string{"matroska", "webm", "mov", "mp4"} {
		if !got[n] {
			t.Errorf("demuxer %q not parsed: %v", n, got)
		}
	}
	got = parseListing([]byte(fullProtocols), "-protocols")
	if !got["file"] || !got["pipe"] || got["Input:"] {
		t.Errorf("protocols: %v", got)
	}
	got = parseListing([]byte(fullEncoders), "-encoders")
	if !got["libx264"] || !got["aac"] || got["="] {
		t.Errorf("encoders: %v", got)
	}
}
