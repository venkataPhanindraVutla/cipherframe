package hls_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
)

const testToken = "test-fixture-v1.abc_-DEF.1.ghi"

func readTestdata(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name) //nolint:gosec // test data in the package directory
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRewriteGolden(t *testing.T) {
	master, media := readTestdata(t, "master.m3u8.golden"), readTestdata(t, "media.m3u8.golden")
	for _, tc := range []struct {
		name, golden, token string
		fn                  func(string, string) (string, error)
		src                 string
	}{
		{"master header", "session_master_header.m3u8.golden", "", hls.RewriteMaster, master},
		{"master url", "session_master_url.m3u8.golden", testToken, hls.RewriteMaster, master},
		{"media header", "session_media_header.m3u8.golden", "", hls.RewriteMedia, media},
		{"media url", "session_media_url.m3u8.golden", testToken, hls.RewriteMedia, media},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.fn(tc.src, tc.token)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, tc.golden, got)
		})
	}
}

// The header form never contains a token or a query, and the placeholder never survives.
func TestRewriteHeaderModeHasNoQuery(t *testing.T) {
	for _, tc := range []struct {
		src string
		fn  func(string, string) (string, error)
	}{
		{readTestdata(t, "master.m3u8.golden"), hls.RewriteMaster},
		{readTestdata(t, "media.m3u8.golden"), hls.RewriteMedia},
	} {
		got, err := tc.fn(tc.src, "")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(got, "?") || strings.Contains(got, "t=") || strings.Contains(got, hls.KeyURI) {
			t.Fatalf("unexpected content:\n%s", got)
		}
	}
}

func TestRewriteMediaChangesOnlyURIs(t *testing.T) {
	src := readTestdata(t, "media.m3u8.golden")
	got, err := hls.RewriteMedia(src, "")
	if err != nil {
		t.Fatal(err)
	}
	in, out := strings.Split(src, "\n"), strings.Split(got, "\n")
	if len(in) != len(out) {
		t.Fatalf("line count changed: %d -> %d", len(in), len(out))
	}
	for i := range in {
		if in[i] == out[i] {
			continue
		}
		if !strings.Contains(in[i], "URI=") {
			t.Fatalf("line %d changed but has no URI attribute: %q", i+1, in[i])
		}
	}
	if !strings.Contains(got, "IV=0xF0E1D2C3B4A5968778695A4B3C2D1E0F") {
		t.Fatal("IV lost")
	}
}

func TestRewriteRefusesUnexpectedInput(t *testing.T) {
	master, media := readTestdata(t, "master.m3u8.golden"), readTestdata(t, "media.m3u8.golden")
	rep := func(s, old, repl string) string {
		if !strings.Contains(s, old) {
			t.Fatalf("test input does not contain %q", old)
		}
		return strings.Replace(s, old, repl, 1)
	}
	masterCases := map[string]string{
		"empty":               "",
		"no trailing newline": strings.TrimSuffix(master, "\n"),
		"carriage return":     rep(master, "\n", "\r\n"),
		"no header":           strings.TrimPrefix(master, "#EXTM3U\n"),
		"absolute variant":    rep(master, "240p/playlist.m3u8", "https://evil.example/x.m3u8"),
		"traversal variant":   rep(master, "240p/playlist.m3u8", "../240p/playlist.m3u8"),
		"upper rendition":     rep(master, "240p/playlist.m3u8", "240P/playlist.m3u8"),
		"other file":          rep(master, "240p/playlist.m3u8", "240p/other.m3u8"),
		"unknown tag":         rep(master, "#EXT-X-VERSION:7\n", "#EXT-X-VERSION:7\n#EXT-X-SESSION-KEY:METHOD=NONE\n"),
		"URI attribute":       rep(master, "FRAME-RATE=30.000\n240p", "FRAME-RATE=30.000,URI=\"x\"\n240p"),
		"variant no uri":      "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\n",
		"empty line":          rep(master, "#EXT-X-VERSION:7\n", "#EXT-X-VERSION:7\n\n"),
		"no variants":         "#EXTM3U\n#EXT-X-VERSION:7\n",
		"stray uri":           master + "stray.m3u8\n",
	}
	for name, src := range masterCases {
		t.Run("master "+name, func(t *testing.T) {
			if _, err := hls.RewriteMaster(src, ""); !errors.Is(err, hls.ErrPlaylist) {
				t.Fatalf("err = %v, want ErrPlaylist", err)
			}
		})
	}
	mediaCases := map[string]string{
		"empty":            "",
		"foreign key uri":  rep(media, `URI="cipherframe-key"`, `URI="https://keys.example/k"`),
		"key method":       rep(media, "METHOD=AES-128", "METHOD=SAMPLE-AES"),
		"extra key attr":   rep(media, ",IV=", ",KEYFORMAT=\"identity\",IV="),
		"bad iv":           rep(media, "IV=0x000102030405060708090A0B0C0D0E0F", "IV=0x00"),
		"absolute segment": rep(media, "seg-0.m4s", "https://cdn.example/seg-0.m4s"),
		"traversal":        rep(media, "seg-0.m4s", "../seg-0.m4s"),
		"nested":           rep(media, "seg-0.m4s", "a/seg-0.m4s"),
		"segment name":     rep(media, "seg-0.m4s", "seg-x.m4s"),
		"leading zero":     rep(media, "seg-0.m4s", "seg-01.m4s"),
		"wrong init":       rep(media, `URI="init.mp4"`, `URI="other.mp4"`),
		"map byterange":    rep(media, `URI="init.mp4"`, `URI="init.mp4",BYTERANGE="1@0"`),
		"unknown tag":      rep(media, "#EXT-X-ENDLIST", "#EXT-X-DISCONTINUITY\n#EXT-X-ENDLIST"),
		"extinf no uri":    rep(media, "seg-2.m4s\n", ""),
		"no init":          rep(media, "#EXT-X-MAP:URI=\"init.mp4\"\n", ""),
		"two inits":        rep(media, "#EXT-X-MAP:URI=\"init.mp4\"\n", "#EXT-X-MAP:URI=\"init.mp4\"\n#EXT-X-MAP:URI=\"init.mp4\"\n"),
		"no segments":      "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXT-X-ENDLIST\n",
		"stray uri":        rep(media, "#EXT-X-ENDLIST", "stray.m4s\n#EXT-X-ENDLIST"),
	}
	for name, src := range mediaCases {
		t.Run("media "+name, func(t *testing.T) {
			_, err := hls.RewriteMedia(src, "")
			if !errors.Is(err, hls.ErrPlaylist) {
				t.Fatalf("err = %v, want ErrPlaylist", err)
			}
			if strings.Contains(err.Error(), "://") {
				t.Fatalf("error quotes the input: %v", err)
			}
		})
	}
}

func FuzzRewrite(f *testing.F) {
	f.Add(readTestdata(f, "master.m3u8.golden"))
	f.Add(readTestdata(f, "media.m3u8.golden"))
	f.Fuzz(func(t *testing.T, src string) {
		// Whatever the input, an accepted playlist never leaks the placeholder or an absolute URL.
		for _, fn := range []func(string, string) (string, error){hls.RewriteMaster, hls.RewriteMedia} {
			got, err := fn(src, testToken)
			if err != nil {
				continue
			}
			if strings.Contains(got, hls.KeyURI) || strings.Contains(got, "://") {
				t.Fatalf("accepted playlist leaks: %q", got)
			}
		}
	})
}
