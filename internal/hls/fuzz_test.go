package hls_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
)

// A URI the session rewriters may emit: a relative name under the session path, optionally with
// the escaped token query. Nothing else (no scheme, no "//", no "..", no other directory) is
// allowed, whatever the stored playlist or the token held.
var (
	reAllowedURI = regexp.MustCompile(`^(?:seg-[0-9]{1,9}\.m4s|init\.mp4|\.\./key|[a-z0-9_]{1,16}/media\.m3u8|` +
		`subtitles/sub_[0-9a-hjkmnp-tv-z]{26}/media\.m3u8)(?:\?t=[A-Za-z0-9._~%+-]*)?$`)
	reURIAttr = regexp.MustCompile(`URI="([^"]*)"`)
)

// checkSessionPlaylist asserts what every rewritten playlist must satisfy: it is still a playlist
// (starts with #EXTM3U, ends with one newline, no empty line, CR or NUL), every URI line and every
// URI attribute stays inside the allowed set, and without a token there is no query at all.
func checkSessionPlaylist(t *testing.T, out, token string) {
	t.Helper()
	if !strings.HasPrefix(out, "#EXTM3U\n") || !strings.HasSuffix(out, "\n") || strings.Contains(out, "\n\n") ||
		strings.ContainsAny(out, "\r\x00") {
		t.Fatalf("output is not a valid playlist: %q", out)
	}
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !strings.HasPrefix(l, "#") && !reAllowedURI.MatchString(l) {
			t.Fatalf("URI line outside the allowed prefix: %q", l)
		}
		for _, m := range reURIAttr.FindAllStringSubmatch(l, -1) {
			if !reAllowedURI.MatchString(m[1]) {
				t.Fatalf("URI attribute outside the allowed prefix: %q", l)
			}
		}
	}
	if token == "" && strings.Contains(out, "?") {
		t.Fatalf("token-less output carries a query: %q", out)
	}
}

func seedRewrite(f *testing.F) {
	for _, n := range []string{"master.m3u8.golden", "media.m3u8.golden"} {
		f.Add(readTestdata(f, n), testToken)
		f.Add(readTestdata(f, n), "")
	}
	f.Add("#EXTM3U\n#EXTINF:6.000,\nhttps://evil.example/seg-0.m4s\n", "")
	f.Add("#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:6.000,\n../../etc/passwd\n", "a&b=c")
}

func FuzzRewriteMaster(f *testing.F) {
	seedRewrite(f)
	f.Fuzz(func(t *testing.T, src, token string) {
		out, err := hls.RewriteMaster(src, token)
		if err != nil {
			return
		}
		checkSessionPlaylist(t, out, token)
	})
}

func FuzzRewriteMedia(f *testing.F) {
	seedRewrite(f)
	f.Fuzz(func(t *testing.T, src, token string) {
		out, err := hls.RewriteMedia(src, token)
		if err != nil {
			return
		}
		checkSessionPlaylist(t, out, token)
	})
}

func FuzzAddSubtitles(f *testing.F) {
	master := readTestdata(f, "session_master_url.m3u8.golden")
	f.Add(master, "sub_00000000000000000000000000", "en", "English", testToken)
	f.Add(master, "sub_00000000000000000000000000", "x\"y", "a\"\nURI=\"https://evil.example/x", "")
	f.Fuzz(func(t *testing.T, base, id, lang, label, token string) {
		if base != master {
			return // the master is a session playlist; only the track fields are attacker-controlled
		}
		out, err := hls.AddSubtitles(base, []hls.SubtitleTrack{{ID: id, Language: lang, Label: label, Default: true}}, token)
		if err != nil {
			return
		}
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "#EXT-X-MEDIA:") {
				ms := reURIAttr.FindAllStringSubmatch(l, -1)
				for _, m := range ms {
					if !reAllowedURI.MatchString(m[1]) {
						t.Fatalf("subtitle URI outside the allowed prefix: %q", l)
					}
				}
				if strings.Count(l, "\"") != 8 || len(ms) != 1 {
					t.Fatalf("attribute injection: %q", l)
				}
			}
		}
	})
}

func FuzzRewriteThumbnailTrack(f *testing.F) {
	f.Add("WEBVTT\n\n00:00:00.000 --> 00:00:05.000\nsprite.jpg#xywh=0,0,160,90\n", testToken)
	f.Fuzz(func(t *testing.T, vtt, token string) {
		out := hls.RewriteThumbnailTrack(vtt, token)
		if token == "" && out != vtt {
			t.Fatal("changed a track without a token")
		}
		if strings.Count(out, "\n") != strings.Count(vtt, "\n") {
			t.Fatal("token escaping changed the line count")
		}
	})
}
