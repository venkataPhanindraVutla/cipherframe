package subtitles

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParse: Parse never panics; an accepted file produces WebVTT with one timing line per cue, no
// blank line run, no script tag, that parses again to the same bytes.
func FuzzParse(f *testing.F) {
	f.Add([]byte("WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhello <b>world</b>\n"))
	f.Add([]byte("1\n00:00:01,000 --> 00:00:02,500\nline one\nline two\n\n2\n00:00:03,000 --> 00:00:04,000\nx\n"))
	f.Add([]byte("\xef\xbb\xbfWEBVTT\r\n\r\nNOTE hi\r\n\r\n00:01.000 --> 00:02.000 align:start\r\n<v Bob>hi</v>\r\n"))
	f.Add([]byte("WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhi\n\n00:00:05.000 --> 00:00:06.000\n<script>alert(1)</script>\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		tr, err := Parse(data, clip)
		if err != nil {
			return
		}
		out := tr.WebVTT()
		if strings.Count(string(out), "-->") != len(tr.Cues) || bytes.Contains(out, []byte("\n\n\n")) {
			t.Fatalf("malformed output: %q", out)
		}
		if strings.Contains(strings.ToLower(string(out)), "<script") {
			t.Fatalf("script tag survived: %q", out)
		}
		again, err := Parse(out, clip)
		if err != nil || !bytes.Equal(again.WebVTT(), out) {
			t.Fatalf("output is not stable: %v", err)
		}
	})
}
