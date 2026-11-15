package subtitles

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

const clip = 10 * time.Minute

func mustParse(t *testing.T, in string) *Track {
	t.Helper()
	tr, err := Parse([]byte(in), clip)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tr
}

func wantProblem(t *testing.T, in string) {
	t.Helper()
	_, err := Parse([]byte(in), clip)
	var p *Problem
	if !errors.As(err, &p) {
		t.Fatalf("Parse(%.40q) error = %v, want a Problem", in, err)
	}
}

func TestSRTConvertsToWebVTT(t *testing.T) {
	srt := "1\n00:00:01,000 --> 00:00:02,500\nHello <i>there</i>\n\n2\n00:00:03,000 --> 00:00:04,000\nline one\nline two\n"
	got := string(mustParse(t, srt).WebVTT())
	want := "WEBVTT\n\n00:00:01.000 --> 00:00:02.500\nHello <i>there</i>\n\n00:00:03.000 --> 00:00:04.000\nline one\nline two\n\n"
	if got != want {
		t.Errorf("converted =\n%q\nwant\n%q", got, want)
	}
}

func TestWebVTTIsRewrittenCanonically(t *testing.T) {
	in := "WEBVTT - a title\nKind: captions\n\nSTYLE\n::cue { color: red }\n\nREGION\nid:r\n\nNOTE a comment\nover two lines\n\n" +
		"intro-id\n00:01.000 --> 00:02.000 align:start position:10%\n<v Ann>Hi &amp; bye\n\n01:00:00.000 --> 01:00:01.000\nlate\n"
	tr, err := Parse([]byte(in), 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	want := "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n<v Ann>Hi &amp; bye</v>\n\n01:00:00.000 --> 01:00:01.000\nlate\n\n"
	if got := string(tr.WebVTT()); got != want {
		t.Errorf("canonical form =\n%q\nwant\n%q", got, want)
	}
	// The canonical form reads back to itself.
	again, err := Parse(tr.WebVTT(), 2*time.Hour)
	if err != nil || string(again.WebVTT()) != want {
		t.Errorf("not a fixed point: %v", err)
	}
}

func TestBOMAndLineEndings(t *testing.T) {
	for name, in := range map[string]string{
		"bom":  "\xef\xbb\xbfWEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhi\n",
		"crlf": "WEBVTT\r\n\r\n00:00:01.000 --> 00:00:02.000\r\nhi\r\n",
		"cr":   "WEBVTT\r\r00:00:01.000 --> 00:00:02.000\rhi\r",
		"srt":  "\xef\xbb\xbf1\r\n00:00:01,000 --> 00:00:02,000\r\nhi\r\n",
	} {
		if got := string(mustParse(t, in).WebVTT()); got != "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhi\n\n" {
			t.Errorf("%s: %q", name, got)
		}
	}
	// A BOM anywhere but the start is a character the file may not contain in a cue.
	tr := mustParse(t, "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nh\ufeffi\n")
	if tr.Cues[0].Text != "hi" {
		t.Errorf("inner BOM kept: %q", tr.Cues[0].Text)
	}
}

func TestRejectedFiles(t *testing.T) {
	big := "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n" + strings.Repeat("x", MaxBytes) + "\n"
	manyLines := "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n" + strings.Repeat("a\n", MaxCueLines+1)
	longCue := "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n" + strings.Repeat("x", MaxCueTextRunes+1) + "\n"
	for name, in := range map[string]string{
		"empty":             "",
		"only header":       "WEBVTT\n",
		"not a subtitle":    "hello world\n",
		"binary":            "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhi\x00there\n",
		"invalid utf-8":     "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n\xff\xfe\n",
		"over the size cap": big,
		"huge cue":          longCue,
		"too many lines":    manyLines,
		"negative start":    "WEBVTT\n\n-00:00:01.000 --> 00:00:02.000\nhi\n",
		"negative signed":   "WEBVTT\n\n00:00:-1.000 --> 00:00:02.000\nhi\n",
		"end before start":  "WEBVTT\n\n00:00:05.000 --> 00:00:02.000\nhi\n",
		"zero length":       "WEBVTT\n\n00:00:05.000 --> 00:00:05.000\nhi\n",
		"out of order":      "WEBVTT\n\n00:00:05.000 --> 00:00:06.000\na\n\n00:00:01.000 --> 00:00:02.000\nb\n",
		"past the video":    "WEBVTT\n\n00:09:59.000 --> 00:12:00.000\nhi\n",
		"minutes over 59":   "WEBVTT\n\n00:60:00.000 --> 00:61:00.000\nhi\n",
		"two digit millis":  "WEBVTT\n\n00:00:01.00 --> 00:00:02.00\nhi\n",
		"no end time":       "WEBVTT\n\n00:00:01.000 -->\nhi\n",
		"empty cue text":    "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n<b></b>  \n",
		"tags only":         "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n<ruby>\n",
		"header glued":      "WEBVTTX\n\n00:00:01.000 --> 00:00:02.000\nhi\n",
		"cue without time":  "WEBVTT\n\nid\nhi there\n",
		"huge hour":         "WEBVTT\n\n99:00:00.000 --> 99:00:01.000\nhi\n",
	} {
		t.Run(name, func(t *testing.T) { wantProblem(t, in) })
	}
}

func TestOverlappingCuesAreAccepted(t *testing.T) {
	tr := mustParse(t, "WEBVTT\n\n00:00:01.000 --> 00:00:05.000\na\n\n00:00:02.000 --> 00:00:03.000\nb\n\n00:00:02.000 --> 00:00:03.000\nc\n")
	if len(tr.Cues) != 3 {
		t.Fatalf("cues = %d", len(tr.Cues))
	}
}

func TestEndsWithinTolerance(t *testing.T) {
	if _, err := Parse([]byte("WEBVTT\n\n00:09:58.000 --> 00:10:01.000\nhi\n"), clip); err != nil {
		t.Errorf("a cue ending one second past the video was refused: %v", err)
	}
	if _, err := Parse([]byte("WEBVTT\n\n00:09:58.000 --> 00:10:02.001\nhi\n"), clip); err == nil {
		t.Error("a cue ending past the tolerance was accepted")
	}
}

func TestTooManyCues(t *testing.T) {
	var b strings.Builder
	b.WriteString("WEBVTT\n\n")
	for i := 0; i <= MaxCues; i++ {
		b.WriteString("00:00:01.000 --> 00:00:02.000\nx\n\n")
	}
	if _, err := Parse([]byte(b.String()), clip); err == nil {
		t.Error("a track over the cue cap was accepted")
	}
}

func TestSanitizeMarkup(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain", "plain"},
		{"<b>x</b><i>y</i><u>z</u>", "<b>x</b><i>y</i><u>z</u>"},
		{"<b class=x onclick=evil()>x</b>", "<b>x</b>"},
		{"<script>alert(1)</script>", "alert(1)"},
		{`<img src=x onerror=alert(1)>`, ""},
		{"<a href=\"http://evil\">link</a>", "link"},
		{"<<script>>", "&lt;&gt;"},
		{"a < b > c", "a &lt; b &gt; c"},
		{"1 <2", "1 &lt;2"},
		{"x &amp; y &lt; &#60; &bogus; & z", "x &amp; y &lt; &amp;#60; &amp;bogus; &amp; z"},
		{"<c.loud.big>x</c>", "<c.loud.big>x</c>"},
		{"<c.a-->x</c>", "<c>x</c>"},
		{`<c.x" onmouseover="y>z</c>`, "<c>z</c>"},
		{"<v Ann Lee>hi</v>", "<v Ann Lee>hi</v>"},
		{"<v>nobody</v>", "nobody"},
		{`<v Ann"><script>>hi</v>`, "<v Ann>&gt;hi</v>"},
		{"<v a-->>b</v>", "<v a->&gt;b</v>"},
		{"<lang en-US>hola</lang>", "<lang en-US>hola</lang>"},
		{"<lang x\"y>t</lang>", "t"},
		{"<00:00:01.500>word", "word"},
		{"<ruby>漢<rt>kan</rt></ruby>", "漢kan"},
		{"</b>stray", "stray"},
		{"<b><i>x</b>y", "<b><i>xy</i></b>"},
		{"<b>open", "<b>open</b>"},
		{"a --> b", "a --&gt; b"},
		{"tab\there", "tab here"},
		{"bell\x07 and‮flip ", "bell andflip"},
		{"zero​width", "zero​width"},
	} {
		if got := sanitizeMarkup(c.in); got != c.want {
			t.Errorf("sanitizeMarkup(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeNeverEmitsAnInjectableCue(t *testing.T) {
	hostile := []string{
		"hi\n\n00:00:05.000 --> 00:00:06.000\nforged cue",
		"WEBVTT\n\nNOTE x",
		"<b>" + strings.Repeat("<i>", 100) + "x",
		"<v " + strings.Repeat("a", 5000) + ">x</v>",
		"</b></i></u></v></c></lang></b>",
		"<<<<<<<>>>>>>>",
		"&&&&&&&&amp;&amp",
	}
	for _, in := range hostile {
		tr, err := Parse([]byte("WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n"+in+"\n"), clip)
		if err != nil {
			continue // refusing is fine too
		}
		out := string(tr.WebVTT())
		if strings.Count(out, "-->") != len(tr.Cues) {
			t.Errorf("hostile cue changed the number of cues: %q", out)
		}
		if strings.Contains(out, "\n\n\n") || strings.Contains(strings.Join(strings.Split(tr.Cues[0].Text, "\n"), "|"), "||") {
			t.Errorf("blank line inside a cue: %q", tr.Cues[0].Text)
		}
		again, err := Parse(tr.WebVTT(), clip)
		if err != nil || string(again.WebVTT()) != out {
			t.Errorf("sanitized output is not stable for %q: %v", in, err)
		}
	}
}

func TestTagStateSpansLines(t *testing.T) {
	tr := mustParse(t, "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n<i>one\ntwo</i>\n")
	if got := tr.Cues[0].Text; got != "<i>one\ntwo</i>" {
		t.Errorf("text = %q", got)
	}
}

func TestFromTranscript(t *testing.T) {
	tr, err := FromTranscript([]TranscriptCue{
		{Start: 1, End: 2.5, Text: "Hello <b>& welcome</b>", Speaker: "Ann <script>"},
		{Start: 3, End: 4.0006, Text: "second\n\nline", Speaker: ""},
	}, clip)
	if err != nil {
		t.Fatal(err)
	}
	want := "WEBVTT\n\n00:00:01.000 --> 00:00:02.500\n<v Ann script>Hello &lt;b&gt;&amp; welcome&lt;/b&gt;</v>\n\n00:00:03.000 --> 00:00:04.001\nsecond\nline\n\n"
	if got := string(tr.WebVTT()); got != want {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
}

func TestFromTranscriptRejects(t *testing.T) {
	for name, cues := range map[string][]TranscriptCue{
		"none":        nil,
		"negative":    {{Start: -1, End: 2, Text: "x"}},
		"nan":         {{Start: math.NaN(), End: 2, Text: "x"}},
		"inf":         {{Start: 1, End: math.Inf(1), Text: "x"}},
		"backwards":   {{Start: 5, End: 4, Text: "x"}},
		"unordered":   {{Start: 5, End: 6, Text: "x"}, {Start: 1, End: 2, Text: "y"}},
		"past end":    {{Start: 1, End: 700, Text: "x"}},
		"blank":       {{Start: 1, End: 2, Text: " \n "}},
		"huge":        {{Start: 1, End: 2, Text: strings.Repeat("x", MaxCueTextRunes+1)}},
		"bad utf8":    {{Start: 1, End: 2, Text: "\xff"}},
		"many":        make([]TranscriptCue, MaxCues+1),
		"speaker bad": {{Start: 1, End: 2, Text: "", Speaker: "Ann"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := FromTranscript(cues, clip)
			var p *Problem
			if !errors.As(err, &p) || p.Field != "cues" {
				t.Fatalf("err = %v, want a Problem on cues", err)
			}
		})
	}
}

func TestNormalizeLanguage(t *testing.T) {
	for in, want := range map[string]string{
		"en": "en", "EN": "en", "pt-br": "pt-BR", "zh-hant-tw": "zh-Hant-TW", "es-419": "es-419", "de-DE-1996": "de-DE-1996", "fil": "fil",
	} {
		if got, err := NormalizeLanguage(in); err != nil || got != want {
			t.Errorf("NormalizeLanguage(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "e", "english", "en_US", "en-", "en US", "en\"", "en\nfr", "x-private", "en-u-ca-gregory", strings.Repeat("a", 40), "en-US\x00"} {
		if got, err := NormalizeLanguage(in); err == nil {
			t.Errorf("NormalizeLanguage(%q) = %q, want an error", in, got)
		}
	}
}

func TestCleanLabel(t *testing.T) {
	if got, err := CleanLabel("  English (CC) "); err != nil || got != "English (CC)" {
		t.Errorf("CleanLabel = %q, %v", got, err)
	}
	for _, in := range []string{"", "   ", strings.Repeat("x", MaxLabelRunes+1), "a\nb", "a\"b\r", "a‮b", "a\x00b", "\xff"} {
		if got, err := CleanLabel(in); err == nil && (strings.ContainsAny(got, "\n\r\x00") || in == "" || in == "   ") {
			t.Errorf("CleanLabel(%q) = %q, want an error", in, got)
		}
	}
	if _, err := CleanLabel("a\nb"); err == nil {
		t.Error("a label with a newline was accepted")
	}
}
