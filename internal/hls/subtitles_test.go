package hls

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	subA = "sub_00000000000000000000000001"
	subB = "sub_00000000000000000000000002"
)

const sessionMaster = "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-INDEPENDENT-SEGMENTS\n" +
	"#EXT-X-STREAM-INF:BANDWIDTH=1000,AVERAGE-BANDWIDTH=900,RESOLUTION=640x360,CODECS=\"avc1.64001f,mp4a.40.2\",FRAME-RATE=25.000\n360p/media.m3u8\n" +
	"#EXT-X-STREAM-INF:BANDWIDTH=2000,AVERAGE-BANDWIDTH=1900,RESOLUTION=1280x720,CODECS=\"avc1.64001f,mp4a.40.2\",FRAME-RATE=25.000\n720p/media.m3u8\n"

func TestAddSubtitles(t *testing.T) {
	got, err := AddSubtitles(sessionMaster, []SubtitleTrack{
		{ID: subA, Language: "en", Label: "English", Default: true},
		{ID: subB, Language: "pt-BR", Label: "Português"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	want := "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-INDEPENDENT-SEGMENTS\n" +
		"#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"subs\",NAME=\"English\",LANGUAGE=\"en\",DEFAULT=YES,AUTOSELECT=YES,FORCED=NO,URI=\"subtitles/" + subA + "/media.m3u8\"\n" +
		"#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"subs\",NAME=\"Português\",LANGUAGE=\"pt-BR\",DEFAULT=NO,AUTOSELECT=YES,FORCED=NO,URI=\"subtitles/" + subB + "/media.m3u8\"\n" +
		"#EXT-X-STREAM-INF:BANDWIDTH=1000,AVERAGE-BANDWIDTH=900,RESOLUTION=640x360,CODECS=\"avc1.64001f,mp4a.40.2\",FRAME-RATE=25.000,SUBTITLES=\"subs\"\n360p/media.m3u8\n" +
		"#EXT-X-STREAM-INF:BANDWIDTH=2000,AVERAGE-BANDWIDTH=1900,RESOLUTION=1280x720,CODECS=\"avc1.64001f,mp4a.40.2\",FRAME-RATE=25.000,SUBTITLES=\"subs\"\n720p/media.m3u8\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestAddSubtitlesCarriesTheToken(t *testing.T) {
	got, err := AddSubtitles(sessionMaster, []SubtitleTrack{{ID: subA, Language: "en", Label: "English"}}, "tok.en+/=")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `URI="subtitles/`+subA+`/media.m3u8?t=tok.en%2B%2F%3D"`) {
		t.Errorf("token missing or not escaped:\n%s", got)
	}
}

func TestAddSubtitlesWithoutTracksChangesNothing(t *testing.T) {
	got, err := AddSubtitles(sessionMaster, nil, "tok")
	if err != nil || got != sessionMaster {
		t.Errorf("got %q, %v", got, err)
	}
}

// Labels and languages come from tenants. Nothing in them may end a quoted value, start a line or
// add an attribute.
func TestAddSubtitlesHostileValues(t *testing.T) {
	hostile := []SubtitleTrack{
		{ID: subA, Language: "en", Label: "x\",DEFAULT=YES,URI=\"https://evil/x.m3u8"},
		{ID: subB, Language: "en\"\n#EXT-X-KEY:METHOD=NONE", Label: "line\r\n#EXT-X-ENDLIST\n"},
	}
	got, err := AddSubtitles(sessionMaster, hostile, "")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	media := 0
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "#EXT-X-MEDIA:"):
			media++
			bare := regexp.MustCompile(`"[^"]*"`).ReplaceAllString(l, `""`) // attribute names outside quoted values
			if strings.Count(l, `"`)%2 != 0 || strings.Count(bare, "URI=") != 1 || strings.Count(bare, "DEFAULT=") != 1 {
				t.Errorf("injected attribute or quote: %s", l)
			}
		case strings.HasPrefix(l, "#EXT-X-STREAM-INF:"), l == "360p/media.m3u8", l == "720p/media.m3u8",
			l == "#EXTM3U", l == "#EXT-X-VERSION:7", l == "#EXT-X-INDEPENDENT-SEGMENTS":
		default:
			t.Errorf("an extra line appeared: %q", l)
		}
	}
	if media != 2 {
		t.Errorf("%d EXT-X-MEDIA lines, want 2", media)
	}
	if !strings.Contains(got, `LANGUAGE="und"`) {
		t.Error("a malformed language was not replaced")
	}
	if strings.Contains(got, "https://evil") && !strings.Contains(got, "x',DEFAULT=YES,URI='https://evil") {
		t.Errorf("hostile label not neutralised: %s", got)
	}
}

func TestAddSubtitlesNamesAreUnique(t *testing.T) {
	got, err := AddSubtitles(sessionMaster, []SubtitleTrack{
		{ID: subA, Language: "en", Label: "English"}, {ID: subB, Language: "en", Label: "English"}, {ID: "sub_00000000000000000000000003", Language: "en", Label: "  "},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{`NAME="English"`, `NAME="English (2)"`, `NAME="en"`} {
		if !strings.Contains(got, name) {
			t.Errorf("missing %s in\n%s", name, got)
		}
	}
}

func TestAddSubtitlesRefuses(t *testing.T) {
	for name, tr := range map[string]SubtitleTrack{
		"bad id":       {ID: "sub_x", Language: "en", Label: "a"},
		"traversal id": {ID: "../../sub", Language: "en", Label: "a"},
		"empty id":     {Language: "en", Label: "a"},
	} {
		if _, err := AddSubtitles(sessionMaster, []SubtitleTrack{tr}, ""); !errors.Is(err, ErrPlaylist) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := AddSubtitles("#EXTM3U\n", []SubtitleTrack{{ID: subA, Language: "en", Label: "a"}}, ""); !errors.Is(err, ErrPlaylist) {
		t.Errorf("a master without variants: %v", err)
	}
}

func TestRenderSubtitleMedia(t *testing.T) {
	got, err := RenderSubtitleMedia(90*time.Second+500*time.Millisecond, SubtitleFileURI("t k"))
	if err != nil {
		t.Fatal(err)
	}
	want := "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:91\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:90.500,\ntrack.vtt?t=t+k\n#EXT-X-ENDLIST\n"
	if got != want {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
	if _, err := RenderSubtitleMedia(0, "track.vtt"); err == nil {
		t.Error("a zero duration was accepted")
	}
	if _, err := RenderSubtitleMedia(time.Second, "a\nb"); err == nil {
		t.Error("a URI with a line break was accepted")
	}
}
