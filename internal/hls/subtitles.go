package hls

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Subtitles are listed in the session's master playlist as one EXT-X-MEDIA group of type SUBTITLES
// (RFC 8216 section 4.3.4.1), each with a media playlist of one WebVTT segment (ADR 0044). They are
// added to the already rewritten master, and every value that comes from a tenant (the label) is
// made safe for a quoted attribute: HLS has no escape for a quote or a line break, so they cannot
// be written at all.

// Names under the session path.
const (
	// SubtitleGroup is the GROUP-ID of the subtitle renditions.
	SubtitleGroup = "subs"
	// SubtitlePlaylistName and SubtitleFileName are the last path elements of a track's media
	// playlist and of its WebVTT file; the element before them is the track ID, under "subtitles/".
	SubtitlePlaylistName = "media.m3u8"
	SubtitleFileName     = "track.vtt"
	subtitleDir          = "subtitles/"
)

var (
	reSubtitleID = regexp.MustCompile(`^sub_[0-9a-hjkmnp-tv-z]{26}$`)
	reLanguage   = regexp.MustCompile(`^[A-Za-z0-9]{1,8}(-[A-Za-z0-9]{1,8}){0,4}$`)
)

// SubtitleTrack is a track as the master playlist lists it.
type SubtitleTrack struct {
	ID       string // "sub_..."
	Language string // BCP 47
	Label    string
	Default  bool
}

// attrString makes s safe inside a quoted attribute value: control characters and line breaks are
// dropped and a double quote becomes a single quote.
func attrString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteByte('\'')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029:
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// AddSubtitles adds the tracks to a master playlist already rewritten for a session: one
// EXT-X-MEDIA line per track before the first variant, and SUBTITLES="subs" on every variant. Each
// track's URI is "subtitles/<id>/media.m3u8", with "?t=<token>" when token is not empty. With no
// tracks the playlist is returned as it is. A track with a malformed ID is refused; a language
// that is not a language tag is written as "und", and a label that is empty after cleaning is
// replaced by the language. Two tracks never share a NAME (RFC 8216 requires it).
func AddSubtitles(master string, tracks []SubtitleTrack, token string) (string, error) {
	if len(tracks) == 0 {
		return master, nil
	}
	var media strings.Builder
	used := map[string]bool{}
	for _, t := range tracks {
		if !reSubtitleID.MatchString(t.ID) {
			return "", fmt.Errorf("%w: bad subtitle track ID", ErrPlaylist)
		}
		lang := t.Language
		if !reLanguage.MatchString(lang) {
			lang = "und"
		}
		name := attrString(t.Label)
		if name == "" {
			name = lang
		}
		unique := name
		for n := 2; used[unique]; n++ {
			unique = name + " (" + strconv.Itoa(n) + ")"
		}
		used[unique] = true
		def := "NO"
		if t.Default {
			def = "YES"
		}
		// The values are quoted by hand: HLS has no escapes, and none of them can hold a quote.
		media.WriteString(`#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="` + SubtitleGroup + `",NAME="` + unique + `",LANGUAGE="` + lang +
			`",DEFAULT=` + def + `,AUTOSELECT=YES,FORCED=NO,URI="` + withToken(subtitleDir+t.ID+"/"+SubtitlePlaylistName, token) + "\"\n")
	}
	var b strings.Builder
	added := false
	for _, l := range strings.SplitAfter(master, "\n") {
		if strings.HasPrefix(l, "#EXT-X-STREAM-INF:") {
			if !added {
				b.WriteString(media.String())
				added = true
			}
			l = strings.TrimSuffix(l, "\n") + ",SUBTITLES=\"" + SubtitleGroup + "\"\n"
		}
		b.WriteString(l)
	}
	if !added {
		return "", fmt.Errorf("%w: no variants to attach subtitles to", ErrPlaylist)
	}
	return b.String(), nil
}

// RenderSubtitleMedia returns the media playlist of one track: a single WebVTT segment of the
// given duration. file is the segment URI relative to the playlist (the caller adds the token).
func RenderSubtitleMedia(duration time.Duration, file string) (string, error) {
	if duration <= 0 {
		return "", fmt.Errorf("%w: a subtitle playlist needs a positive duration", ErrPlaylist)
	}
	if err := checkURI(file); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("#EXTM3U\n")
	b.WriteString("#EXT-X-VERSION:3\n")
	b.WriteString("#EXT-X-TARGETDURATION:" + strconv.Itoa(int(math.Ceil(duration.Seconds()))) + "\n")
	b.WriteString("#EXT-X-MEDIA-SEQUENCE:0\n")
	b.WriteString("#EXT-X-PLAYLIST-TYPE:VOD\n")
	fmt.Fprintf(&b, "#EXTINF:%.3f,\n%s\n", duration.Seconds(), file)
	b.WriteString("#EXT-X-ENDLIST\n")
	return b.String(), nil
}

// SubtitleFileURI is the URI of a track's WebVTT file as written in its media playlist.
func SubtitleFileURI(token string) string { return withToken(SubtitleFileName, token) }
