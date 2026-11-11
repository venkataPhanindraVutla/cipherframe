package hls

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// The session-scoped rewriters below turn the canonical stored playlists (RenderMaster and
// RenderMedia output) into what edge serves for one playback session (ADR 0027, 0030).
//
// They are deliberately strict line rewriters, not general HLS parsers. A stored playlist is
// written by this package, so anything else in it means the object is not what the pipeline
// wrote; the rewriters refuse it instead of passing unknown lines to a player. Only URI lines and
// URI="..." attributes are touched, every other line is copied byte for byte.
//
// URIs are relative, so they resolve under the session path the playlist was fetched from:
//
//	/v1/play/<session>/master.m3u8              variants  <rendition>/media.m3u8
//	/v1/play/<session>/<rendition>/media.m3u8   segments  seg-N.m4s, init.mp4, key ../key
//
// With a non-empty token (ADR 0030, a tenant with token_in_url on) every rewritten URI carries
// "?t=<token>"; without one no URI carries any token.

// Names edge serves under a session path.
const (
	// MediaPlaylistName is the file name of a rendition's media playlist in the session path. The
	// stored object is called playlist.m3u8; the session path names it media.m3u8.
	MediaPlaylistName = "media.m3u8"
	// KeyPathFromRendition is the key URL as seen from a media playlist in a rendition directory:
	// one level up is the session path, where the key endpoint lives.
	KeyPathFromRendition = "../key"

	storedPlaylistName = "playlist.m3u8"
)

// ErrPlaylist is returned (wrapped) for a stored playlist the rewriters refuse. Its text never
// quotes the playlist.
var ErrPlaylist = errors.New("hls: unexpected playlist content")

var (
	reVariantURI = regexp.MustCompile(`^([a-z0-9_]{1,16})/` + regexp.QuoteMeta(storedPlaylistName) + `$`)
	reSegmentURI = regexp.MustCompile(`^seg-(?:0|[1-9][0-9]{0,8})\.m4s$`)
	reTag        = regexp.MustCompile(`^#EXT[A-Z0-9-]*(?::.*)?$`)

	reMap = regexp.MustCompile(`^#EXT-X-MAP:URI="init\.mp4"$`)
	reKey = regexp.MustCompile(`^#EXT-X-KEY:METHOD=AES-128,URI="` + regexp.QuoteMeta(KeyURI) + `",IV=0x[0-9A-F]{32}$`)
	reInf = regexp.MustCompile(`^#EXTINF:[0-9]+\.[0-9]{3},$`)
	// A variant tag has no URI attribute of its own: the URI is the next line.
	reStreamInf = regexp.MustCompile(`^#EXT-X-STREAM-INF:[A-Z-]+=[^,"]+(?:,[A-Z-]+=(?:[^,"]+|"[^"]*"))*$`)
)

// plainMaster and plainMedia are the tags that carry no URI and are copied as they are.
var (
	plainMaster = regexp.MustCompile(`^#(?:EXTM3U|EXT-X-INDEPENDENT-SEGMENTS|EXT-X-VERSION:[0-9]+)$`)
	plainMedia  = regexp.MustCompile(`^#(?:EXTM3U|EXT-X-INDEPENDENT-SEGMENTS|EXT-X-ENDLIST|EXT-X-VERSION:[0-9]+|` +
		`EXT-X-TARGETDURATION:[0-9]+|EXT-X-MEDIA-SEQUENCE:[0-9]+|EXT-X-PLAYLIST-TYPE:VOD)$`)
)

// withToken appends the token query to uri when token is not empty.
func withToken(uri, token string) string {
	if token == "" {
		return uri
	}
	return uri + "?t=" + url.QueryEscape(token)
}

func refuse(line int, what string) error {
	return fmt.Errorf("%w: line %d: %s", ErrPlaylist, line, what)
}

// lines splits a stored playlist into lines. It must start with #EXTM3U and end with one newline,
// and must not contain a carriage return, a NUL or an empty line.
func lines(src string) ([]string, error) {
	if !strings.HasSuffix(src, "\n") || strings.ContainsAny(src, "\r\x00") {
		return nil, fmt.Errorf("%w: bad line endings", ErrPlaylist)
	}
	ls := strings.Split(strings.TrimSuffix(src, "\n"), "\n")
	if ls[0] != "#EXTM3U" {
		return nil, refuse(1, "missing #EXTM3U")
	}
	for i, l := range ls {
		if l == "" {
			return nil, refuse(i+1, "empty line")
		}
	}
	return ls, nil
}

// RewriteMaster rewrites a stored master playlist for a session: every variant URI
// "<rendition>/playlist.m3u8" becomes "<rendition>/media.m3u8", with "?t=<token>" when token is
// not empty. The playlist must hold at least one variant.
func RewriteMaster(src, token string) (string, error) {
	ls, err := lines(src)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	variants := 0
	for i := 0; i < len(ls); i++ {
		l := ls[i]
		switch {
		case plainMaster.MatchString(l):
			b.WriteString(l)
		case reStreamInf.MatchString(l) && !strings.Contains(l, "URI="):
			if i+1 >= len(ls) {
				return "", refuse(i+1, "variant without a URI")
			}
			m := reVariantURI.FindStringSubmatch(ls[i+1])
			if m == nil {
				return "", refuse(i+2, "unexpected variant URI")
			}
			b.WriteString(l)
			b.WriteByte('\n')
			b.WriteString(withToken(m[1]+"/"+MediaPlaylistName, token))
			variants++
			i++
		default:
			return "", refuse(i+1, "unexpected line")
		}
		b.WriteByte('\n')
	}
	if variants == 0 {
		return "", fmt.Errorf("%w: no variants", ErrPlaylist)
	}
	return b.String(), nil
}

// RewriteMedia rewrites a stored media playlist for a session: the key placeholder KeyURI becomes
// KeyPathFromRendition, and the init and media segment URIs keep their names; each of the three
// carries "?t=<token>" when token is not empty. The playlist must hold an init segment and at
// least one media segment.
func RewriteMedia(src, token string) (string, error) {
	ls, err := lines(src)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	maps, segs := 0, 0
	for i := 0; i < len(ls); i++ {
		l := ls[i]
		switch {
		case plainMedia.MatchString(l):
			b.WriteString(l)
		case reMap.MatchString(l):
			b.WriteString(`#EXT-X-MAP:URI="` + withToken("init.mp4", token) + `"`)
			maps++
		case reKey.MatchString(l):
			// The IV is copied as it is; only the URI changes.
			iv := l[strings.LastIndex(l, ",IV=")+1:]
			b.WriteString(`#EXT-X-KEY:METHOD=AES-128,URI="` + withToken(KeyPathFromRendition, token) + `",` + iv)
		case reInf.MatchString(l):
			if i+1 >= len(ls) || !reSegmentURI.MatchString(ls[i+1]) {
				return "", refuse(i+1, "segment without a valid URI")
			}
			b.WriteString(l)
			b.WriteByte('\n')
			b.WriteString(withToken(ls[i+1], token))
			segs++
			i++
		default:
			if reTag.MatchString(l) {
				return "", refuse(i+1, "unexpected tag")
			}
			return "", refuse(i+1, "unexpected line")
		}
		b.WriteByte('\n')
	}
	if maps != 1 || segs == 0 {
		return "", fmt.Errorf("%w: needs one init segment and at least one media segment", ErrPlaylist)
	}
	return b.String(), nil
}
