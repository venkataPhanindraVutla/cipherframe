package hls

import "strings"

// Names under the session path of the thumbnail objects (ADR 0046). They are fixed, one of each per
// session, so a player finds them by replacing "master.m3u8" in the master playlist's URL.
const (
	PosterName         = "poster.jpg"
	SpriteName         = "sprite.jpg"
	ThumbnailTrackName = "thumbnails.vtt"
)

// RewriteThumbnailTrack returns the stored WebVTT thumbnail track for a session: with a token (the
// tenant allows tokens in URLs) each cue's sprite reference gets "?t=<token>", so a player that
// cannot send headers can fetch the sprite named in the cue. A line that is not a sprite reference
// is left as it is.
func RewriteThumbnailTrack(vtt, token string) string {
	if token == "" {
		return vtt
	}
	var b strings.Builder
	for _, l := range strings.SplitAfter(vtt, "\n") {
		if rest, ok := strings.CutPrefix(l, SpriteName+"#"); ok {
			l = withToken(SpriteName, token) + "#" + rest
		}
		b.WriteString(l)
	}
	return b.String()
}
