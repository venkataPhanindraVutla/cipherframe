package hls

import (
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// KeyURI is the placeholder every stored media playlist carries in its EXT-X-KEY tags. It is not a
// URL. The edge (M4) rewrites it per playback session to a session-bound key URL when it serves a
// playlist, so what is stored in the delivery bucket never contains a token, a session or a real
// key location. A player that was handed a stored playlist as is could not fetch a key.
const KeyURI = "cipherframe-key"

// Segment is one encrypted media segment of a rendition.
type Segment struct {
	// URI is relative to the media playlist, for example "seg-0.m4s".
	URI      string
	Duration time.Duration
	IV       IV
}

// MediaPlaylist describes one rendition: an init segment and its encrypted media segments.
type MediaPlaylist struct {
	// InitURI is the init segment's URI relative to the playlist, for example "init.mp4".
	InitURI  string
	Segments []Segment
}

// Variant is one rendition in the master playlist.
type Variant struct {
	// URI is relative to the master playlist, for example "720p/playlist.m3u8".
	URI string
	// Bandwidth is the peak segment bitrate in bits per second and AverageBandwidth the average
	// over the whole rendition.
	Bandwidth        int64
	AverageBandwidth int64
	Width, Height    int
	// Codecs is the RFC 6381 list, for example "avc1.64001f,mp4a.40.2".
	Codecs string
	// FrameRate is in frames per second.
	FrameRate float64
}

// playlistVersion 7 is the lowest that allows fMP4 media with EXT-X-MAP in a playlist that has no
// I-frames-only tag (RFC 8216 section 7).
const playlistVersion = 7

// RenderMedia returns the canonical VOD media playlist of a rendition.
//
// The EXT-X-MAP tag comes before the first EXT-X-KEY on purpose. RFC 8216 section 4.3.2.4 says a
// key applies to the init segments declared "between it and the next EXT-X-KEY tag", so an init
// segment declared before any key is not encrypted. The init segment holds codec configuration only
// (no media samples), and players need it before they have a key. Every segment then carries its own
// EXT-X-KEY with its own IV.
func RenderMedia(p MediaPlaylist) (string, error) {
	if p.InitURI == "" || len(p.Segments) == 0 {
		return "", errors.New("hls: a media playlist needs an init segment and at least one segment")
	}
	var maxDur time.Duration
	for _, s := range p.Segments {
		if s.URI == "" || s.Duration <= 0 {
			return "", errors.New("hls: every segment needs a URI and a positive duration")
		}
		if err := checkURI(s.URI); err != nil {
			return "", err
		}
		maxDur = max(maxDur, s.Duration)
	}
	if err := checkURI(p.InitURI); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("#EXTM3U\n")
	b.WriteString("#EXT-X-VERSION:" + strconv.Itoa(playlistVersion) + "\n")
	b.WriteString("#EXT-X-TARGETDURATION:" + strconv.Itoa(int(math.Ceil(maxDur.Seconds()))) + "\n")
	b.WriteString("#EXT-X-MEDIA-SEQUENCE:0\n")
	b.WriteString("#EXT-X-PLAYLIST-TYPE:VOD\n")
	b.WriteString("#EXT-X-INDEPENDENT-SEGMENTS\n")
	b.WriteString("#EXT-X-MAP:URI=\"" + p.InitURI + "\"\n")
	for _, s := range p.Segments {
		fmt.Fprintf(&b, "#EXT-X-KEY:METHOD=AES-128,URI=%q,IV=0x%X\n", KeyURI, s.IV[:])
		fmt.Fprintf(&b, "#EXTINF:%.3f,\n%s\n", s.Duration.Seconds(), s.URI)
	}
	b.WriteString("#EXT-X-ENDLIST\n")
	return b.String(), nil
}

// ParseMedia reads a stored media playlist, the form RenderMedia writes: it takes the init segment,
// and for every segment its IV, duration and URI. Anything else (another key method, a missing IV,
// a tag out of place) is an error, so a playlist that was not made by Cipherframe is refused rather
// than half-read. Durations are kept to the millisecond RenderMedia writes.
func ParseMedia(src string) (MediaPlaylist, error) {
	var (
		p     MediaPlaylist
		iv    IV
		hasIV bool
		dur   time.Duration
	)
	for line := range strings.SplitSeq(strings.TrimSuffix(src, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "#EXT-X-MAP:URI=\""):
			uri, ok := strings.CutSuffix(strings.TrimPrefix(line, "#EXT-X-MAP:URI=\""), "\"")
			if !ok || p.InitURI != "" {
				return MediaPlaylist{}, errors.New("hls: malformed EXT-X-MAP")
			}
			p.InitURI = uri
		case strings.HasPrefix(line, "#EXT-X-KEY:METHOD=AES-128,"):
			_, hexIV, ok := strings.Cut(line, ",IV=0x")
			raw, err := hex.DecodeString(hexIV)
			if !ok || err != nil || len(raw) != IVBytes {
				return MediaPlaylist{}, errors.New("hls: malformed EXT-X-KEY")
			}
			copy(iv[:], raw)
			hasIV = true
		case strings.HasPrefix(line, "#EXTINF:"):
			secs, ok := strings.CutSuffix(strings.TrimPrefix(line, "#EXTINF:"), ",")
			f, err := strconv.ParseFloat(secs, 64)
			if !ok || err != nil || f <= 0 || f > 1e6 {
				return MediaPlaylist{}, errors.New("hls: malformed EXTINF")
			}
			dur = time.Duration(math.Round(f*1000)) * time.Millisecond
		case strings.HasPrefix(line, "#"): // headers, ENDLIST: nothing to keep
		default:
			if !hasIV || dur == 0 {
				return MediaPlaylist{}, errors.New("hls: a segment without its key or duration")
			}
			p.Segments = append(p.Segments, Segment{URI: line, Duration: dur, IV: iv})
			hasIV, dur = false, 0
		}
	}
	if p.InitURI == "" || len(p.Segments) == 0 {
		return MediaPlaylist{}, errors.New("hls: a media playlist needs an init segment and at least one segment")
	}
	return p, nil
}

// RenderMaster returns the canonical master playlist. Variants are listed by codec family, H.264
// first, then HEVC, then AV1, and within a family from the lowest bandwidth to the highest, which is the
// order players that start at the first entry want for a fast start: that entry is always H.264, which
// every player can decode (ADR 0064). With H.264 alone the order is by bandwidth only, as before.
func RenderMaster(variants []Variant) (string, error) {
	if len(variants) == 0 {
		return "", errors.New("hls: a master playlist needs at least one variant")
	}
	// A stable sort keeps the order of equal bandwidths.
	sorted := slices.Clone(variants)
	slices.SortStableFunc(sorted, func(a, b Variant) int {
		return cmp.Or(cmp.Compare(familyRank(a.Codecs), familyRank(b.Codecs)), cmp.Compare(a.Bandwidth, b.Bandwidth))
	})
	var b strings.Builder
	b.WriteString("#EXTM3U\n")
	b.WriteString("#EXT-X-VERSION:" + strconv.Itoa(playlistVersion) + "\n")
	b.WriteString("#EXT-X-INDEPENDENT-SEGMENTS\n")
	for _, v := range sorted {
		if v.URI == "" || v.Bandwidth <= 0 || v.AverageBandwidth <= 0 || v.Width <= 0 || v.Height <= 0 ||
			v.Codecs == "" || v.FrameRate <= 0 {
			return "", errors.New("hls: incomplete variant")
		}
		if err := checkURI(v.URI); err != nil {
			return "", err
		}
		if strings.ContainsAny(v.Codecs, "\"\r\n") {
			return "", errors.New("hls: invalid codecs string")
		}
		fmt.Fprintf(&b, "#EXT-X-STREAM-INF:BANDWIDTH=%d,AVERAGE-BANDWIDTH=%d,RESOLUTION=%dx%d,CODECS=%q,FRAME-RATE=%.3f\n%s\n",
			v.Bandwidth, v.AverageBandwidth, v.Width, v.Height, v.Codecs, v.FrameRate, v.URI)
	}
	return b.String(), nil
}

// familyRank orders the codec families of a CODECS string: H.264, HEVC, AV1, anything else last.
func familyRank(codecs string) int {
	switch {
	case strings.HasPrefix(codecs, "avc1"):
		return 0
	case strings.HasPrefix(codecs, "hvc1"), strings.HasPrefix(codecs, "hev1"):
		return 1
	case strings.HasPrefix(codecs, "av01"):
		return 2
	}
	return 3
}

// checkURI refuses anything that could break out of a playlist line or an attribute value. URIs
// here are built from fixed names, so this is a guard against programming errors.
func checkURI(u string) error {
	if u == "" || strings.ContainsAny(u, "\"\r\n,\\ ") {
		return errors.New("hls: invalid URI")
	}
	return nil
}
