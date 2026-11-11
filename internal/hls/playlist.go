package hls

import (
	"errors"
	"fmt"
	"math"
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

// RenderMaster returns the canonical master playlist. Variants are listed from the lowest bandwidth
// to the highest, which is the order players that start at the first entry want for a fast start.
func RenderMaster(variants []Variant) (string, error) {
	if len(variants) == 0 {
		return "", errors.New("hls: a master playlist needs at least one variant")
	}
	sorted := append([]Variant(nil), variants...)
	// Insertion sort: a handful of entries, and it keeps the order of equal bandwidths.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].Bandwidth < sorted[j-1].Bandwidth; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
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

// checkURI refuses anything that could break out of a playlist line or an attribute value. URIs
// here are built from fixed names, so this is a guard against programming errors.
func checkURI(u string) error {
	if u == "" || strings.ContainsAny(u, "\"\r\n,\\ ") {
		return errors.New("hls: invalid URI")
	}
	return nil
}
