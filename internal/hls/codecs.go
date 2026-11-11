package hls

import (
	"bytes"
	"errors"
	"fmt"
)

// The CODECS attribute of the master playlist is derived from the streams FFmpeg actually wrote:
// the AVC decoder configuration record and the AAC elementary stream descriptor in each
// rendition's init segment. Nothing is assumed from the encoder settings, so a build that picked a
// different profile or level is reported truthfully.

// VideoCodec returns the RFC 6381 string of the H.264 track in an init segment, for example
// "avc1.64001f" (profile_idc, constraint flags and level_idc as hex bytes). init is the file
// FFmpeg wrote, so a plain search for the "avcC" box inside an "avc1" sample entry is enough; the
// bounds are still checked so a malformed file gives an error and not a panic.
func VideoCodec(init []byte) (string, error) {
	if !bytes.Contains(init, []byte("avc1")) {
		return "", errors.New("hls: init segment has no avc1 sample entry")
	}
	i := bytes.Index(init, []byte("avcC"))
	if i < 4 {
		return "", errors.New("hls: init segment has no avcC box")
	}
	// avcC box: size(4) "avcC" configurationVersion(1) profile(1) compatibility(1) level(1) ...
	rec := init[i+4:]
	if len(rec) < 4 || rec[0] != 1 {
		return "", errors.New("hls: malformed avcC box")
	}
	return fmt.Sprintf("avc1.%02x%02x%02x", rec[1], rec[2], rec[3]), nil
}

// AudioCodec returns the RFC 6381 string of the AAC track in an init segment, for example
// "mp4a.40.2" (AAC-LC). It reads the audio object type from the AudioSpecificConfig inside the
// "esds" box.
func AudioCodec(init []byte) (string, error) {
	if !bytes.Contains(init, []byte("mp4a")) {
		return "", errors.New("hls: init segment has no mp4a sample entry")
	}
	i := bytes.Index(init, []byte("esds"))
	if i < 4 {
		return "", errors.New("hls: init segment has no esds box")
	}
	// esds: version/flags(4), then MPEG-4 descriptors (ES_Descriptor > DecoderConfigDescriptor >
	// DecoderSpecificInfo), each "tag, expandable length, body".
	d := init[i+4:]
	if len(d) < 4 {
		return "", errors.New("hls: malformed esds box")
	}
	d = d[4:] // version and flags
	tag, body, ok := nextDescriptor(d)
	if !ok || tag != 0x03 || len(body) < 3 {
		return "", errors.New("hls: malformed ES descriptor")
	}
	body = body[2:] // ES_ID
	flags := body[0]
	body = body[1:]
	if flags&0x80 != 0 { // streamDependenceFlag
		if len(body) < 2 {
			return "", errors.New("hls: malformed ES descriptor")
		}
		body = body[2:]
	}
	if flags&0x40 != 0 { // URL_Flag
		if len(body) < 1 || len(body) < 1+int(body[0]) {
			return "", errors.New("hls: malformed ES descriptor")
		}
		body = body[1+int(body[0]):]
	}
	if flags&0x20 != 0 { // OCRstreamFlag
		if len(body) < 2 {
			return "", errors.New("hls: malformed ES descriptor")
		}
		body = body[2:]
	}
	tag, dec, ok := nextDescriptor(body)
	if !ok || tag != 0x04 || len(dec) < 13 {
		return "", errors.New("hls: malformed decoder configuration")
	}
	objectType := dec[0]
	if objectType != 0x40 {
		return "", errors.New("hls: audio is not MPEG-4 AAC")
	}
	tag, asc, ok := nextDescriptor(dec[13:])
	if !ok || tag != 0x05 || len(asc) < 2 {
		return "", errors.New("hls: malformed audio specific config")
	}
	aot := int(asc[0] >> 3)
	if aot == 31 { // escape: the type is 32 plus the next six bits
		aot = 32 + int(asc[0]&0x07)<<3 + int(asc[1]>>5)
	}
	return fmt.Sprintf("mp4a.40.%d", aot), nil
}

// nextDescriptor reads one MPEG-4 descriptor: a tag byte, a length of one to four bytes (seven
// bits each, the high bit marks a continuation) and the body. The rest of the data is not returned
// because the callers descend into the body.
func nextDescriptor(b []byte) (tag byte, body []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, false
	}
	tag = b[0]
	n, off := 0, 1
	for range 4 {
		if off >= len(b) {
			return 0, nil, false
		}
		c := b[off]
		off++
		n = n<<7 | int(c&0x7f)
		if c&0x80 == 0 {
			break
		}
	}
	if n < 0 || off+n > len(b) {
		return 0, nil, false
	}
	return tag, b[off : off+n], true
}
