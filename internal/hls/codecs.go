package hls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// The CODECS attribute of the master playlist is derived from the streams FFmpeg actually wrote:
// the AVC, HEVC or AV1 decoder configuration record and the AAC elementary stream descriptor in each
// rendition's init segment. Nothing is assumed from the encoder settings, so a build that picked a
// different profile or level is reported truthfully.

// VideoCodec returns the RFC 6381 string of the video track in an init segment: H.264 as
// "avc1.64001f", HEVC as "hvc1.1.6.L120.90", AV1 as "av01.0.08M.08". The sample entry decides which.
func VideoCodec(init []byte) (string, error) {
	switch {
	case bytes.Contains(init, []byte("hvc1")) || bytes.Contains(init, []byte("hev1")):
		return hevcCodec(init)
	case bytes.Contains(init, []byte("av01")):
		return av1Codec(init)
	}
	return avcCodec(init)
}

// avcCodec returns the string of the H.264 track, for example "avc1.64001f" (profile_idc,
// constraint flags and level_idc as hex bytes). init is the file FFmpeg wrote, so a plain search for
// the "avcC" box inside an "avc1" sample entry is enough; the bounds are still checked so a
// malformed file gives an error and not a panic.
func avcCodec(init []byte) (string, error) {
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

// hevcCodec returns the string of the HEVC track from its "hvcC" box (ISO/IEC 14496-15 annex E):
// the sample entry, the profile space (a letter, when not 0) and profile_idc, the 32 profile
// compatibility flags in reverse bit order as hex, the tier (L or H) and level_idc, then the six
// constraint bytes in hex with trailing zero bytes left off, for example "hvc1.1.6.L120.90".
func hevcCodec(init []byte) (string, error) {
	entry := "hvc1"
	if !bytes.Contains(init, []byte(entry)) {
		entry = "hev1"
	}
	i := bytes.Index(init, []byte("hvcC"))
	if i < 4 {
		return "", errors.New("hls: init segment has no hvcC box")
	}
	// hvcC: configurationVersion(1), profile_space(2) tier(1) profile_idc(5), compatibility flags(4),
	// constraint indicator flags(6), level_idc(1), ...
	rec := init[i+4:]
	if len(rec) < 13 || rec[0] != 1 {
		return "", errors.New("hls: malformed hvcC box")
	}
	space := ""
	if sp := rec[1] >> 6; sp > 0 {
		space = string(rune('A' + sp - 1))
	}
	tier := "L"
	if rec[1]&0x20 != 0 {
		tier = "H"
	}
	compat := bits.Reverse32(binary.BigEndian.Uint32(rec[2:6]))
	constraints := rec[6:12]
	n := len(constraints)
	for n > 0 && constraints[n-1] == 0 {
		n--
	}
	out := fmt.Sprintf("%s.%s%d.%x.%s%d", entry, space, rec[1]&0x1f, compat, tier, rec[12])
	for _, c := range constraints[:n] {
		out += fmt.Sprintf(".%x", c)
	}
	return out, nil
}

// av1Codec returns the string of the AV1 track from its "av1C" box: "av01.<profile>.<level><tier>.<bit
// depth>", for example "av01.0.08M.08" (profile 0, level index 8 which is level 4.0, Main tier, 8 bit).
// The optional parameters that follow are left off, which the AV1 ISOBMFF binding allows when they have
// their default values (4:2:0, not monochrome), as every rendition here does.
func av1Codec(init []byte) (string, error) {
	i := bytes.Index(init, []byte("av1C"))
	if i < 4 {
		return "", errors.New("hls: init segment has no av1C box")
	}
	// av1C: marker(1) version(7), seq_profile(3) seq_level_idx_0(5), seq_tier_0(1) high_bitdepth(1)
	// twelve_bit(1) monochrome(1) subsampling_x(1) subsampling_y(1) chroma_sample_position(2), ...
	rec := init[i+4:]
	if len(rec) < 4 || rec[0] != 0x81 {
		return "", errors.New("hls: malformed av1C box")
	}
	depth := 8
	switch {
	case rec[2]&0x40 != 0 && rec[2]&0x20 != 0:
		depth = 12
	case rec[2]&0x40 != 0:
		depth = 10
	}
	tier := "M"
	if rec[2]&0x80 != 0 {
		tier = "H"
	}
	return fmt.Sprintf("av01.%d.%02d%s.%02d", rec[1]>>5, rec[1]&0x1f, tier, depth), nil
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
