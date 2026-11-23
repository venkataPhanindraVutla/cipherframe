package media

import (
	"encoding/binary"
	"errors"
	"time"
)

// FirstVideoPTS returns the presentation time of the first picture (the earliest of the segment's
// presentation times) of the video track in a fragmented MP4 media segment, read from the segment's
// moof (track fragment decode time plus each sample's composition offset) and the timescale in the
// init segment. It is how far the container holds the video back from the start, which differs by encoder:
// H.264 with B-frames puts its first picture two frames in, an encoder without reordering puts it at zero.
// The worker reads it from the H.264 rendition so the extra codecs can be given the same start
// (TranscodeSpec.TSOffset). Both files are FFmpeg's own output; the bounds are still checked so a
// malformed file gives an error and not a panic.
func FirstVideoPTS(init, segment []byte) (time.Duration, error) {
	trackID, timescale, err := videoTrack(init)
	if err != nil {
		return 0, err
	}
	for typ, body := range boxes(segment) {
		if typ != "moof" {
			continue
		}
		for typ, traf := range boxes(body) {
			if typ != "traf" {
				continue
			}
			if pts, ok, err := trafFirstPTS(traf, trackID); err != nil {
				return 0, err
			} else if ok {
				return time.Duration(float64(pts) / float64(timescale) * float64(time.Second)), nil
			}
		}
	}
	return 0, errors.New("media: the segment has no fragment of the video track")
}

var errMP4 = errors.New("media: malformed MP4 box")

// boxes yields the boxes of b one level deep: type and body. It stops at the first box that does not fit.
func boxes(b []byte) func(yield func(string, []byte) bool) {
	return func(yield func(string, []byte) bool) {
		for len(b) >= 8 {
			size, hdr := uint64(binary.BigEndian.Uint32(b)), 8
			switch size {
			case 1:
				if len(b) < 16 {
					return
				}
				size, hdr = binary.BigEndian.Uint64(b[8:]), 16
			case 0:
				size = uint64(len(b))
			}
			if size < uint64(hdr) || size > uint64(len(b)) {
				return
			}
			if !yield(string(b[4:8]), b[hdr:size]) {
				return
			}
			b = b[size:]
		}
	}
}

// videoTrack finds the video track of an init segment: its ID and its media timescale.
func videoTrack(init []byte) (id, timescale uint32, err error) {
	for typ, moov := range boxes(init) {
		if typ != "moov" {
			continue
		}
		for typ, trak := range boxes(moov) {
			if typ != "trak" {
				continue
			}
			var tid, scale uint32
			video := false
			for typ, body := range boxes(trak) {
				switch typ {
				case "tkhd":
					if len(body) >= 24 {
						tid = binary.BigEndian.Uint32(body[12:])
						if body[0] == 1 {
							tid = binary.BigEndian.Uint32(body[20:])
						}
					}
				case "mdia":
					for typ, m := range boxes(body) {
						switch typ {
						case "mdhd":
							if len(m) >= 24 {
								scale = binary.BigEndian.Uint32(m[12:])
								if m[0] == 1 {
									scale = binary.BigEndian.Uint32(m[20:])
								}
							}
						case "hdlr":
							video = len(m) >= 12 && string(m[8:12]) == "vide"
						}
					}
				}
			}
			if video && tid != 0 && scale != 0 {
				return tid, scale, nil
			}
		}
	}
	return 0, 0, errors.New("media: the init segment has no video track")
}

// trafFirstPTS reads one track fragment: ok is false when it belongs to another track.
func trafFirstPTS(traf []byte, trackID uint32) (pts int64, ok bool, err error) {
	var (
		defaultDuration uint32
		base            uint64
		sawTfhd         bool
		match           bool
	)
	best := int64(1<<63 - 1)
	for typ, body := range boxes(traf) {
		switch typ {
		case "tfhd":
			if len(body) < 8 {
				return 0, false, errMP4
			}
			flags := binary.BigEndian.Uint32(body) & 0xffffff
			match, sawTfhd = binary.BigEndian.Uint32(body[4:]) == trackID, true
			off := 8
			for _, f := range []struct {
				bit  uint32
				size int
			}{{0x1, 8}, {0x2, 4}} {
				if flags&f.bit != 0 {
					off += f.size
				}
			}
			if flags&0x8 != 0 {
				if len(body) < off+4 {
					return 0, false, errMP4
				}
				defaultDuration = binary.BigEndian.Uint32(body[off:])
			}
		case "tfdt":
			if len(body) < 8 {
				return 0, false, errMP4
			}
			base = uint64(binary.BigEndian.Uint32(body[4:]))
			if body[0] == 1 {
				if len(body) < 12 {
					return 0, false, errMP4
				}
				base = binary.BigEndian.Uint64(body[4:])
			}
		case "trun":
			if !sawTfhd || !match {
				return 0, false, nil
			}
			if err := truns(body, base, defaultDuration, &best); err != nil {
				return 0, false, err
			}
		}
	}
	return best, match && best != int64(1<<63-1), nil
}

// truns folds the samples of one trun box into the earliest presentation time.
func truns(body []byte, base uint64, defaultDuration uint32, best *int64) error {
	if len(body) < 8 {
		return errMP4
	}
	version, flags := body[0], binary.BigEndian.Uint32(body)&0xffffff
	count := binary.BigEndian.Uint32(body[4:])
	off := 8
	if flags&0x1 != 0 {
		off += 4
	}
	if flags&0x4 != 0 {
		off += 4
	}
	dts := int64(base) //nolint:gosec // a media time far below 2^63
	for range count {
		duration := defaultDuration
		if flags&0x100 != 0 {
			if len(body) < off+4 {
				return errMP4
			}
			duration = binary.BigEndian.Uint32(body[off:])
			off += 4
		}
		if flags&0x200 != 0 {
			off += 4
		}
		if flags&0x400 != 0 {
			off += 4
		}
		cts := int64(0)
		if flags&0x800 != 0 {
			if len(body) < off+4 {
				return errMP4
			}
			cts = int64(binary.BigEndian.Uint32(body[off:]))
			if version == 1 {
				cts = int64(int32(binary.BigEndian.Uint32(body[off:]))) //nolint:gosec // a signed offset is what version 1 stores
			}
			off += 4
		}
		if off > len(body) {
			return errMP4
		}
		*best = min(*best, dts+cts)
		dts += int64(duration)
	}
	return nil
}
