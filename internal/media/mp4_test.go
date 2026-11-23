package media

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func mp4box(typ string, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return append(append(binary.BigEndian.AppendUint32(nil, uint32(8+len(body))), typ...), body...) //nolint:gosec // small test data
}

func u32s(v ...uint32) []byte {
	var b []byte
	for _, x := range v {
		b = binary.BigEndian.AppendUint32(b, x)
	}
	return b
}

// testInit has an audio track (ID 1, 48000) before the video track (ID 2, 15360).
func testInit() []byte {
	trak := func(id, scale uint32, handler string) []byte {
		tkhd := mp4box("tkhd", u32s(0, 0, 0, id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) // version 0
		mdhd := mp4box("mdhd", u32s(0, 0, 0, scale, 0, 0))
		hdlr := mp4box("hdlr", u32s(0, 0), []byte(handler), make([]byte, 13))
		return mp4box("trak", tkhd, mp4box("mdia", mdhd, hdlr))
	}
	return mp4box("moov", trak(1, 48000, "soun"), trak(2, 15360, "vide"))
}

// segment is a moof with an audio fragment and a video fragment: tfdt (version 1) 92150 and four
// samples of 512 ticks whose composition offsets are cts.
func testSegment(baseVideo uint32, cts []int32, version byte) []byte {
	tfhd := func(id uint32) []byte { return mp4box("tfhd", u32s(0x020000, id)) }
	var samples []byte
	for _, c := range cts {
		samples = binary.BigEndian.AppendUint32(samples, 512)       // duration
		samples = binary.BigEndian.AppendUint32(samples, 1000)      // size
		samples = binary.BigEndian.AppendUint32(samples, uint32(c)) //nolint:gosec // negative offsets are the point
	}
	flags := uint32(0x1 | 0x100 | 0x200 | 0x800)
	hdr := append([]byte{version}, byte(flags>>16), byte(flags>>8), byte(flags))
	trunBox := mp4box("trun", hdr, u32s(uint32(len(cts)), 0), samples) //nolint:gosec // small test data
	tfdt := mp4box("tfdt", []byte{1, 0, 0, 0}, binary.BigEndian.AppendUint64(nil, uint64(baseVideo)))
	audio := mp4box("traf", tfhd(1), mp4box("tfdt", []byte{0, 0, 0, 0}, u32s(0)), mp4box("trun", []byte{0, 0, 0x01, 0x00}, u32s(0, 0)))
	video := mp4box("traf", tfhd(2), tfdt, trunBox)
	return append(mp4box("moof", mp4box("mfhd", u32s(0, 1)), audio, video), mp4box("mdat", make([]byte, 16))...)
}

// ticks is a time in the test video track's 15360 ticks per second.
func ticks(n int) time.Duration { return time.Duration(float64(n) / 15360 * float64(time.Second)) }

// 92150 + 1024 ticks at 15360 per second is 6.066 s: the first picture of a segment that starts at 6 s
// and whose encoder holds two frames back.
func TestFirstVideoPTS(t *testing.T) {
	for name, tc := range map[string]struct {
		cts     []int32
		version byte
		want    time.Duration
	}{
		"reordered":        {[]int32{1024, 3072, 1536, 2048}, 0, ticks(92150 + 1024)},
		"no reordering":    {[]int32{0, 0, 0, 0}, 0, ticks(92150)},
		"negative offsets": {[]int32{-1024, 1024, 0, 512}, 1, ticks(92150 - 1024)},
		"a later first":    {[]int32{2048, 512, 1024, 3072}, 0, ticks(92150 + 512 + 512)},
	} {
		got, err := FirstVideoPTS(testInit(), testSegment(92150, tc.cts, tc.version))
		if err != nil || math.Abs((got-tc.want).Seconds()) > 1e-6 {
			t.Errorf("%s: %v, %v; want %v", name, got, err, tc.want)
		}
	}
}

func TestFirstVideoPTSRefusesWhatIsNotOurs(t *testing.T) {
	init, seg := testInit(), testSegment(92150, []int32{1024, 2048}, 0)
	for name, in := range map[string][2][]byte{
		"no init":         {nil, seg},
		"no video track":  {mp4box("moov"), seg},
		"no segment":      {init, nil},
		"no fragment":     {init, mp4box("moof", mp4box("mfhd", u32s(0, 1)))},
		"another track":   {mp4box("moov", mp4box("trak", mp4box("tkhd", u32s(0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)), mp4box("mdia", mp4box("mdhd", u32s(0, 0, 0, 90000, 0, 0)), mp4box("hdlr", u32s(0, 0), []byte("vide"), make([]byte, 13))))), seg},
		"truncated trun":  {init, seg[:len(seg)-40]},
		"garbage":         {init, []byte("not an mp4 file at all")},
		"huge box length": {init, append([]byte{0xff, 0xff, 0xff, 0xff}, "moof"...)},
	} {
		if got, err := FirstVideoPTS(in[0], in[1]); err == nil {
			t.Errorf("%s: accepted, %v", name, got)
		}
	}
	// A cut at any length is an error or a value, never a panic.
	for n := range len(seg) {
		_, _ = FirstVideoPTS(init, seg[:n])
	}
}
