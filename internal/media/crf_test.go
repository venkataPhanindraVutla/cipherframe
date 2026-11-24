package media

import (
	"slices"
	"testing"
)

// The defaults must give the ffmpeg arguments the fixed constants gave before the CRF was configurable.
func TestDefaultCRFsKeepArguments(t *testing.T) {
	info := testSpec().Info
	for _, c := range []Codec{CodecH264, CodecHEVC, CodecAV1} {
		for _, e := range Encoders() {
			for i, r := range DefaultCRFs().Apply(LadderFor(c, info, nil)) {
				old := LadderFor(c, info, nil)[i] // CRF straight from the constants
				want, werr := videoArgs(e, c, old, X264Preset, OutputFrameRate(30))
				got, gerr := videoArgs(e, c, r, X264Preset, OutputFrameRate(30))
				if (werr == nil) != (gerr == nil) || !slices.Equal(got, want) {
					t.Errorf("%s %s %s: %v != %v", e, c, r.Name, got, want)
				}
			}
		}
	}
}

func TestCRFsApplyPerCodecAndReachArguments(t *testing.T) {
	q := CRFs{H264: 18, HEVC: 20, AV1: 30}
	info := testSpec().Info
	for c, want := range map[Codec]int{CodecH264: 18, CodecHEVC: 20, CodecAV1: 30} {
		for _, r := range q.Apply(LadderFor(c, info, nil)) {
			if r.CRF != want {
				t.Errorf("%s %s: CRF %d, want %d", c, r.Name, r.CRF, want)
			}
		}
	}
	r := q.Apply(LadderFor(CodecH264, info, nil))[0]
	for _, e := range Encoders() {
		def, _ := videoArgs(e, CodecH264, LadderFor(CodecH264, info, nil)[0], X264Preset, OutputFrameRate(30))
		got, err := videoArgs(e, CodecH264, r, X264Preset, OutputFrameRate(30))
		if err != nil || slices.Equal(got, def) {
			t.Errorf("%s: CRF 18 did not change the arguments (%v)", e, err)
		}
	}
}
