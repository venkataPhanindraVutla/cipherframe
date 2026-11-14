package media

import (
	"strings"
	"testing"
)

func TestLadderHeightFilter(t *testing.T) {
	names := func(rs []Rendition) string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Name)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		name    string
		w, h    int
		heights []int
		want    string
	}{
		{"subset of a tall source", 3840, 2160, []int{720, 360}, "720p,360p"},
		{"order in the setting does not matter", 3840, 2160, []int{360, 720}, "720p,360p"},
		{"selected rung taller than the source is skipped", 640, 480, []int{720, 360}, "360p"},
		{"empty means every rung", 640, 480, nil, "480p,360p,240p"},
		{"below every selected rung: one rendition at source height", 640, 480, []int{720}, "480p"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := names(Ladder(infoWithDisplay(c.w, c.h, true), c.heights)); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
	// The fallback takes the caps of the smallest selected rung, not of the 240p rung.
	r := Ladder(infoWithDisplay(640, 480, true), []int{720})[0]
	if r.MaxrateKbps != 2500 || r.BufsizeKbps != 5000 {
		t.Errorf("fallback caps: %+v", r)
	}
}
