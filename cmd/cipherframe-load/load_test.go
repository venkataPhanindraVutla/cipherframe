package main

import (
	"slices"
	"testing"
	"time"
)

func TestPercentileNearestRank(t *testing.T) {
	s := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for p, want := range map[float64]float64{50: 5, 95: 10, 99: 10, 10: 1, 0: 1, 100: 10} {
		if got := percentile(s, p); got != want {
			t.Errorf("p%v = %v, want %v", p, got, want)
		}
	}
	if percentile(nil, 99) != 0 {
		t.Error("an empty sample has percentile 0")
	}
}

func TestRampTargets(t *testing.T) {
	if got := rampTargets(10, 10, 40); !slices.Equal(got, []int{10, 20, 30, 40}) {
		t.Errorf("got %v", got)
	}
	if got := rampTargets(10, 25, 40); !slices.Equal(got, []int{10, 35}) {
		t.Errorf("max is a ceiling: got %v", got)
	}
	if rampTargets(50, 10, 40) != nil || rampTargets(10, 0, 40) != nil {
		t.Error("an empty or non-advancing ramp has no steps")
	}
}

func TestSummarizeAndBreach(t *testing.T) {
	seg := &kindStats{}
	for i := 1; i <= 100; i++ {
		seg.ms = append(seg.ms, float64(i))
	}
	per := map[string]*kindStats{"segment": seg, "heartbeat": {ms: []float64{5, 5}, errs: 2}}
	rows := summarize(3, 40, 10, per)
	var all, segRow row
	for _, r := range rows {
		switch r.Kind {
		case "all":
			all = r
		case "segment":
			segRow = r
		}
	}
	if segRow.Requests != 100 || segRow.ReqPerSec != 10 || segRow.P50 != 50 || segRow.P95 != 95 || segRow.P99 != 99 {
		t.Errorf("segment row %+v", segRow)
	}
	if all.Requests != 102 || all.Errors != 2 || all.Step != 3 || all.Viewers != 40 {
		t.Errorf("total row %+v", all)
	}
	if got := breach(rows, time.Second, 0.05); got != "" {
		t.Errorf("a passing step breached: %s", got)
	}
	if breach(rows, 50*time.Millisecond, 0.05) == "" {
		t.Error("segment p99 over the limit should breach")
	}
	if breach(rows, time.Second, 0.01) == "" {
		t.Error("error rate over the limit should breach")
	}
}

func TestParsePlaylists(t *testing.T) {
	if got := parseMaster([]byte("#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\n720p/media.m3u8\n360p/media.m3u8\n")); got != "720p/media.m3u8" {
		t.Errorf("master: %q", got)
	}
	h := parseMedia([]byte("#EXTM3U\n#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"../key\"\n#EXT-X-MAP:URI=\"init.mp4\"\n" +
		"#EXTINF:4.000,\nseg-0.m4s\n#EXTINF:2.500,\nhttps://storage.test/seg-1.m4s?sig=x\n#EXT-X-ENDLIST\n"))
	if h.key != "../key" || h.init != "init.mp4" || len(h.segs) != 2 || h.durs[0] != 4*time.Second || h.durs[1] != 2500*time.Millisecond {
		t.Errorf("media: %+v", h)
	}
}
